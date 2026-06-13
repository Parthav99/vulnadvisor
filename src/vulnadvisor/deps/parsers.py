"""Manifest parsers that normalize project dependencies to :class:`Dependency` records.

Every ``parse_*`` function is pure: it takes the manifest *content* as a string and returns a
list of :class:`Dependency`, performing no file or network I/O. The thin :func:`parse_manifest_file`
and :func:`collect_dependencies` helpers do the file reading and dispatch, and
:func:`dependencies_from_environment` is the installed-environment fallback.

Defensive parsing is a hard requirement: structurally malformed TOML/JSON raises a typed
:class:`ManifestParseError` (never an unhandled crash), while individual malformed *entries*
degrade to a record with ``version=None`` rather than being dropped, so we never silently lose a
dependency (a lost dependency would be a downstream false negative).
"""

import json
import re
import tomllib
from collections.abc import Iterable, Mapping
from importlib import metadata
from pathlib import Path
from typing import Any

from vulnadvisor.model.dependency import Dependency, DependencySource

__all__ = [
    "ManifestParseError",
    "canonicalize_name",
    "collect_dependencies",
    "dependencies_from_environment",
    "parse_manifest_file",
    "parse_pipfile_lock",
    "parse_poetry_lock",
    "parse_pyproject_toml",
    "parse_requirements_txt",
]


class ManifestParseError(Exception):
    """Raised when a manifest's structured content cannot be parsed.

    Carries the offending ``source`` and a human-readable ``detail`` so callers can surface a
    degraded-mode message instead of crashing.
    """

    def __init__(self, source: DependencySource, detail: str) -> None:
        """Store the failing ``source`` and ``detail`` and build the message."""
        self.source = source
        self.detail = detail
        super().__init__(f"failed to parse {source.value}: {detail}")


_CANON_RE = re.compile(r"[-_.]+")
# name [extras] <rest-is-specifier-or-marker>
_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$"
)
_EXACT_RE = re.compile(r"(===|==)\s*(?P<value>[^,;\s]+)")
_BARE_VERSION_RE = re.compile(r"\d+(?:\.\d+)*$")


def canonicalize_name(name: str) -> str:
    """Return the PEP 503 canonical form of a distribution name (lowercase, dash-separated)."""
    return _CANON_RE.sub("-", name.strip()).lower()


def _extract_exact_version(spec: str) -> str | None:
    """Return the pinned version from a specifier string, or ``None`` for ranges/wildcards."""
    spec = spec.strip()
    if not spec:
        return None
    match = _EXACT_RE.match(spec)
    if match is None:
        return None
    value = match.group("value")
    return None if "*" in value else value


def _strip_inline_comment(line: str) -> str:
    """Drop a ``#`` comment (full-line, or inline when preceded by whitespace)."""
    if line.lstrip().startswith("#"):
        return ""
    match = re.search(r"\s#", line)
    return line[: match.start()] if match else line


def _requirement_from_string(
    raw: str, source: DependencySource, *, is_direct: bool
) -> Dependency | None:
    """Parse a single PEP 508-style requirement string into a :class:`Dependency`.

    Returns ``None`` for blank input. URL/VCS forms keep the name with no resolvable version.
    """
    line = raw.strip()
    if not line:
        return None
    # Drop an environment marker (``; python_version < "3.8"``).
    line = line.split(";", 1)[0].strip()
    if not line:
        return None
    # ``name @ https://...`` direct-reference form: keep the name, no pinned version.
    if " @ " in line:
        url_name = line.split("@", 1)[0].strip()
        if not url_name:
            return None
        return Dependency(
            name=canonicalize_name(url_name),
            raw_name=url_name,
            source=source,
            is_direct=is_direct,
        )
    match = _REQ_RE.match(line)
    if match is None:
        return None
    name = match.group("name")
    extras_raw = match.group("extras")
    spec = (match.group("spec") or "").strip()
    extras = (
        tuple(part.strip() for part in extras_raw.strip("[]").split(",") if part.strip())
        if extras_raw
        else ()
    )
    return Dependency(
        name=canonicalize_name(name),
        raw_name=name,
        version=_extract_exact_version(spec),
        specifier=spec or None,
        source=source,
        is_direct=is_direct,
        extras=extras,
    )


def _dedupe(deps: Iterable[Dependency]) -> list[Dependency]:
    """Drop duplicate records (by name + version + source), preserving first-seen order."""
    seen: set[tuple[str, str | None, DependencySource]] = set()
    out: list[Dependency] = []
    for dep in deps:
        key = (dep.name, dep.version, dep.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(dep)
    return out


def parse_requirements_txt(content: str) -> list[Dependency]:
    """Parse ``requirements.txt`` content into direct dependencies.

    Handles comments, blank lines, backslash line-continuations, environment markers, extras,
    and URL/VCS references. Option lines (``-e``, ``-r``, ``--hash`` …) are ignored.
    """
    logical_lines: list[str] = []
    buffer = ""
    for raw in content.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += raw
        logical_lines.append(buffer)
        buffer = ""
    if buffer:
        logical_lines.append(buffer)

    deps: list[Dependency] = []
    for line in logical_lines:
        text = _strip_inline_comment(line).strip()
        if not text or text.startswith("-"):
            continue
        dep = _requirement_from_string(text, DependencySource.REQUIREMENTS_TXT, is_direct=True)
        if dep is not None:
            deps.append(dep)
    return _dedupe(deps)


def _poetry_constraint_version(constraint: Any) -> tuple[str | None, str | None]:
    """Return ``(exact_version, raw_specifier)`` for a Poetry dependency constraint value."""
    if isinstance(constraint, str):
        version = constraint if _BARE_VERSION_RE.fullmatch(constraint) else None
        return version, constraint
    if isinstance(constraint, Mapping):
        inner = constraint.get("version")
        if isinstance(inner, str):
            return _poetry_constraint_version(inner)
    return None, None


def _add_poetry_dependencies(table: Any, deps: list[Dependency]) -> None:
    """Append Poetry ``[tool.poetry...dependencies]`` table entries to ``deps``."""
    if not isinstance(table, Mapping):
        return
    for name, constraint in table.items():
        if not isinstance(name, str) or canonicalize_name(name) == "python":
            continue
        version, specifier = _poetry_constraint_version(constraint)
        deps.append(
            Dependency(
                name=canonicalize_name(name),
                raw_name=name,
                version=version,
                specifier=specifier,
                source=DependencySource.PYPROJECT_TOML,
                is_direct=True,
            )
        )


def parse_pyproject_toml(content: str) -> list[Dependency]:
    """Parse ``pyproject.toml`` content (PEP 621 ``[project]`` and/or Poetry tables)."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestParseError(DependencySource.PYPROJECT_TOML, str(exc)) from exc

    deps: list[Dependency] = []

    project = data.get("project")
    if isinstance(project, Mapping):
        for item in project.get("dependencies") or []:
            if isinstance(item, str):
                dep = _requirement_from_string(
                    item, DependencySource.PYPROJECT_TOML, is_direct=True
                )
                if dep is not None:
                    deps.append(dep)
        optional = project.get("optional-dependencies")
        if isinstance(optional, Mapping):
            for group in optional.values():
                for item in group or []:
                    if isinstance(item, str):
                        dep = _requirement_from_string(
                            item, DependencySource.PYPROJECT_TOML, is_direct=True
                        )
                        if dep is not None:
                            deps.append(dep)

    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, Mapping) else None
    if isinstance(poetry, Mapping):
        _add_poetry_dependencies(poetry.get("dependencies"), deps)
        groups = poetry.get("group")
        if isinstance(groups, Mapping):
            for group in groups.values():
                if isinstance(group, Mapping):
                    _add_poetry_dependencies(group.get("dependencies"), deps)

    return _dedupe(deps)


def parse_poetry_lock(content: str) -> list[Dependency]:
    """Parse ``poetry.lock`` content into resolved (transitive) dependencies."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestParseError(DependencySource.POETRY_LOCK, str(exc)) from exc

    deps: list[Dependency] = []
    for package in data.get("package") or []:
        if not isinstance(package, Mapping):
            continue
        name = package.get("name")
        if not isinstance(name, str):
            continue
        version = package.get("version")
        deps.append(
            Dependency(
                name=canonicalize_name(name),
                raw_name=name,
                version=version if isinstance(version, str) else None,
                source=DependencySource.POETRY_LOCK,
                is_direct=False,
            )
        )
    return _dedupe(deps)


def parse_pipfile_lock(content: str) -> list[Dependency]:
    """Parse ``Pipfile.lock`` (JSON) ``default`` and ``develop`` sections."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(DependencySource.PIPFILE_LOCK, str(exc)) from exc
    if not isinstance(data, Mapping):
        raise ManifestParseError(DependencySource.PIPFILE_LOCK, "top-level value is not an object")

    deps: list[Dependency] = []
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, Mapping):
            continue
        for name, spec in block.items():
            if not isinstance(name, str):
                continue
            version: str | None = None
            specifier: str | None = None
            if isinstance(spec, Mapping):
                raw_version = spec.get("version")
                if isinstance(raw_version, str):
                    specifier = raw_version
                    if raw_version.startswith("=="):
                        version = raw_version[2:]
            deps.append(
                Dependency(
                    name=canonicalize_name(name),
                    raw_name=name,
                    version=version,
                    specifier=specifier,
                    source=DependencySource.PIPFILE_LOCK,
                    is_direct=False,
                )
            )
    return _dedupe(deps)


_DISPATCH: dict[str, tuple[Any, DependencySource]] = {
    "requirements.txt": (parse_requirements_txt, DependencySource.REQUIREMENTS_TXT),
    "pyproject.toml": (parse_pyproject_toml, DependencySource.PYPROJECT_TOML),
    "poetry.lock": (parse_poetry_lock, DependencySource.POETRY_LOCK),
    "Pipfile.lock": (parse_pipfile_lock, DependencySource.PIPFILE_LOCK),
}

# Order matters: lockfiles are preferred (more precise) but we collect from every present file.
_MANIFEST_ORDER = ("poetry.lock", "Pipfile.lock", "pyproject.toml", "requirements.txt")


def parse_manifest_file(path: Path) -> list[Dependency]:
    """Read and parse a single supported manifest file, dispatching on its filename."""
    entry = _DISPATCH.get(path.name)
    if entry is None:
        raise ManifestParseError(
            DependencySource.ENVIRONMENT, f"unsupported manifest file: {path.name}"
        )
    parser, source = entry
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestParseError(source, f"cannot read {path}: {exc}") from exc
    result: list[Dependency] = parser(text)
    return result


def dependencies_from_environment() -> list[Dependency]:
    """Return dependencies discovered in the active environment via ``importlib.metadata``."""
    deps: list[Dependency] = []
    for dist in metadata.distributions():
        name = dist.name
        if not name:
            continue
        version = dist.version
        deps.append(
            Dependency(
                name=canonicalize_name(name),
                raw_name=name,
                version=version if isinstance(version, str) and version else None,
                source=DependencySource.ENVIRONMENT,
                is_direct=False,
            )
        )
    return _dedupe(deps)


def collect_dependencies(
    project_dir: Path, *, use_environment_fallback: bool = True
) -> list[Dependency]:
    """Collect dependencies from every supported manifest found under ``project_dir``.

    When no manifest is present and ``use_environment_fallback`` is set, falls back to the
    installed environment. Records from all present manifests are merged and de-duplicated.
    """
    collected: list[Dependency] = []
    found_any = False
    for filename in _MANIFEST_ORDER:
        candidate = project_dir / filename
        if candidate.is_file():
            found_any = True
            collected.extend(parse_manifest_file(candidate))

    if not found_any:
        if use_environment_fallback:
            return dependencies_from_environment()
        return []
    return _dedupe(collected)
