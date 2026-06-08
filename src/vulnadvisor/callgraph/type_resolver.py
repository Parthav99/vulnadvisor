# File: src/vulnadvisor/callgraph/type_resolver.py
"""Type-informed resolution of reflective dispatch (M7 precision), with a sound fallback.

A reflective access ``getattr(pkg, name)`` is, to pure static analysis, an over-approximation: it
*could* reach the vulnerable symbol, so M6 escalates the finding to DYNAMIC-UNKNOWN. When a type
checker can infer that ``name`` is a string ``Literal`` (e.g. ``Literal["safe_load"]``), we resolve
which attribute is actually accessed and drop the over-approximation — *only* when the resolved
attribute is provably not the vulnerable symbol. If no type info is available the resolver returns
``None`` and the caller keeps the conservative tier, so precision never costs soundness.

``PyrightResolver`` shells out to ``pyright`` (an optional external tool, discovered on ``PATH``) by
copying the project, injecting ``reveal_type`` probes, and parsing the inferred types from
``--outputjson``. The subprocess/probe mechanics live behind an injectable ``runner`` so the
resolution *logic* (and the JSON parser) is exercised deterministically in tests without Pyright
installed; when Pyright is absent the resolver reports ``available == False`` and contributes
nothing — exactly the M6 behavior.
"""

import json
import shutil
import subprocess  # noqa: S404 - used only to invoke the user's local pyright, never shell=True
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from vulnadvisor.callgraph.call_paths import PackageReflection

__all__ = [
    "NullResolver",
    "Probe",
    "PyrightResolver",
    "RevealRunner",
    "TypeResolver",
    "literals_from_type_string",
    "parse_pyright_reveals",
]


@dataclass(frozen=True)
class Probe:
    """A request to learn the inferred type of expression ``expr`` at ``file``:``lineno``."""

    file: str
    lineno: int
    expr: str


# A runner is given probes and returns the revealed type string per probe (the text a type checker
# would print, e.g. ``Literal['safe_load']``). Probes it cannot resolve are simply absent.
RevealRunner = Callable[[Path, tuple[Probe, ...]], Mapping[Probe, str]]


@runtime_checkable
class TypeResolver(Protocol):
    """Resolves a reflective package access to the attribute name(s) it can take."""

    @property
    def available(self) -> bool:
        """Whether this resolver can actually contribute type information in this environment."""
        ...

    def resolve_attrs(
        self, project_dir: Path, reflection: PackageReflection
    ) -> frozenset[str] | None:
        """Return the attribute names ``reflection`` can resolve to, or ``None`` if unknown.

        ``None`` means "no information" — the caller must stay conservative. A returned set means
        the access is provably limited to those attributes (used to rule the vulnerable symbol in
        or out).
        """
        ...


class NullResolver:
    """A resolver that never resolves anything — the sound fallback (== M6 behavior)."""

    @property
    def available(self) -> bool:
        """Always ``False``: this resolver contributes no type information."""
        return False

    def resolve_attrs(
        self, project_dir: Path, reflection: PackageReflection
    ) -> frozenset[str] | None:
        """Always return ``None`` (no information)."""
        return None


def literals_from_type_string(type_str: str) -> frozenset[str] | None:
    """Extract the string members of a ``Literal[...]`` type, or ``None`` if not a string literal.

    ``Literal['safe_load']`` -> ``{'safe_load'}``; ``Literal['a', 'b']`` -> ``{'a', 'b'}``. A type
    that is not a pure string ``Literal`` (``str``, ``Unknown``, a union with non-literals, an int
    literal) yields ``None`` — we only narrow when the attribute name is fully pinned down.
    """
    text = type_str.strip()
    prefix = "Literal["
    start = text.find(prefix)
    if start == -1 or not text.endswith("]"):
        return None
    inner = text[start + len(prefix) : -1]
    if not inner.strip():
        return None
    members: set[str] = set()
    for raw in _split_top_level(inner):
        member = raw.strip()
        if len(member) >= 2 and member[0] in {'"', "'"} and member[-1] == member[0]:
            members.add(member[1:-1])
        else:
            # A non-string literal member (int/bool/enum) means this isn't a plain attribute name.
            return None
    return frozenset(members) if members else None


def _split_top_level(inner: str) -> list[str]:
    """Split ``inner`` on commas that are not nested inside brackets or quotes."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for char in inner:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            current.append(char)
        elif char in "[(":
            depth += 1
            current.append(char)
        elif char in ")]":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def parse_pyright_reveals(output: str, line_to_probe: Mapping[int, Probe]) -> dict[Probe, str]:
    """Parse ``pyright --outputjson`` text into ``{probe: revealed_type}`` by reveal-line number.

    ``reveal_type`` emits an ``information`` diagnostic ``Type of "<expr>" is "<type>"`` at the line
    it was injected. We match strictly on that 1-based line (``line_to_probe``) so a reveal can only
    bind to the probe we placed there; anything ambiguous or unrecognized is dropped (resolve
    nothing rather than risk a wrong, unsound narrowing). Malformed JSON yields an empty result.
    """
    try:
        payload = json.loads(output)
    except (ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    diagnostics = payload.get("generalDiagnostics")
    if not isinstance(diagnostics, list):
        return {}

    resolved: dict[Probe, str] = {}
    for diag in diagnostics:
        if not isinstance(diag, dict) or diag.get("severity") != "information":
            continue
        message = diag.get("message")
        rng = diag.get("range")
        start = rng.get("start", {}) if isinstance(rng, dict) else {}
        line0 = start.get("line") if isinstance(start, dict) else None
        if not isinstance(message, str) or not isinstance(line0, int):
            continue
        probe = line_to_probe.get(line0 + 1)  # pyright lines are 0-based; probes are 1-based
        if probe is None:
            continue
        type_str = _revealed_type(message)
        if type_str is not None:
            resolved[probe] = type_str
    return resolved


def _revealed_type(message: str) -> str | None:
    """Pull ``<type>`` out of a ``Type of "<expr>" is "<type>"`` reveal message, else ``None``."""
    marker = '" is "'
    idx = message.find(marker)
    if idx == -1 or not message.endswith('"'):
        return None
    return message[idx + len(marker) : -1]


class PyrightResolver:
    """Resolve reflective accesses via Pyright's inferred ``Literal`` types (optional tool).

    When ``pyright`` is not on ``PATH`` (and no ``runner`` is injected) the resolver is unavailable
    and resolves nothing, so behavior is identical to M6. The ``runner`` seam lets tests supply
    inferred types deterministically; in production the default runner shells out to Pyright.
    """

    def __init__(
        self, *, command: tuple[str, ...] = ("pyright",), runner: RevealRunner | None = None
    ) -> None:
        """Configure the Pyright ``command`` and an optional injected type ``runner``."""
        self._command = command
        self._runner = runner
        self._cache: dict[tuple[Path, Probe], str | None] = {}

    @property
    def available(self) -> bool:
        """``True`` if a runner is injected, or the ``pyright`` executable is on ``PATH``."""
        if self._runner is not None:
            return True
        return shutil.which(self._command[0]) is not None

    def resolve_attrs(
        self, project_dir: Path, reflection: PackageReflection
    ) -> frozenset[str] | None:
        """Resolve ``reflection.name_arg``'s ``Literal`` type to attribute names, or ``None``."""
        if not self.available:
            return None
        probe = Probe(file=reflection.file, lineno=reflection.lineno, expr=reflection.name_arg)
        type_str = self._reveal_one(project_dir, probe)
        if type_str is None:
            return None
        return literals_from_type_string(type_str)

    def _reveal_one(self, project_dir: Path, probe: Probe) -> str | None:
        """Return the revealed type for one ``probe`` (cached), running the configured runner."""
        key = (project_dir, probe)
        if key in self._cache:
            return self._cache[key]
        runner = self._runner if self._runner is not None else self._default_runner
        try:
            revealed = runner(project_dir, (probe,))
        except (OSError, ValueError):
            revealed = {}
        type_str = revealed.get(probe)
        self._cache[key] = type_str
        return type_str

    def _default_runner(self, project_dir: Path, probes: tuple[Probe, ...]) -> Mapping[Probe, str]:
        """Production runner: copy the project, inject ``reveal_type`` probes, run Pyright, parse.

        Best-effort and fail-safe: any error (copy, injection, subprocess, parse) yields an empty
        map, so the caller falls back to the sound M6 over-approximation. Never raises into a scan.
        """
        if not probes:
            return {}
        with tempfile.TemporaryDirectory(prefix="vulnadvisor-pyright-") as tmp:
            workdir = Path(tmp) / "project"
            try:
                shutil.copytree(project_dir, workdir)
                line_to_probe = _inject_reveals(workdir, probes)
            except OSError:
                return {}
            if not line_to_probe:
                return {}
            try:
                completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, local tool only
                    [*self._command, "--outputjson", str(workdir)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return {}
            return parse_pyright_reveals(completed.stdout, line_to_probe)


def _inject_reveals(workdir: Path, probes: tuple[Probe, ...]) -> dict[int, Probe]:
    """Insert ``reveal_type(<expr>)`` after each probe's line; return the reveal-line -> probe map.

    Probes in the same file are inserted in ascending line order while tracking how many lines were
    already inserted (``offset``), so each reveal's final 1-based line stays correct. The reveal is
    indented to match its probe's anchor line so the expression keeps its original scope.
    """
    line_to_probe: dict[int, Probe] = {}
    by_file: dict[str, list[Probe]] = {}
    for probe in probes:
        by_file.setdefault(probe.file, []).append(probe)

    for rel, file_probes in by_file.items():
        target = workdir / rel
        lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
        offset = 0
        for probe in sorted(file_probes, key=lambda p: p.lineno):
            anchor_idx = (probe.lineno - 1) + offset
            if probe.lineno < 1 or anchor_idx >= len(lines):
                continue
            anchor = lines[anchor_idx]
            indent = anchor[: len(anchor) - len(anchor.lstrip())]
            insert_idx = anchor_idx + 1
            lines.insert(insert_idx, f"{indent}reveal_type({probe.expr})\n")
            line_to_probe[insert_idx + 1] = probe  # final 1-based line of the inserted reveal
            offset += 1
        target.write_text("".join(lines), encoding="utf-8")
    return line_to_probe
