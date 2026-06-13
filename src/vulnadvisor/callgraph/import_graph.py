"""Build an import graph of a project's first-party code with ``ast``.

Walks every ``.py`` file under a project, collecting each ``import`` / ``from ... import`` (with
aliases and relative-import levels) and flagging dynamic constructs (``importlib``,
``__import__``, ``eval``/``exec``) that can hide a real usage from static analysis. Parsing is
defensive: a file that won't parse is recorded as a parse error, never a crash — but it is
surfaced so reachability can stay cautious about a file it could not read.

:func:`map_imports_to_distributions` then maps absolute import roots back to the project's
distributions via the Task 1.2 resolver, yielding the import-site evidence per distribution.
"""

import ast
from collections.abc import Iterable, Sequence
from pathlib import Path

from vulnadvisor.deps.import_mapping import resolve_import_names
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.model.imports import (
    DynamicImportKind,
    DynamicImportSite,
    FileAnalysis,
    ImportedName,
    ImportGraph,
    ImportKind,
    ImportParseError,
    ImportSite,
)
from vulnadvisor.store.analysis_cache import AnalysisCache, cache_key

__all__ = ["build_import_graph", "map_imports_to_distributions"]

# Directories that are never first-party source and should not be walked.
_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        ".nox",
        "build",
        "dist",
        ".eggs",
        "node_modules",
    }
)


def _is_excluded(relative: Path) -> bool:
    """Return ``True`` if any path component is an excluded directory."""
    return any(part in _EXCLUDED_DIRS for part in relative.parts)


def _infer_first_party(root: Path) -> set[str]:
    """Infer the project's own top-level module names from ``root`` and ``root/src``."""
    modules: set[str] = set()
    for base in (root, root / "src"):
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / "__init__.py").is_file():
                modules.add(child.name)
            elif child.is_file() and child.suffix == ".py" and child.stem != "setup":
                modules.add(child.stem)
    return modules


# Files whose code runs only at build/packaging/docs time, never in the deployed application. An
# ``eval``/``exec`` here cannot make a runtime dependency vulnerability reachable, so it must not
# force caution. We still record (and trust) the *static* imports in these files, so nothing that
# is genuinely imported is ever hidden — only the dynamic-dispatch caution is relaxed.
_NON_RUNTIME_DIRS = frozenset({"docs", "doc"})
_NON_RUNTIME_BASENAMES = frozenset({"setup.py", "conf.py"})


def _is_runtime_file(rel: str) -> bool:
    """Whether ``rel`` is part of the deployed app's runtime surface (vs. build/docs-only code)."""
    parts = rel.split("/")
    if parts[0] in _NON_RUNTIME_DIRS:
        return False
    return parts[-1] not in _NON_RUNTIME_BASENAMES


def _func_repr(func: ast.expr) -> str:
    """Best-effort source text of a call target (for dynamic-site detail)."""
    try:
        return ast.unparse(func)
    except (ValueError, AttributeError):
        return "<dynamic call>"


# Name-based module import: ``import_module(x)`` / ``__import__(x)``. These can be proven to target
# first-party modules when their argument has a constant first-party prefix (``_dynamic_target``).
_IMPORT_CALLEES = frozenset({"import_module", "__import__"})

# File-/spec-based and plugin-discovery loaders: ``imp.load_source``, ``importlib.util``
# spec loaders, and ``pkgutil`` walkers. Their target is a filesystem path or a discovered module,
# never a statically-provable first-party module name, so they are always conservative (unproven).
# Detecting these closes the gap where a custom helper (e.g. searx's ``load_module`` wrapping
# ``load_source``) hid a dynamic import from analysis.
_LOADER_CALLEES = frozenset(
    {
        "load_source",
        "load_compiled",
        "spec_from_file_location",
        "module_from_spec",
        "exec_module",
        "walk_packages",
        "iter_modules",
    }
)


def _callee_name(func: ast.expr) -> str | None:
    """Return the bare callee name for a ``Name``/``Attribute`` call target, else ``None``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _dynamic_kind(call: ast.Call) -> DynamicImportKind | None:
    """Classify a call as a dynamic import/exec/loader construct, or ``None`` if it is neither.

    Matches on the bare callee name, so both ``importlib.import_module(x)`` and a
    ``from importlib import import_module`` then ``import_module(x)`` are caught (the latter was a
    soundness gap). File/spec loaders and ``pkgutil`` walkers are also caught.
    """
    name = _callee_name(call.func)
    if name is None:
        return None
    if name == "eval":
        return DynamicImportKind.EVAL
    if name == "exec":
        return DynamicImportKind.EXEC
    if name == "__import__":
        return DynamicImportKind.DUNDER_IMPORT
    if name in _IMPORT_CALLEES or name in _LOADER_CALLEES:
        return DynamicImportKind.IMPORTLIB
    return None


def _const_prefix_target(prefix: str) -> tuple[str | None, bool]:
    """Classify a constant leading string of an import target as (target_root, first_party_rel)."""
    if prefix.startswith("."):
        return None, True  # relative import -> resolves within the first-party package
    if "." in prefix:
        # The first dotted segment is fully constant, so the top-level module is pinned down.
        return (prefix.split(".")[0] or None), False
    return None, False  # no separating dot: the leading segment is not fully determined


def _dynamic_target(call: ast.Call, kind: DynamicImportKind) -> tuple[str | None, bool]:
    """Return ``(target_root, first_party_relative)`` provable from a dynamic call's argument.

    Sound by construction: only fully-constant leading segments (a constant string, an f-string or
    ``+`` concatenation with a constant dotted prefix) pin down the top-level module; a leading dot
    or a ``__name__``/``__package__`` prefix proves the target is within the first-party package.
    ``eval``/``exec`` and any opaque/computed argument yield ``(None, False)`` — stay conservative.
    """
    if kind in (DynamicImportKind.EVAL, DynamicImportKind.EXEC) or not call.args:
        return None, False
    # Only name-based imports can be proven first-party from a constant module-name prefix; a
    # file/spec loader or pkgutil walker takes a path or discovers modules, so it is never provable.
    if _callee_name(call.func) not in _IMPORT_CALLEES:
        return None, False
    name = call.args[0]
    if isinstance(name, ast.Constant) and isinstance(name.value, str):
        return _const_prefix_target(name.value)
    if isinstance(name, ast.JoinedStr) and name.values:
        first = name.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return _const_prefix_target(first.value)
        if (
            isinstance(first, ast.FormattedValue)
            and isinstance(first.value, ast.Name)
            and first.value.id in ("__name__", "__package__")
        ):
            return None, True  # f"{__name__}.{x}" -> within the first-party package
        return None, False
    if isinstance(name, ast.BinOp) and isinstance(name.op, ast.Add):
        left = name.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return _const_prefix_target(left.value)
    return None, False


def _names(node: ast.Import | ast.ImportFrom) -> tuple[ImportedName, ...]:
    """Convert ast aliases to :class:`ImportedName` records."""
    return tuple(ImportedName(name=alias.name, asname=alias.asname) for alias in node.names)


def _app_list_roots(value: ast.expr) -> list[str]:
    """Top-level module roots from a list/tuple of string literals (recursing into ``+`` concat)."""
    roots: list[str] = []
    if isinstance(value, ast.List | ast.Tuple):
        for elt in value.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value:
                roots.append(elt.value.split(".")[0])
    elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        roots.extend(_app_list_roots(value.left))
        roots.extend(_app_list_roots(value.right))
    return roots


def _framework_app_site(node: ast.Assign | ast.AugAssign, rel: str) -> ImportSite | None:
    """A synthetic import site for a Django ``*_APPS`` setting (its entries load at startup).

    Django imports every distribution listed in ``INSTALLED_APPS`` (and the common split-settings
    ``*_APPS`` lists) at startup, by string. Those packages are genuinely used even though no
    first-party ``import`` statement references them — so we record them as imports to keep them out
    of the confidently-safe NOT_IMPORTED tier. This only ever *adds* imports (more conservative);
    it never hides a finding. Non-literal entries (a computed/env ``+=``) are simply not seen.
    """
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if not any(isinstance(t, ast.Name) and t.id.endswith("_APPS") for t in targets):
        return None
    roots = _app_list_roots(node.value)
    if not roots:
        return None
    names = tuple(ImportedName(name=root) for root in dict.fromkeys(roots))
    return ImportSite(
        file=rel, lineno=node.lineno, col=node.col_offset, kind=ImportKind.IMPORT, names=names
    )


def _analyze_source(text: str, rel: str, filename: str) -> FileAnalysis:
    """Parse one file's text into a :class:`FileAnalysis` (imports, dynamics, any parse error)."""
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        return FileAnalysis(parse_error=ImportParseError(file=rel, message=f"syntax error: {exc}"))

    imports: list[ImportSite] = []
    dynamics: list[DynamicImportSite] = []
    runtime = _is_runtime_file(rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.append(
                ImportSite(
                    file=rel,
                    lineno=node.lineno,
                    col=node.col_offset,
                    kind=ImportKind.IMPORT,
                    names=_names(node),
                )
            )
        elif isinstance(node, ast.ImportFrom):
            imports.append(
                ImportSite(
                    file=rel,
                    lineno=node.lineno,
                    col=node.col_offset,
                    kind=ImportKind.FROM,
                    module=node.module,
                    level=node.level or 0,
                    names=_names(node),
                )
            )
        elif isinstance(node, ast.Assign | ast.AugAssign):
            app_site = _framework_app_site(node, rel)
            if app_site is not None:
                imports.append(app_site)
        elif isinstance(node, ast.Call):
            kind = _dynamic_kind(node)
            if kind is not None:
                target_root, first_party_relative = _dynamic_target(node, kind)
                dynamics.append(
                    DynamicImportSite(
                        file=rel,
                        lineno=node.lineno,
                        col=node.col_offset,
                        kind=kind,
                        detail=_func_repr(node.func),
                        target_root=target_root,
                        first_party_relative=first_party_relative,
                        runtime=runtime,
                    )
                )
    return FileAnalysis(imports=tuple(imports), dynamic_sites=tuple(dynamics))


def _analyze_cached(
    text: str, rel: str, filename: str, cache: AnalysisCache | None
) -> FileAnalysis:
    """Return the file's analysis, served from ``cache`` on a content-hash hit, else computed."""
    if cache is None:
        return _analyze_source(text, rel, filename)
    key = cache_key(rel, text)
    cached = cache.get(key)
    if cached is not None:
        return cached
    analysis = _analyze_source(text, rel, filename)
    cache.set(key, analysis)
    return analysis


def _iter_python_files(root: Path) -> list[Path]:
    """Return the project's ``.py`` files, excluding vendored/build/cache directories."""
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if not _is_excluded(path.relative_to(root)):
            files.append(path)
    return sorted(files)


def build_import_graph(
    project_dir: Path,
    *,
    first_party_modules: Iterable[str] | None = None,
    cache: AnalysisCache | None = None,
) -> ImportGraph:
    """Build the :class:`ImportGraph` for the project rooted at ``project_dir``.

    When ``cache`` is provided, each file's analysis is looked up by its content hash and only
    re-parsed on a miss (unchanged files are skipped on repeat scans). The cache is a pure speed
    optimization: results are identical with or without it.
    """
    root = Path(project_dir)
    first_party = (
        set(first_party_modules) if first_party_modules is not None else _infer_first_party(root)
    )

    imports: list[ImportSite] = []
    dynamics: list[DynamicImportSite] = []
    errors: list[ImportParseError] = []
    analyzed = 0
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            # A non-UTF-8 / binary file with a .py suffix (some repos ship such test fixtures) must
            # not crash the scan — record it as an unreadable file and stay cautious.
            errors.append(ImportParseError(file=rel, message=f"cannot read: {exc}"))
            continue
        analyzed += 1
        analysis = _analyze_cached(text, rel, str(path), cache)
        imports.extend(analysis.imports)
        dynamics.extend(analysis.dynamic_sites)
        if analysis.parse_error is not None:
            errors.append(analysis.parse_error)

    imports.sort(key=lambda s: (s.file, s.lineno, s.col))
    dynamics.sort(key=lambda s: (s.file, s.lineno, s.col))
    return ImportGraph(
        import_sites=tuple(imports),
        dynamic_sites=tuple(dynamics),
        first_party_modules=tuple(sorted(first_party)),
        parse_errors=tuple(errors),
        analyzed_file_count=analyzed,
    )


def map_imports_to_distributions(
    graph: ImportGraph, dependencies: Sequence[Dependency]
) -> dict[str, tuple[ImportSite, ...]]:
    """Map each dependency that is actually imported to its import-site evidence.

    Builds a reverse index (import root -> canonical distribution name) from the Task 1.2
    resolver, then attributes every absolute import root in the graph to its distribution.
    Distributions that are never imported simply do not appear in the result.
    """
    reverse: dict[str, str] = {}
    for dependency in dependencies:
        mapping = resolve_import_names(dependency.raw_name or dependency.name)
        for import_name in mapping.import_names:
            reverse.setdefault(import_name.split(".")[0], dependency.name)

    result: dict[str, list[ImportSite]] = {}
    for root, sites in graph.import_roots().items():
        distribution = reverse.get(root)
        if distribution is not None:
            result.setdefault(distribution, []).extend(sites)

    return {dist: tuple(sites) for dist, sites in result.items()}
