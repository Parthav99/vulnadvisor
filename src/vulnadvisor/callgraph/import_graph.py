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
    ImportedName,
    ImportGraph,
    ImportKind,
    ImportParseError,
    ImportSite,
)

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


def _func_repr(func: ast.expr) -> str:
    """Best-effort source text of a call target (for dynamic-site detail)."""
    try:
        return ast.unparse(func)
    except (ValueError, AttributeError):
        return "<dynamic call>"


def _dynamic_kind(call: ast.Call) -> DynamicImportKind | None:
    """Classify a call as a dynamic import/exec construct, or ``None`` if it is neither."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id == "__import__":
            return DynamicImportKind.DUNDER_IMPORT
        if func.id == "eval":
            return DynamicImportKind.EVAL
        if func.id == "exec":
            return DynamicImportKind.EXEC
    elif isinstance(func, ast.Attribute):
        if func.attr in ("import_module", "__import__"):
            return DynamicImportKind.IMPORTLIB
    return None


def _names(node: ast.Import | ast.ImportFrom) -> tuple[ImportedName, ...]:
    """Convert ast aliases to :class:`ImportedName` records."""
    return tuple(ImportedName(name=alias.name, asname=alias.asname) for alias in node.names)


def _analyze_source(
    text: str, rel: str, filename: str
) -> tuple[list[ImportSite], list[DynamicImportSite], ImportParseError | None]:
    """Parse one source file's text, returning its imports, dynamic sites, and any parse error."""
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        return [], [], ImportParseError(file=rel, message=f"syntax error: {exc}")

    imports: list[ImportSite] = []
    dynamics: list[DynamicImportSite] = []
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
        elif isinstance(node, ast.Call):
            kind = _dynamic_kind(node)
            if kind is not None:
                dynamics.append(
                    DynamicImportSite(
                        file=rel,
                        lineno=node.lineno,
                        col=node.col_offset,
                        kind=kind,
                        detail=_func_repr(node.func),
                    )
                )
    return imports, dynamics, None


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
    project_dir: Path, *, first_party_modules: Iterable[str] | None = None
) -> ImportGraph:
    """Build the :class:`ImportGraph` for the project rooted at ``project_dir``."""
    root = Path(project_dir)
    first_party = (
        set(first_party_modules) if first_party_modules is not None else _infer_first_party(root)
    )

    imports: list[ImportSite] = []
    dynamics: list[DynamicImportSite] = []
    errors: list[ImportParseError] = []
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(ImportParseError(file=rel, message=f"cannot read: {exc}"))
            continue
        file_imports, file_dynamics, error = _analyze_source(text, rel, str(path))
        imports.extend(file_imports)
        dynamics.extend(file_dynamics)
        if error is not None:
            errors.append(error)

    imports.sort(key=lambda s: (s.file, s.lineno, s.col))
    dynamics.sort(key=lambda s: (s.file, s.lineno, s.col))
    return ImportGraph(
        import_sites=tuple(imports),
        dynamic_sites=tuple(dynamics),
        first_party_modules=tuple(sorted(first_party)),
        parse_errors=tuple(errors),
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
