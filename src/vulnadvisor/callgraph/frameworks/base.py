# File: src/vulnadvisor/callgraph/frameworks/base.py
"""Framework plugins: teach the call graph which callables a framework invokes for you.

Web frameworks rarely call your handlers directly — they *register* them (a route decorator, a URL
conf entry, a signal receiver) and dispatch them later. A naive call graph rooted only at module
top-level therefore can't reach a vulnerable symbol used inside a handler with a proper path.

A :class:`FrameworkPlugin` inspects a parsed module and reports the *entry points* the framework
will invoke — by the function (or view-class) name. :func:`collect_entry_points` runs the enabled
plugins across the project; the call-path search then seeds its BFS from those names so a
handler -> helper -> vulnerable-call chain yields a path rooted at the real entry point. Plugins are
independent: enabling or disabling one never changes another's results.
"""

import ast
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from vulnadvisor.callgraph.import_graph import _iter_python_files

__all__ = [
    "EntryPoint",
    "FrameworkPlugin",
    "collect_entry_points",
    "entry_point_names",
]


@dataclass(frozen=True)
class EntryPoint:
    """A callable a framework invokes on your behalf, identified by ``name`` for call-graph rooting.

    ``name`` is a first-party function name or a view-class name (for class-based views, where the
    framework dispatches the class's HTTP-verb methods). ``reason`` explains the registration so the
    evidence can say *why* the handler is reachable.
    """

    file: str
    name: str
    framework: str
    reason: str


@runtime_checkable
class FrameworkPlugin(Protocol):
    """Reports the framework entry points registered in a parsed module."""

    name: str

    def entry_points(self, tree: ast.Module, rel: str) -> list[EntryPoint]:
        """Return the entry points this framework registers in ``tree`` (file ``rel``)."""
        ...


def collect_entry_points(
    project_dir: Path, plugins: Sequence[FrameworkPlugin]
) -> tuple[EntryPoint, ...]:
    """Run every plugin over each source file, returning all framework entry points found.

    Parsing and each plugin are defensive: a file that won't parse or a plugin that raises is
    skipped, never crashing the scan. Over-reporting an entry point is sound — it only adds a BFS
    root (more reported paths), never hides one.
    """
    root = Path(project_dir)
    found: list[EntryPoint] = []
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue
        for plugin in plugins:
            try:
                found.extend(plugin.entry_points(tree, rel))
            except (ValueError, AttributeError, TypeError):
                continue  # an individual plugin must never break the scan
    return tuple(found)


def entry_point_names(entry_points: Iterable[EntryPoint]) -> frozenset[str]:
    """Collapse entry points to the set of names used to seed call-graph roots."""
    return frozenset(ep.name for ep in entry_points)
