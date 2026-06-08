"""Demand-driven call-path search: is a vulnerable symbol actually *called* from the code?

Seeded by a dependency's import names and its advisory's vulnerable symbol names, we build a
lazy per-module call graph and search from module entry points to a call site of the vulnerable
symbol. We never build a whole-program graph; analysis is per file and stops at the first path.

A call is treated as hitting the vulnerable symbol when it is ``pkg.symbol(...)`` on the imported
package (or an alias) or ``symbol(...)`` for a name imported ``from pkg``. Dynamic dispatch
(``getattr``/``eval``/``exec``/computed callees) is recorded so the caller can downgrade to
DYNAMIC_UNKNOWN rather than claim the symbol is not called.
"""

import ast
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from vulnadvisor.callgraph.import_graph import _iter_python_files
from vulnadvisor.model.callpath import CallPath, CallStep

__all__ = ["find_vulnerable_call_paths"]

_MODULE_KEY = "<module>"
_DYNAMIC_CALL_NAMES = frozenset({"getattr", "eval", "exec", "__import__"})


@dataclass
class _Node:
    """A call-graph node: a first-party function/method or the module scope."""

    key: str
    file: str
    lineno: int
    raw_calls: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    vuln_calls: list[tuple[str, int]] = field(default_factory=list)
    dynamic: bool = False


def _bindings(
    tree: ast.Module, import_roots: frozenset[str], vulnerable_names: frozenset[str]
) -> tuple[set[str], set[str]]:
    """Return (module aliases bound to the package, local names imported from it)."""
    module_aliases: set[str] = set()
    imported_vuln_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in import_roots:
                    module_aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import -> first-party, not the vulnerable package
                continue
            module = node.module or ""
            if module.split(".")[0] in import_roots:
                for alias in node.names:
                    if alias.name in vulnerable_names:
                        imported_vuln_names.add(alias.asname or alias.name)
    return module_aliases, imported_vuln_names


def _vuln_call_name(
    call: ast.Call,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
) -> str | None:
    """Return a display name if this call targets the vulnerable symbol, else ``None``."""
    func = call.func
    if isinstance(func, ast.Attribute):
        base = func.value
        if (
            isinstance(base, ast.Name)
            and base.id in module_aliases
            and func.attr in vulnerable_names
        ):
            return f"{base.id}.{func.attr}"
        return None
    if isinstance(func, ast.Name) and func.id in imported_vuln_names:
        return func.id
    return None


def _classify_call(
    call: ast.Call,
    node: _Node,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
) -> None:
    """Update ``node`` with edge/vuln/dynamic information from a single call."""
    func = call.func
    if isinstance(func, ast.Name):
        node.raw_calls.add(func.id)
        if func.id in _DYNAMIC_CALL_NAMES:
            node.dynamic = True
    elif not isinstance(func, ast.Attribute):
        node.dynamic = True  # computed callee, e.g. handlers[key]() or factory()()

    vuln = _vuln_call_name(call, module_aliases, imported_vuln_names, vulnerable_names)
    if vuln is not None:
        node.vuln_calls.append((vuln, call.lineno))


def _collect(
    scope: ast.AST,
    node: _Node,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
) -> None:
    """Attribute every call within ``scope`` to ``node``."""
    for child in ast.walk(scope):
        if isinstance(child, ast.Call):
            _classify_call(child, node, module_aliases, imported_vuln_names, vulnerable_names)


def _build_nodes(
    rel: str,
    tree: ast.Module,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
) -> dict[str, _Node]:
    """Build the per-file call-graph nodes (module scope, functions, and methods)."""
    module_node = _Node(key=_MODULE_KEY, file=rel, lineno=1)
    nodes: list[_Node] = []
    top_level_funcs: set[str] = set()

    def collect(scope: ast.AST, target: _Node) -> None:
        _collect(scope, target, module_aliases, imported_vuln_names, vulnerable_names)

    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            node = _Node(key=stmt.name, file=rel, lineno=stmt.lineno)
            collect(stmt, node)
            nodes.append(node)
            top_level_funcs.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    node = _Node(key=f"{stmt.name}.{item.name}", file=rel, lineno=item.lineno)
                    collect(item, node)
                    nodes.append(node)
        else:
            collect(stmt, module_node)
    nodes.append(module_node)

    # First-party edges: a call by simple name to a top-level function in this same module.
    for node in nodes:
        node.calls = node.raw_calls & top_level_funcs
    return {node.key: node for node in nodes}


def _find_path(nodes: dict[str, _Node]) -> CallPath | None:
    """BFS from the module entry to a node containing a vulnerable call; build that path."""
    visited: dict[str, str | None] = {_MODULE_KEY: None}
    queue: deque[str] = deque([_MODULE_KEY])
    target: str | None = None
    while queue:
        key = queue.popleft()
        node = nodes.get(key)
        if node is None:
            continue
        if node.vuln_calls:
            target = key
            break
        for callee in sorted(node.calls):
            if callee in nodes and callee not in visited:
                visited[callee] = key
                queue.append(callee)

    if target is None:
        # A vulnerable call exists but isn't reachable from module top-level (e.g. a library API
        # entry point). Still report it — never drop a real call site.
        for key, node in nodes.items():
            if node.vuln_calls:
                target = key
                visited = {key: None}
                break
    if target is None:
        return None

    chain: list[str] = []
    cursor: str | None = target
    while cursor is not None:
        chain.append(cursor)
        cursor = visited.get(cursor)
    chain.reverse()

    target_node = nodes[target]
    vuln_name, vuln_line = target_node.vuln_calls[0]
    steps = [CallStep(qualname=key, file=nodes[key].file, line=nodes[key].lineno) for key in chain]
    steps.append(CallStep(qualname=vuln_name, file=target_node.file, line=vuln_line))
    return CallPath(steps=tuple(steps))


def find_vulnerable_call_paths(
    project_dir: Path,
    *,
    import_names: Iterable[str],
    vulnerable_names: Iterable[str],
) -> tuple[list[CallPath], bool]:
    """Find call paths to the vulnerable symbol; also report if dynamic dispatch is present.

    Returns ``(paths, has_dynamic_dispatch)``. ``paths`` is empty when no concrete call to the
    vulnerable symbol was found. ``has_dynamic_dispatch`` is ``True`` when reflective/computed
    calls in first-party code mean a call could be hidden.
    """
    import_roots = frozenset(name.split(".")[0] for name in import_names)
    vuln_names = frozenset(vulnerable_names)
    if not import_roots or not vuln_names:
        return [], False

    root = Path(project_dir)
    paths: list[CallPath] = []
    dynamic = False
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue
        module_aliases, imported_vuln_names = _bindings(tree, import_roots, vuln_names)
        if not module_aliases and not imported_vuln_names:
            continue
        nodes = _build_nodes(rel, tree, module_aliases, imported_vuln_names, vuln_names)
        if any(node.dynamic for node in nodes.values()):
            dynamic = True
        found = _find_path(nodes)
        if found is not None:
            paths.append(found)
    return paths, dynamic
