# File: src/vulnadvisor/callgraph/call_paths.py
"""Demand-driven call-path search: is a vulnerable symbol actually *called* from the code?

Seeded by a dependency's import names and its advisory's vulnerable symbol names, we build a
lazy per-module call graph and search from module entry points to a call site of the vulnerable
symbol. We never build a whole-program graph; analysis is per file and stops at the first path.

A call is treated as hitting the vulnerable symbol when it is ``pkg.symbol(...)`` on the imported
package (or an alias) or ``symbol(...)`` for a name imported ``from pkg``. Reflective access to
the package — ``getattr(pkg, name)`` — is recorded as a :class:`PackageReflection` so a
type-informed resolver (M7) can later decide *which* attribute it resolves to; until then it is
treated conservatively. Genuinely opaque dynamic calls (``eval``/``exec``/``__import__`` or a
computed callee) are flagged separately because no resolver can pin them down.
"""

import ast
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from vulnadvisor.callgraph.import_graph import _iter_python_files
from vulnadvisor.model.callpath import CallPath, CallStep

__all__ = ["CallGraphResult", "PackageReflection", "find_vulnerable_call_paths"]

_MODULE_KEY = "<module>"
_OPAQUE_CALL_NAMES = frozenset({"eval", "exec", "__import__"})


@dataclass(frozen=True)
class PackageReflection:
    """A reflective attribute access on the vulnerable package: ``getattr(<alias>, <name_arg>)``.

    ``name_arg`` is the source text of the attribute-name argument (e.g. ``'"safe_load"'`` or
    ``'func_name'``). A resolver may map it to the concrete attribute(s) it can take; on its own,
    static analysis must assume it could reach the vulnerable symbol.
    """

    file: str
    lineno: int
    col: int
    alias: str
    name_arg: str


@dataclass(frozen=True)
class CallGraphResult:
    """The outcome of the per-project call-path search for one (package, symbols) pair."""

    paths: tuple[CallPath, ...] = ()
    reflections: tuple[PackageReflection, ...] = ()
    has_opaque_dynamic: bool = False

    @property
    def has_dynamic(self) -> bool:
        """Whether any dispatch could hide a call: reflective access or an opaque dynamic call."""
        return bool(self.reflections) or self.has_opaque_dynamic


@dataclass
class _Node:
    """A call-graph node: a first-party function/method or the module scope."""

    key: str
    file: str
    lineno: int
    raw_calls: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    vuln_calls: list[tuple[str, int]] = field(default_factory=list)
    reflections: list[PackageReflection] = field(default_factory=list)
    opaque_dynamic: bool = False


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


def _package_reflection(
    call: ast.Call, module_aliases: set[str], rel: str
) -> PackageReflection | None:
    """Return a :class:`PackageReflection` for ``getattr(<pkg_alias>, name)``, else ``None``."""
    if call.keywords or len(call.args) < 2:
        return None
    obj = call.args[0]
    if isinstance(obj, ast.Name) and obj.id in module_aliases:
        try:
            name_arg = ast.unparse(call.args[1])
        except (ValueError, AttributeError):
            name_arg = "<dynamic>"
        return PackageReflection(
            file=rel, lineno=call.lineno, col=call.col_offset, alias=obj.id, name_arg=name_arg
        )
    return None


def _classify_call(
    call: ast.Call,
    node: _Node,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
    rel: str,
) -> None:
    """Update ``node`` with edge / vuln / reflection / opaque-dynamic info from a single call."""
    func = call.func
    if isinstance(func, ast.Name):
        node.raw_calls.add(func.id)
        if func.id == "getattr":
            reflection = _package_reflection(call, module_aliases, rel)
            if reflection is not None:
                node.reflections.append(reflection)
            else:
                node.opaque_dynamic = True  # getattr on a non-package / unusual receiver
        elif func.id in _OPAQUE_CALL_NAMES:
            node.opaque_dynamic = True
    elif not isinstance(func, ast.Attribute):
        node.opaque_dynamic = True  # computed callee, e.g. handlers[key]() or factory()()

    vuln = _vuln_call_name(call, module_aliases, imported_vuln_names, vulnerable_names)
    if vuln is not None:
        node.vuln_calls.append((vuln, call.lineno))


def _collect(
    scope: ast.AST,
    node: _Node,
    module_aliases: set[str],
    imported_vuln_names: set[str],
    vulnerable_names: frozenset[str],
    rel: str,
) -> None:
    """Attribute every call within ``scope`` to ``node``."""
    for child in ast.walk(scope):
        if isinstance(child, ast.Call):
            _classify_call(child, node, module_aliases, imported_vuln_names, vulnerable_names, rel)


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
        _collect(scope, target, module_aliases, imported_vuln_names, vulnerable_names, rel)

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


def _roots(nodes: dict[str, _Node], entry_points: frozenset[str]) -> list[str]:
    """Return the BFS roots: the module scope plus any framework entry-point functions/methods.

    A node is a framework root when its key is an entry-point name, or its enclosing class is (so a
    class-based view's HTTP-verb methods, keyed ``Class.method``, are all rooted).
    """
    roots = [_MODULE_KEY]
    for key in nodes:
        if key == _MODULE_KEY:
            continue
        if key in entry_points or key.split(".")[0] in entry_points:
            roots.append(key)
    return roots


def _find_path(nodes: dict[str, _Node], entry_points: frozenset[str]) -> CallPath | None:
    """BFS from the module + framework entry points to a vulnerable call; build that path."""
    visited: dict[str, str | None] = {root: None for root in _roots(nodes, entry_points)}
    queue: deque[str] = deque(visited)
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
    entry_points: Iterable[str] = (),
) -> CallGraphResult:
    """Search for call paths to the vulnerable symbol, also surfacing reflective/opaque dispatch.

    Returns a :class:`CallGraphResult`: any concrete call ``paths`` found, the
    :class:`PackageReflection` sites (``getattr`` on the package, resolvable later by type info),
    and ``has_opaque_dynamic`` for calls no analysis can pin down (``eval``/``exec`` or a computed
    callee). ``entry_points`` are framework-registered handler/view names that seed the BFS in
    addition to the module scope, so a vuln reached only through a handler is rooted at it. An empty
    result means no concrete call and no dispatch that could hide one.
    """
    import_roots = frozenset(name.split(".")[0] for name in import_names)
    vuln_names = frozenset(vulnerable_names)
    entries = frozenset(entry_points)
    if not import_roots or not vuln_names:
        return CallGraphResult()

    root = Path(project_dir)
    paths: list[CallPath] = []
    reflections: list[PackageReflection] = []
    opaque = False
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
        for node in nodes.values():
            reflections.extend(node.reflections)
            if node.opaque_dynamic:
                opaque = True
        found = _find_path(nodes, entries)
        if found is not None:
            paths.append(found)
    return CallGraphResult(
        paths=tuple(paths), reflections=tuple(reflections), has_opaque_dynamic=opaque
    )
