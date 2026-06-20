# File: src/vulnadvisor/sast/taint.py
"""Demand-driven taint propagation: prove a flow from a real source to a sink (Task 16.3 / 20.2).

This is the SAST differentiator. Task 16.2 finds every sink and classifies it *intra-procedurally*
(literal -> ``SANITIZED``, non-literal -> ``POSSIBLE_FLOW``). Task 16.3 takes those as a floor and
**escalates** the ones it can tie to a recognized taint source; Task 20.2 carries that escalation
*across module boundaries* so a source in module A reaching a sink in module B via an imported
callable is still ``CONFIRMED_FLOW``.

* **Sources** seed taint — framework entry-point parameters (FastAPI/Flask routes, Django views and
  signals, Celery tasks), the Flask ``request`` global, and ``stdin`` / ``argv`` / the environment.
* **Propagation** is conservative and inter-procedural over the project's import/call graph:
  assignments, calls passing a tainted value to a first-party helper (taint flows to the parameter),
  returns, f-strings / ``%`` / ``+`` concatenation, and containers. **Cross-module** calls are
  resolved through imports — ``from pkg.helpers import f`` (incl. relative imports and re-export
  chains), ``pkg.helpers.f(...)``, and class methods reached via ``Cls()``/``Cls.static`` — and a
  reused **per-function taint summary** (does a tainted parameter taint the return value?) keeps the
  search tractable. **Object state** (Task 20.3) is tracked field-sensitively: ``self.attr`` is a
  distinct taint slot, a constructor parameter stored on a field propagates to later reads, a
  dataclass field is seeded from its positional argument, and an instance variable
  (``svc = Cls(...); svc.m()``) resolves its method and carries its tracked fields in as the
  method's ``self.*``; a dynamic attribute write (``setattr`` with a computed name) escalates the
  whole object to ``DYNAMIC_UNKNOWN``. When unsure, a value is treated as tainted (over-report, then
  let the tier speak) — never the reverse.
* **Sinks** are the §3 rule pack. A tainted value reaching a sink's dangerous argument with no
  CWE-matching sanitizer on the path -> ``CONFIRMED_FLOW`` with the source->sink :class:`CallPath`
  as evidence. A path crossing a dynamic construct (``eval``/``exec``/``getattr`` dispatch, a
  computed callee) -> ``DYNAMIC_UNKNOWN`` — escalated, never quietly dropped.

**FFI boundary policy** (docs/sast-design.md): a call into a callable the engine cannot resolve —
a third-party function, a C/Rust native extension, or any unparsed module — falls to
:meth:`_Analyzer._unknown_call`, which *keeps* the value tainted (dropping any sanitizer claims). A
crossing into native code therefore escalates the taint, never silently terminates the trace.

Soundness direction is always *toward* a finding (docs/sast-design.md §4): a sink the engine cannot
tie to a source keeps its intra-procedural tier; the taint pass only ever raises concern. The
analysis is flow-insensitive within a function (sanitizer state merges by intersection across
paths, so a *partially* sanitized value stays unsanitized — a real sink is never cleared by one safe
branch). The per-source function is pure; the only I/O is reading the project's files.
"""

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from vulnadvisor.callgraph.frameworks import DEFAULT_PLUGINS, FrameworkPlugin
from vulnadvisor.callgraph.import_graph import _iter_python_files
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.sast import rules, sinks
from vulnadvisor.sast.model import SastFinding, SastTier, tier_concern
from vulnadvisor.sast.sinks import find_sinks

__all__ = ["analyze_source", "analyze_taint"]

_MODULE_KEY = "<module>"
_MAX_ITERS = 64  # fixpoint iteration cap; taint is monotone so this is a safety bound only

# Module globals that are taint sources, matched on their import-resolved fully-qualified name.
_ENV_FQNS = frozenset({"os.environ", "os.getenv", "posix.environ"})
_ARGV_FQNS = frozenset({"sys.argv"})
_STDIN_FQNS = frozenset({"sys.stdin"})
_FLASK_REQUEST_FQN = "flask.request"

# Calls whose presence on a tainted value's provenance blocks certainty (docs §4 DYNAMIC_UNKNOWN).
_DYNAMIC_NAMES = frozenset({"eval", "exec", "__import__", "getattr"})

# In-place container mutators: ``c.append(t)`` / ``c.update(t)`` etc. taint the receiver ``c`` with
# the argument's taint (the result is usually discarded, so the effect is on the container, not a
# return value). Whole-container conservatism — a tainted element taints the whole container.
_MUTATION_METHODS = frozenset(
    {"append", "extend", "insert", "add", "update", "setdefault", "__setitem__"}
)

# Framework -> the source-kind label reported for an entry-point parameter.
_FRAMEWORK_SOURCE_KIND: dict[str, str] = {
    "fastapi": "http-parameter",
    "flask": "http-parameter",
    "django": "http-parameter",
    "celery": "task-parameter",
}
_DEFAULT_ENTRY_SOURCE_KIND = "entry-parameter"

# A summary/emit memo key: a function is identified project-wide by its module and qualname, and an
# analysis is parameterized by *which* of its parameters carry taint (the source identity is an
# over-approximation kept out of the key — the first reaching flow supplies the evidence).
_SummaryKey = tuple[str, str, frozenset[str]]


def _sanitizer_map() -> dict[str, frozenset[str]]:
    """Build ``sanitizer-name -> {cleared CWEs}`` from the rule pack (a sanitizer is CWE-scoped)."""
    out: dict[str, set[str]] = {}
    for rule in rules.RULES:
        for name in rule.sanitizers:
            out.setdefault(name, set()).add(rule.cwe)
    return {name: frozenset(cwes) for name, cwes in out.items()}


_SANITIZERS: dict[str, frozenset[str]] = _sanitizer_map()


def _module_fqn(rel: str) -> str:
    """Map a project-relative POSIX path to its importable dotted module name.

    ``pkg/helpers.py`` -> ``pkg.helpers``; ``pkg/__init__.py`` -> ``pkg``; ``m.py`` -> ``m``. A
    leading ``src/`` segment (the standard src-layout) is stripped so the name matches how the code
    imports it (``src/pkg/x.py`` is imported as ``pkg.x``). This is a best-effort mapping used only
    to resolve first-party imports; an unresolved import simply falls back to the conservative
    unknown-call handling, so a wrong guess never causes a missed flow.
    """
    parts = [p for p in rel.split("/") if p]
    if len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return ""
    last = parts[-1]
    if last.endswith(".py"):
        last = last[:-3]
    parts = parts[:-1] if last == "__init__" else [*parts[:-1], last]
    return ".".join(parts)


@dataclass(frozen=True)
class _Source:
    """Where a tainted value originated, for evidence."""

    kind: str
    file: str
    line: int


@dataclass(frozen=True)
class _Taint:
    """A tainted value: its origin, the CWEs already sanitized on every path, and a dynamic flag.

    ``cleared`` is intersected when values merge (a CWE is cleared only if cleared on *all* paths),
    so a partially sanitized value stays dangerous. ``dynamic`` is set when the value's provenance
    crosses a construct no static analysis can pin down; it only ever turns on (never off).
    """

    source: _Source
    cleared: frozenset[str]
    dynamic: bool


def _merge_taint(a: _Taint | None, b: _Taint | None) -> _Taint | None:
    """Merge two (maybe-absent) taints: tainted if either is, clears intersected, dynamic OR'd."""
    if a is None:
        return b
    if b is None:
        return a
    a_key = (a.source.file, a.source.line, a.source.kind)
    b_key = (b.source.file, b.source.line, b.source.kind)
    source = a.source if a_key <= b_key else b.source  # deterministic representative origin
    return _Taint(source=source, cleared=a.cleared & b.cleared, dynamic=a.dynamic or b.dynamic)


@dataclass
class _FuncInfo:
    """A first-party function/method (or the module scope) as a taint-analysis unit."""

    qualname: str
    scope: ast.AST
    file: str
    lineno: int
    params: list[str]  # all parameter names (for entry-point seeding)
    positional: list[str]  # positional parameter names (for call-argument mapping)
    class_name: str | None = None
    method_kind: str | None = None  # 'instance' | 'class' | 'static' for methods, else None


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[list[str], list[str]]:
    """Return ``(all_param_names, positional_param_names)`` for a function definition."""
    a = node.args
    positional = [arg.arg for arg in (*a.posonlyargs, *a.args)]
    allp = list(positional) + [arg.arg for arg in a.kwonlyargs]
    if a.vararg is not None:
        allp.append(a.vararg.arg)
    if a.kwarg is not None:
        allp.append(a.kwarg.arg)
    return allp, positional


def _method_kind(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Classify a method by its decorators: ``static`` / ``class`` / plain ``instance``.

    Used to decide whether a bound call (``Cls.static(x)`` / ``inst.method(x)``) implicitly consumes
    the leading ``self``/``cls`` parameter when mapping call arguments to parameters.
    """
    for dec in node.decorator_list:
        name: str | None = None
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        if name == "staticmethod":
            return "static"
        if name == "classmethod":
            return "class"
    return "instance"


def _attr_path(node: ast.expr) -> str | None:
    """A dotted taint key for a ``Name`` or attribute chain rooted at a ``Name`` (Task 20.3).

    ``x`` -> ``"x"``; ``self.cmd`` -> ``"self.cmd"``; ``obj.a.b`` -> ``"obj.a.b"``. Anything not
    rooted at a bare name (a subscript or call base) returns ``None``. These dotted strings are used
    as ordinary keys in the taint state so an instance attribute is tracked field-sensitively
    alongside plain locals — ``self.cmd`` is a distinct slot from ``self.path``.
    """
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_dataclass(node: ast.ClassDef) -> bool:
    """Whether ``node`` is decorated ``@dataclass`` / ``@dataclasses.dataclass`` (call form too)."""
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name: str | None = None
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
        if name == "dataclass":
            return True
    return False


def _dataclass_fields(node: ast.ClassDef) -> list[str]:
    """The declared field names of a dataclass, in definition order (annotated class attributes).

    These are the positional/keyword parameters of the synthesized ``__init__`` — so constructing
    ``Cmd(tainted)`` maps the tainted argument onto the first field. Best-effort: ``ClassVar`` and
    ``init=False`` fields are not filtered (over-mapping only ever raises concern, never lowers it).
    """
    fields: list[str] = []
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields.append(item.target.id)
    return fields


def _target_names(target: ast.expr) -> list[str]:
    """The taint keys that receive an assignment's value taint.

    Recurses tuple/list unpacking and ``*starred`` targets. A subscript target ``c[k] = v`` taints
    the *whole container* ``c`` (Task 20.1: index-sensitivity is not tracked, so a tainted element
    conservatively taints the container — a sound over-approximation, never a downgrade). An
    attribute target ``self.x = v`` taints the field key ``"self.x"`` (Task 20.3: field-sensitive
    instance state). A dynamic attribute write (``setattr``) is handled separately and escalates.
    """
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, ast.Subscript):
        return _base_name_ids(target.value)  # c[k] = v -> taint container c (whole-container)
    if isinstance(target, ast.Attribute):
        path = _attr_path(target)  # self.x = v -> taint the field slot self.x (Task 20.3)
        return [path] if path is not None else []
    return []


def _base_name_ids(node: ast.expr) -> list[str]:
    """The root taint key of a subscript chain (``c[i][j]`` -> ``['c']``), else ``[]``.

    Used for whole-container taint on subscript writes and in-place mutation: the base slot that
    holds the container is the thing taint attaches to. An attribute base (``self.items[i]``)
    resolves to its field key ``"self.items"`` (Task 20.3) so container taint survives on object
    state too; a subscript rooted at a call/other expression yields ``[]``.
    """
    cur: ast.expr = node
    while isinstance(cur, ast.Subscript):
        cur = cur.value
    path = _attr_path(cur)
    return [path] if path is not None else []


@dataclass
class _ModuleUnit:
    """One first-party module registered with the project: its fqn and its analyzer."""

    fqn: str
    analyzer: "_Analyzer"


@dataclass
class _BodyState:
    """The result of analyzing a function body: the tainted slots and the local class environment.

    ``taint`` maps every tainted slot (locals, container bases, and field keys like ``self.cmd`` or
    ``svc.path``) to its :class:`_Taint`. ``classes`` maps a local variable to the first-party
    class(es) it was constructed from (``svc = Service(...)``), so a later ``svc.run(...)`` resolves
    to the right method and seeds that method's ``self.*`` from the instance's tracked fields.
    """

    taint: dict[str, _Taint]
    classes: dict[str, set[tuple["_Analyzer", str]]]


class _Project:
    """The project-wide taint analysis: every module's :class:`_Analyzer` and the shared caches.

    Cross-module resolution (imported callables, re-export chains, class methods) and the
    per-function summary/emit memos live here so a function analyzed via one entry point is reused
    by another and the search across the whole import graph stays tractable. Findings accumulate;
    :meth:`run` seeds every module's roots and returns them deterministically ordered by discovery.
    """

    def __init__(self) -> None:
        self.modules: dict[str, _ModuleUnit] = {}
        self.findings: list[SastFinding] = []
        self._return_memo: dict[_SummaryKey, _Taint | None] = {}
        self._return_active: set[_SummaryKey] = set()
        self._emit_visited: set[_SummaryKey] = set()
        # Per-method instance-attribute summary: which ``self.*`` fields a method taints given a set
        # of tainted parameters/incoming fields. Memoized project-wide (Task 20.3) and reused by
        # every constructor call and method write-back, so cross-method field flow stays tractable.
        self._attr_memo: dict[_SummaryKey, dict[str, _Taint]] = {}
        self._attr_active: set[_SummaryKey] = set()

    def add(self, rel: str, tree: ast.Module, entries: dict[str, str]) -> None:
        """Register a module's analyzer under its import fqn (last write wins on collision)."""
        analyzer = _Analyzer(rel, tree, entries, self)
        self.modules[analyzer.module_fqn] = _ModuleUnit(analyzer.module_fqn, analyzer)

    def resolve_callable(
        self, module_fqn: str, symbol: str, seen: set[tuple[str, str]] | None = None
    ) -> "tuple[_Analyzer, _FuncInfo] | None":
        """Resolve ``module_fqn.symbol`` to the analyzer + function that defines it.

        Follows re-export chains (``pkg/__init__`` re-exporting ``pkg.helpers.f``). ``None`` when
        the module is not first-party (third-party / native / unparsed) or it is not a function.
        """
        if seen is None:
            seen = set()
        key = (module_fqn, symbol)
        if key in seen:
            return None
        seen.add(key)
        unit = self.modules.get(module_fqn)
        if unit is None:
            return None
        info = unit.analyzer.callable_funcs.get(symbol)
        if info is not None:
            return unit.analyzer, info
        forwarded = unit.analyzer.import_symbols.get(symbol)
        if forwarded is not None:
            return self.resolve_callable(forwarded[0], forwarded[1], seen)
        return None

    def resolve_class(
        self, module_fqn: str, name: str, seen: set[tuple[str, str]] | None = None
    ) -> "tuple[_Analyzer, str] | None":
        """Resolve ``module_fqn.name`` to the analyzer + defining class name (re-export aware)."""
        if seen is None:
            seen = set()
        key = (module_fqn, name)
        if key in seen:
            return None
        seen.add(key)
        unit = self.modules.get(module_fqn)
        if unit is None:
            return None
        if name in unit.analyzer.class_defs:
            return unit.analyzer, name
        forwarded = unit.analyzer.import_symbols.get(name)
        if forwarded is not None:
            return self.resolve_class(forwarded[0], forwarded[1], seen)
        return None

    def run(self) -> tuple[SastFinding, ...]:
        """Seed every module's roots (deterministic module order) and return the findings."""
        for fqn in sorted(self.modules):
            self.modules[fqn].analyzer.seed_roots()
        return tuple(self.findings)


class _Analyzer:
    """Per-module taint analysis: discovers source->sink flows across the import graph."""

    def __init__(
        self,
        rel: str,
        tree: ast.Module,
        entry_framework: dict[str, str],
        project: _Project,
    ) -> None:
        self.rel = rel
        self.project = project
        self.module_fqn = _module_fqn(rel)
        self.is_package = rel.endswith("__init__.py")
        self.bindings = sinks._build_bindings(tree)
        self.flask_names = frozenset(
            local for local, fqn in self.bindings.from_import.items() if fqn == _FLASK_REQUEST_FQN
        )
        # name -> framework, where name is a function name (route/task/receiver/FBV) or, for a
        # class-based view, the class name (Django dispatches its HTTP-verb methods).
        self.entry_framework = entry_framework
        self.callable_funcs: dict[str, _FuncInfo] = {}
        self.all_funcs: list[_FuncInfo] = []
        self.class_defs: set[str] = set()
        self.methods: dict[tuple[str, str], _FuncInfo] = {}
        # @dataclass classes and their declared field order, for synthesizing a generated __init__
        # (``Cmd(tainted)`` taints field ``Cmd.value``) when no explicit __init__ is written.
        self.is_dataclass: set[str] = set()
        self.dataclass_fields: dict[str, list[str]] = {}
        # local-imported-name -> (absolute module fqn, original symbol), for first-party resolution.
        self.import_symbols: dict[str, tuple[str, str]] = {}
        self._collect_imports(tree)
        self._collect_funcs(tree)

    # -- structure -------------------------------------------------------------------------

    def _abs_module(self, level: int, module: str | None) -> str:
        """Resolve a (possibly relative) ``from`` import to an absolute module fqn.

        ``level`` is the leading-dot count; ``module`` the text after the dots. A relative import is
        resolved against this module's own package (the module itself if it is a package's
        ``__init__``, else its parent), walking up one level per extra dot.
        """
        if level == 0:
            return module or ""
        base = self.module_fqn if self.is_package else self.module_fqn.rpartition(".")[0]
        for _ in range(level - 1):
            base = base.rpartition(".")[0]
        if module:
            return f"{base}.{module}" if base else module
        return base

    def _collect_imports(self, tree: ast.Module) -> None:
        """Record every ``from ... import name`` so first-party callables/classes can be resolved.

        Both absolute and relative imports are captured (relative resolved to an absolute fqn). Each
        local binding maps to ``(module_fqn, original_symbol)``; resolution against the project's
        module set decides first-partyness later (a third-party target simply never resolves).
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                abs_mod = self._abs_module(node.level or 0, node.module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.import_symbols[local] = (abs_mod, alias.name)

    def _collect_funcs(self, tree: ast.Module) -> None:
        """Collect top-level functions (targets + roots) and class methods (roots + targets)."""
        module_body: list[ast.stmt] = []
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                allp, pos = _param_names(stmt)
                info = _FuncInfo(stmt.name, stmt, self.rel, stmt.lineno, allp, pos)
                self.callable_funcs[stmt.name] = info
                self.all_funcs.append(info)
            elif isinstance(stmt, ast.ClassDef):
                self.class_defs.add(stmt.name)
                if _is_dataclass(stmt):
                    self.is_dataclass.add(stmt.name)
                    self.dataclass_fields[stmt.name] = _dataclass_fields(stmt)
                for item in stmt.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                        allp, pos = _param_names(item)
                        info = _FuncInfo(
                            f"{stmt.name}.{item.name}",
                            item,
                            self.rel,
                            item.lineno,
                            allp,
                            pos,
                            class_name=stmt.name,
                            method_kind=_method_kind(item),
                        )
                        self.all_funcs.append(info)
                        self.methods[(stmt.name, item.name)] = info
            else:
                module_body.append(stmt)
        module_scope = ast.Module(body=module_body, type_ignores=[])
        self.all_funcs.append(_FuncInfo(_MODULE_KEY, module_scope, self.rel, 1, [], []))

    # -- callee resolution (cross-module) --------------------------------------------------

    def _resolve_call_target(self, node: ast.Call) -> "tuple[_Analyzer, _FuncInfo, int] | None":
        """Resolve a call's callee to ``(owner_analyzer, func, skip)`` or ``None``.

        ``skip`` is the number of leading parameters an implicit bound receiver consumes (``self`` /
        ``cls``) so call arguments map onto the right parameters. Resolves local functions, imported
        first-party functions (incl. ``pkg.helpers.f`` and re-export chains), and class methods
        reached via ``Cls()``/``Cls.static``. Anything unresolved (third-party, native, computed)
        returns ``None`` and the caller falls back to the conservative unknown-call handling.
        """
        func = node.func
        if isinstance(func, ast.Name):
            info = self.callable_funcs.get(func.id)
            if info is not None:
                return self, info, 0
            forwarded = self.import_symbols.get(func.id)
            if forwarded is not None:
                resolved = self.project.resolve_callable(forwarded[0], forwarded[1])
                if resolved is not None:
                    return resolved[0], resolved[1], 0
            return None
        if isinstance(func, ast.Attribute):
            return self._resolve_attr_target(func)
        return None

    def _resolve_attr_target(
        self, func: ast.Attribute
    ) -> "tuple[_Analyzer, _FuncInfo, int] | None":
        """Resolve an attribute call (``mod.f`` / ``Cls().method`` / ``Cls.static``)."""
        attr = func.attr
        base = func.value
        # 1. module-qualified function via ``import a.b`` then ``a.b.func(...)``.
        fqn = sinks._resolve_module_fqn(func, self.bindings)
        if fqn is not None:
            mod, _, sym = fqn.rpartition(".")
            if mod:
                resolved = self.project.resolve_callable(mod, sym)
                if resolved is not None:
                    return resolved[0], resolved[1], 0
        if isinstance(base, ast.Name):
            # 2. module bound by ``from . import helpers`` then ``helpers.func(...)``.
            forwarded = self.import_symbols.get(base.id)
            if forwarded is not None:
                mod, sym = forwarded
                module_candidate = f"{mod}.{sym}" if mod else sym
                resolved = self.project.resolve_callable(module_candidate, attr)
                if resolved is not None:
                    return resolved[0], resolved[1], 0
            # 3. static/class method called on the bare class: ``Cls.static(x)`` / ``Cls.cm(x)``.
            cls = self._resolve_class_name(base.id)
            if cls is not None:
                bound = self._lookup_method(cls, attr)
                if bound is not None and bound[2] != "instance":
                    return bound[0], bound[1], 1 if bound[2] == "class" else 0
        # 4. instance method on an inline construction: ``Cls().method(x)``.
        if isinstance(base, ast.Call):
            cls = self._resolve_class_from_callee(base.func)
            if cls is not None:
                bound = self._lookup_method(cls, attr)
                if bound is not None:
                    return bound[0], bound[1], 0 if bound[2] == "static" else 1
        return None

    def _resolve_class_name(self, name: str) -> "tuple[_Analyzer, str] | None":
        """Resolve a local or imported class name to ``(owner_analyzer, class_name)``."""
        if name in self.class_defs:
            return self, name
        forwarded = self.import_symbols.get(name)
        if forwarded is not None:
            return self.project.resolve_class(forwarded[0], forwarded[1])
        return None

    def _resolve_class_from_callee(self, func: ast.expr) -> "tuple[_Analyzer, str] | None":
        """Resolve the class of a constructor call target (``Cls`` or ``mod.Cls``)."""
        if isinstance(func, ast.Name):
            return self._resolve_class_name(func.id)
        if isinstance(func, ast.Attribute):
            fqn = sinks._resolve_module_fqn(func, self.bindings)
            if fqn is not None:
                mod, _, sym = fqn.rpartition(".")
                if mod:
                    return self.project.resolve_class(mod, sym)
            base = func.value
            if isinstance(base, ast.Name):
                forwarded = self.import_symbols.get(base.id)
                if forwarded is not None:
                    candidate = f"{forwarded[0]}.{forwarded[1]}" if forwarded[0] else forwarded[1]
                    return self.project.resolve_class(candidate, func.attr)
        return None

    def _lookup_method(
        self, cls: "tuple[_Analyzer, str]", attr: str
    ) -> "tuple[_Analyzer, _FuncInfo, str] | None":
        """Find ``attr`` as a method of class ``cls`` -> ``(owner, func, method_kind)``."""
        owner, class_name = cls
        info = owner.methods.get((class_name, attr))
        if info is None:
            return None
        return owner, info, info.method_kind or "instance"

    # -- source recognition ----------------------------------------------------------------

    def _expr_source_kind(self, node: ast.expr) -> str | None:
        """Return the source kind if ``node`` directly reads a taint source, else ``None``."""
        if isinstance(node, ast.Name):
            fqn = self.bindings.from_import.get(node.id)
            kind = _fqn_source_kind(fqn)
            if kind is not None:
                return kind
            return "flask-request" if node.id in self.flask_names else None
        if isinstance(node, ast.Attribute):
            root, _ = sinks._attr_chain(node)
            if isinstance(root, ast.Name) and root.id in self.flask_names:
                return "flask-request"
            fqn = sinks._resolve_module_fqn(node, self.bindings)
            if fqn == _FLASK_REQUEST_FQN:
                return "flask-request"
            return _fqn_source_kind(fqn)
        return None

    # -- expression taint ------------------------------------------------------------------

    def _eval(self, node: ast.expr, tainted: dict[str, _Taint]) -> _Taint | None:
        """The taint of ``node`` under the current ``tainted`` state, or ``None`` if clean."""
        kind = self._expr_source_kind(node)
        if kind is not None:
            return _Taint(_Source(kind, self.rel, node.lineno), frozenset(), False)
        if isinstance(node, ast.Name):
            return tainted.get(node.id)
        if isinstance(node, ast.Call):
            return self._eval_call(node, tainted)
        if isinstance(node, ast.Attribute):
            # Field-sensitive read: the attribute's own slot (``self.cmd``) OR taint on the whole
            # base object (a wholly-tainted instance taints every attribute) — merged, never lost.
            path = _attr_path(node)
            direct = tainted.get(path) if path is not None else None
            return _merge_taint(direct, self._eval(node.value, tainted))
        if isinstance(node, ast.Subscript | ast.Starred | ast.Await):
            return self._eval(node.value, tainted)
        if isinstance(node, ast.FormattedValue):
            return self._eval(node.value, tainted)
        if isinstance(node, ast.NamedExpr):
            return self._eval(node.value, tainted)
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, tainted)
        if isinstance(node, ast.BinOp):
            return self._combine([self._eval(node.left, tainted), self._eval(node.right, tainted)])
        if isinstance(node, ast.BoolOp):
            return self._combine([self._eval(v, tainted) for v in node.values])
        if isinstance(node, ast.IfExp):
            return self._combine([self._eval(node.body, tainted), self._eval(node.orelse, tainted)])
        if isinstance(node, ast.Compare):
            return self._combine(
                [
                    self._eval(node.left, tainted),
                    *(self._eval(c, tainted) for c in node.comparators),
                ]
            )
        if isinstance(node, ast.JoinedStr):
            return self._combine([self._eval(v, tainted) for v in node.values])
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return self._combine([self._eval(e, tainted) for e in node.elts])
        if isinstance(node, ast.Dict):
            parts = [self._eval(v, tainted) for v in node.values]
            parts += [self._eval(k, tainted) for k in node.keys if k is not None]
            return self._combine(parts)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._combine(
                [self._eval(node.elt, tainted), *self._gen_taints(node.generators, tainted)]
            )
        if isinstance(node, ast.DictComp):
            return self._combine(
                [
                    self._eval(node.key, tainted),
                    self._eval(node.value, tainted),
                    *self._gen_taints(node.generators, tainted),
                ]
            )
        return None

    def _gen_taints(
        self, generators: list[ast.comprehension], tainted: dict[str, _Taint]
    ) -> list[_Taint | None]:
        return [self._eval(gen.iter, tainted) for gen in generators]

    def _combine(self, parts: Sequence[_Taint | None]) -> _Taint | None:
        result: _Taint | None = None
        for part in parts:
            result = _merge_taint(result, part)
        return result

    def _eval_call(self, node: ast.Call, tainted: dict[str, _Taint]) -> _Taint | None:
        """Taint from a call expression (source read, sanitizer, helper, dynamic, or unknown)."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "input":
                return _Taint(_Source("stdin", self.rel, node.lineno), frozenset(), False)
            if self.bindings.from_import.get(func.id) in _ENV_FQNS:
                return _Taint(_Source("environment", self.rel, node.lineno), frozenset(), False)
            if func.id in _DYNAMIC_NAMES:
                return self._dynamic_call(node, tainted)
            resolved = self._resolve_call_target(node)
            if resolved is not None:
                return self._call_summary(resolved, node, tainted)
            san = self._sanitizer_cwes(
                self.bindings.from_import.get(func.id, "")
            ) or self._sanitizer_cwes(func.id)
            if san is not None:
                return self._apply_sanitizer(node, tainted, san)
            return self._unknown_call(node, tainted, receiver=None)
        if isinstance(func, ast.Attribute):
            fqn = sinks._resolve_module_fqn(func, self.bindings)
            if fqn in _ENV_FQNS:
                return _Taint(_Source("environment", self.rel, node.lineno), frozenset(), False)
            receiver_kind = self._expr_source_kind(func.value)
            if receiver_kind is not None:  # environ.get(...) / stdin.read() / request.args.get(...)
                return _Taint(_Source(receiver_kind, self.rel, node.lineno), frozenset(), False)
            resolved = self._resolve_call_target(node)
            if resolved is not None:
                return self._call_summary(resolved, node, tainted)
            san = self._sanitizer_cwes(fqn or "") or self._sanitizer_cwes(func.attr)
            if san is not None:
                return self._apply_sanitizer(node, tainted, san)
            return self._unknown_call(node, tainted, receiver=func.value)
        return self._dynamic_call(node, tainted)  # computed callee, e.g. getattr(o, n)(x)

    def _sanitizer_cwes(self, name: str) -> frozenset[str] | None:
        return _SANITIZERS.get(name)

    def _apply_sanitizer(
        self, node: ast.Call, tainted: dict[str, _Taint], cwes: frozenset[str]
    ) -> _Taint | None:
        inner = self._combine(
            [self._eval(a, tainted) for a in node.args]
            + [self._eval(k.value, tainted) for k in node.keywords]
        )
        if inner is None:
            return None  # sanitizing a clean value yields a clean value
        return _Taint(inner.source, inner.cleared | cwes, inner.dynamic)

    def _dynamic_call(self, node: ast.Call, tainted: dict[str, _Taint]) -> _Taint | None:
        inner = self._combine(
            [self._eval(a, tainted) for a in node.args]
            + [self._eval(k.value, tainted) for k in node.keywords]
        )
        if inner is None:
            return None
        return _Taint(inner.source, inner.cleared, True)  # provenance crossed a dynamic construct

    def _unknown_call(
        self, node: ast.Call, tainted: dict[str, _Taint], receiver: ast.expr | None
    ) -> _Taint | None:
        parts = [self._eval(a, tainted) for a in node.args]
        parts += [self._eval(k.value, tainted) for k in node.keywords]
        if receiver is not None:
            parts.append(self._eval(receiver, tainted))
        combined = self._combine(parts)
        if combined is None:
            return None
        # An unknown transform (incl. an FFI/native call we can't see into) may undo sanitization,
        # so drop the cleared set but keep the taint — the FFI boundary escalates, never clears.
        return _Taint(combined.source, frozenset(), combined.dynamic)

    def _call_summary(
        self,
        resolved: "tuple[_Analyzer, _FuncInfo, int]",
        node: ast.Call,
        tainted: dict[str, _Taint],
    ) -> _Taint | None:
        """Taint of a resolved first-party call's return, via the callee's per-function summary."""
        target, callee, skip = resolved
        return target._return_summary(callee, self._map_args(callee, node, tainted, skip))

    def _map_args(
        self, callee: _FuncInfo, node: ast.Call, tainted: dict[str, _Taint], skip: int = 0
    ) -> dict[str, _Taint]:
        """Map a call's tainted arguments onto the callee's parameter names.

        ``skip`` drops the leading parameters an implicit bound receiver consumes (``self``/``cls``)
        so an instance/classmethod call's positional arguments line up with the real parameters.
        """
        out: dict[str, _Taint] = {}
        positional = callee.positional[skip:]
        for index, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred) or index >= len(positional):
                continue
            taint = self._eval(arg, tainted)
            if taint is not None:
                out[positional[index]] = taint
        for keyword in node.keywords:
            if keyword.arg in callee.params:
                taint = self._eval(keyword.value, tainted)
                if taint is not None:
                    out[keyword.arg] = taint
        return out

    # -- intra-function state (fixpoint) ---------------------------------------------------

    def _body_state(self, func: _FuncInfo, seed: dict[str, _Taint]) -> _BodyState:
        """Compute ``func``'s tainted-slot state and local class environment given seed taints.

        Beyond locals and containers (16.3/20.1), this also tracks **object state** (Task 20.3):
        ``self.x = t`` taints the field slot ``self.x``; ``svc = Service(t)`` binds ``svc``'s class
        (for later method resolution) and seeds ``svc.<field>`` from the constructor's effect on
        ``self``; a method call ``svc.configure(t)`` writes the method's tainted ``self.*`` fields
        back onto ``svc.*``; and ``setattr(obj, n, t)`` escalates ``obj`` to dynamic taint (the
        attribute name is unknown). The fixpoint is monotone, so these effects are order-free.
        """
        tainted: dict[str, _Taint] = dict(seed)
        classes: dict[str, set[tuple[_Analyzer, str]]] = {}
        for _ in range(_MAX_ITERS):
            changed = False
            for stmt in ast.walk(func.scope):
                if isinstance(stmt, ast.Assign):
                    value = self._eval(stmt.value, tainted)
                    changed |= self._bind_construction(stmt, tainted, classes)
                    for target in stmt.targets:
                        for name in _target_names(target):
                            changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.AnnAssign | ast.AugAssign):
                    if stmt.value is None:
                        continue  # bare annotation ``x: int`` — no value to propagate
                    value = self._eval(stmt.value, tainted)
                    for name in _target_names(stmt.target):
                        changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.NamedExpr) and isinstance(stmt.target, ast.Name):
                    changed |= self._add(tainted, stmt.target.id, self._eval(stmt.value, tainted))
                elif isinstance(stmt, ast.For | ast.AsyncFor):
                    value = self._eval(stmt.iter, tainted)
                    for name in _target_names(stmt.target):
                        changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.withitem) and stmt.optional_vars is not None:
                    value = self._eval(stmt.context_expr, tainted)
                    for name in _target_names(stmt.optional_vars):
                        changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
                    # Bind each comprehension loop variable to its iterable's taint, so a sink that
                    # consumes the element (``[os.system(x) for x in tainted]``) is seen. Names leak
                    # into the shared state -> at worst an over-taint, never a downgrade.
                    for gen in stmt.generators:
                        value = self._eval(gen.iter, tainted)
                        for name in _target_names(gen.target):
                            changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.Call):
                    setattr_eff = self._setattr_effect(stmt, tainted)
                    if setattr_eff is not None:
                        changed |= self._add(tainted, setattr_eff[0], setattr_eff[1])
                    target_name, value = self._mutation_effect(stmt, tainted)
                    if target_name is not None:
                        changed |= self._add(tainted, target_name, value)
                    for slot, taint in self._method_writeback(stmt, tainted, classes).items():
                        changed |= self._add(tainted, slot, taint)
            if not changed:
                break
        return _BodyState(tainted, classes)

    def _bind_construction(
        self,
        stmt: ast.Assign,
        tainted: dict[str, _Taint],
        classes: dict[str, set[tuple["_Analyzer", str]]],
    ) -> bool:
        """For ``name = Cls(args)``: record ``name``'s class and seed its tainted fields.

        Returns whether anything changed. The whole-instance taint from the generic assignment is
        still applied by the caller (a conservative backstop for direct uses of ``name``); this adds
        the *field-precise* slots (``name.<field>``) used to seed methods called on the instance.
        """
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            return False
        if not isinstance(stmt.value, ast.Call):
            return False
        cls = self._resolve_class_from_callee(stmt.value.func)
        if cls is None:
            return False
        name = stmt.targets[0].id
        changed = False
        if cls not in classes.get(name, set()):
            classes.setdefault(name, set()).add(cls)
            changed = True
        for attr, taint in self._construct_attrs(stmt.value, cls, tainted).items():
            changed |= self._add(tainted, f"{name}.{attr}", taint)
        return changed

    def _mutation_effect(
        self, call: ast.Call, tainted: dict[str, _Taint]
    ) -> tuple[str | None, _Taint | None]:
        """Taint carried into a container by an in-place mutator (``c.append(t)`` -> taint ``c``).

        Returns ``(receiver_slot, taint)`` when ``call`` is a recognized mutation method on a local
        or field container and an argument carries taint, else ``(None, None)``. The receiver is the
        base slot of the (possibly subscripted) chain — a local (``c``) or a field (``self.items``).
        """
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr not in _MUTATION_METHODS:
            return None, None
        bases = _base_name_ids(func.value)
        if not bases:
            return None, None
        parts = [self._eval(a, tainted) for a in call.args]
        parts += [self._eval(k.value, tainted) for k in call.keywords]
        return bases[0], self._combine(parts)

    def _setattr_effect(
        self, call: ast.Call, tainted: dict[str, _Taint]
    ) -> tuple[str, _Taint] | None:
        """``setattr(obj, name, t)`` with a tainted value -> taint ``obj`` wholly and dynamically.

        The attribute name is computed, so we cannot pin which field is tainted; the sound move is
        to taint the whole object and flag it dynamic, so a later read of any of its attributes is
        not ruled out but is tiered ``DYNAMIC_UNKNOWN`` rather than ``CONFIRMED_FLOW``.
        """
        func = call.func
        if not (isinstance(func, ast.Name) and func.id == "setattr") or len(call.args) < 3:
            return None
        value = self._eval(call.args[2], tainted)
        if value is None:
            return None
        base = _attr_path(call.args[0])
        if base is None:
            return None
        return base, _Taint(value.source, frozenset(), True)

    # -- object / class-state taint (Task 20.3) --------------------------------------------

    @staticmethod
    def _collect_self_attrs(taint: dict[str, _Taint]) -> dict[str, _Taint]:
        """Extract the direct ``self.<attr>`` field taints from a body's tainted-slot state."""
        prefix = "self."
        return {
            key[len(prefix) :]: value
            for key, value in taint.items()
            if key.startswith(prefix) and key.count(".") == 1
        }

    def _self_attr_summary(self, func: _FuncInfo, seed: dict[str, _Taint]) -> dict[str, _Taint]:
        """Which ``self.*`` fields ``func`` taints given tainted params/incoming fields (memoized).

        Reused by constructor seeding and method write-back so a class's field-flow summary is
        computed once per tainted-input shape and shared across every caller.
        """
        key = (self.module_fqn, func.qualname, frozenset(seed))
        if key in self.project._attr_active:
            return {}  # recursion: terminate conservatively
        if key in self.project._attr_memo:
            return self.project._attr_memo[key]
        self.project._attr_active.add(key)
        attrs = self._collect_self_attrs(self._body_state(func, seed).taint)
        self.project._attr_active.discard(key)
        self.project._attr_memo[key] = attrs
        return attrs

    def _construct_attrs(
        self, call: ast.Call, cls: "tuple[_Analyzer, str]", tainted: dict[str, _Taint]
    ) -> dict[str, _Taint]:
        """The instance fields tainted by constructing ``cls`` with ``call``'s arguments.

        An explicit ``__init__`` is analyzed via its ``self.*`` summary (mapping the call arguments,
        skipping ``self``); a dataclass with no ``__init__`` maps the call arguments onto its
        declared fields in order. An unanalyzable constructor simply yields no precise fields — the
        whole-instance backstop still keeps direct uses sound.
        """
        owner, class_name = cls
        init = owner.methods.get((class_name, "__init__"))
        if init is not None:
            return owner._self_attr_summary(init, self._map_args(init, call, tainted, 1))
        if class_name in owner.is_dataclass:
            fields = owner.dataclass_fields.get(class_name, [])
            out: dict[str, _Taint] = {}
            for index, arg in enumerate(call.args):
                if isinstance(arg, ast.Starred) or index >= len(fields):
                    continue
                taint = self._eval(arg, tainted)
                if taint is not None:
                    out[fields[index]] = taint
            for keyword in call.keywords:
                if keyword.arg in fields:
                    taint = self._eval(keyword.value, tainted)
                    if taint is not None:
                        out[keyword.arg] = taint
            return out
        return {}

    def _method_writeback(
        self,
        call: ast.Call,
        tainted: dict[str, _Taint],
        classes: dict[str, set[tuple["_Analyzer", str]]],
    ) -> dict[str, _Taint]:
        """Fields a method call writes onto its tracked receiver (``svc.configure(t)`` -> svc.data).

        Resolves ``recv.method(...)`` against ``recv``'s tracked class(es), runs the method's
        ``self.*`` summary with the mapped arguments **plus** the receiver's currently-tainted
        fields (so chained setters compose), and returns ``{recv.field: taint}``. Empty when the
        receiver is not a tracked instance variable or the method is not an instance method.
        """
        func = call.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return {}
        recv = func.value.id
        candidates = classes.get(recv)
        if not candidates:
            return {}
        prefix = recv + "."
        incoming = {
            key[len(prefix) :]: value
            for key, value in tainted.items()
            if key.startswith(prefix) and key.count(".") == 1
        }
        out: dict[str, _Taint] = {}
        for owner, class_name in sorted(candidates, key=lambda c: c[1]):
            bound = self._lookup_method((owner, class_name), func.attr)
            if bound is None or bound[2] != "instance":
                continue
            method_owner, method, _ = bound
            seed = self._map_args(method, call, tainted, 1)
            for attr, taint in incoming.items():
                seed[f"self.{attr}"] = taint
            for attr, taint in method_owner._self_attr_summary(method, seed).items():
                slot = f"{recv}.{attr}"
                merged = _merge_taint(out.get(slot), taint)
                if merged is not None:
                    out[slot] = merged
        return out

    def _resolve_method_on_instance(
        self, node: ast.Call, body: _BodyState
    ) -> "tuple[_Analyzer, _FuncInfo, int] | None":
        """Resolve ``recv.method(...)`` where ``recv`` is a variable bound to a first-party class.

        Complements :meth:`_resolve_call_target` (which handles inline ``Cls().method`` and
        ``Cls.static``) by using the local class environment to resolve method calls on a tracked
        instance variable — the ``inst = Cls(); inst.m()`` shape deferred from Task 20.2.
        """
        func = node.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return None
        candidates = body.classes.get(func.value.id)
        if not candidates:
            return None
        for owner, class_name in sorted(candidates, key=lambda c: c[1]):
            bound = self._lookup_method((owner, class_name), func.attr)
            if bound is not None:
                method_owner, method, kind = bound
                return method_owner, method, 0 if kind == "static" else 1
        return None

    def _receiver_self_attrs(self, recv: ast.expr, body: _BodyState) -> dict[str, _Taint]:
        """The tainted ``self.*`` fields to seed when entering a method called on ``recv``.

        For an instance variable (``svc.run()``) these are the fields tracked on ``svc``; for an
        inline construction (``Cls(t).run()``) they are the constructor's field effects. ``self`` as
        the receiver (a method calling ``self.other()``) carries the current ``self.*`` fields on.
        """
        if isinstance(recv, ast.Name):
            prefix = recv.id + "."
            return {
                key[len(prefix) :]: value
                for key, value in body.taint.items()
                if key.startswith(prefix) and key.count(".") == 1
            }
        if isinstance(recv, ast.Call):
            cls = self._resolve_class_from_callee(recv.func)
            if cls is not None:
                return self._construct_attrs(recv, cls, body.taint)
        return {}

    def _add(self, tainted: dict[str, _Taint], name: str, value: _Taint | None) -> bool:
        """Merge ``value`` into ``tainted[name]`` (taint only grows); return whether it changed."""
        if value is None:
            return False
        merged = _merge_taint(tainted.get(name), value)
        if merged is not None and tainted.get(name) != merged:
            tainted[name] = merged
            return True
        return False

    def _return_summary(self, func: _FuncInfo, seed: dict[str, _Taint]) -> _Taint | None:
        """Whether ``func`` returns a tainted value given tainted parameters ``seed`` (memoized).

        The memo is project-wide (keyed by module + qualname + tainted-parameter set) so a
        function's summary is computed once and reused by every caller across the import graph.
        """
        key = (self.module_fqn, func.qualname, frozenset(seed))
        if key in self.project._return_active:
            return None  # recursion: terminate conservatively (a rare recursive-return miss)
        if key in self.project._return_memo:
            return self.project._return_memo[key]
        self.project._return_active.add(key)
        tainted = self._body_state(func, seed).taint
        returns: list[_Taint | None] = [
            self._eval(node.value, tainted)
            for node in ast.walk(func.scope)
            if isinstance(node, ast.Return) and node.value is not None
        ]
        summary = self._combine(returns)
        self.project._return_active.discard(key)
        self.project._return_memo[key] = summary
        return summary

    # -- sink discovery / emission ---------------------------------------------------------

    def _emit_walk(self, func: _FuncInfo, seed: dict[str, _Taint], stack: list[CallStep]) -> None:
        """Find sinks reachable in ``func`` under ``seed``; recurse into tainted helper calls.

        Recursion crosses module boundaries: a tainted argument flowing into an imported first-party
        callable (function or method) is followed into its owner module, so a sink in module B
        reached from a source in module A is escalated with the full cross-module call path.
        """
        key = (self.module_fqn, func.qualname, frozenset(seed))
        if key in self.project._emit_visited:
            return
        self.project._emit_visited.add(key)
        body = self._body_state(func, seed)
        tainted = body.taint
        for node in ast.walk(func.scope):
            if not isinstance(node, ast.Call):
                continue
            self._check_sink(node, tainted, stack)
            resolved = self._resolve_call_target(node)
            if resolved is None:  # ``inst.m()`` on a tracked instance variable (Task 20.3)
                resolved = self._resolve_method_on_instance(node, body)
            if resolved is None:
                continue
            target, callee_func, skip = resolved
            child_seed = self._map_args(callee_func, node, tainted, skip)
            # Seed the callee's ``self.*`` from the receiver instance's tracked fields, so a sink
            # reading ``self.cmd`` in the method sees taint set in the constructor/another method.
            if isinstance(node.func, ast.Attribute) and callee_func.method_kind == "instance":
                for attr, taint in self._receiver_self_attrs(node.func.value, body).items():
                    child_seed.setdefault(f"self.{attr}", taint)
            if child_seed:  # demand-driven: only follow a call carrying taint
                step = CallStep(
                    qualname=callee_func.qualname,
                    file=callee_func.file,
                    line=callee_func.lineno,
                )
                target._emit_walk(callee_func, child_seed, [*stack, step])

    def _check_sink(
        self, call: ast.Call, tainted: dict[str, _Taint], stack: list[CallStep]
    ) -> None:
        """Emit a CONFIRMED_FLOW / DYNAMIC_UNKNOWN finding if a tainted value reaches this sink."""
        matched = sinks._match_rule(call, self.bindings)
        if matched is None:
            return
        rule, callee = matched
        if rule.guard is not None and not sinks._guard_satisfied(call, rule.guard):
            return  # the safe form (e.g. subprocess without shell=True)
        if sinks._has_safe_arg(call, rule.safe_args):
            return  # e.g. yaml.load(x, Loader=SafeLoader) -> not dangerous
        selected = sinks._selected_args(call, rule)
        if not selected:
            return

        confirmed: _Taint | None = None
        dynamic: _Taint | None = None
        for arg in selected:
            taint = self._eval(arg, tainted)
            if taint is None or rule.cwe in taint.cleared:
                continue  # clean or sanitized for this CWE on every path
            if taint.dynamic:
                dynamic = dynamic or taint
            else:
                confirmed = confirmed or taint

        if confirmed is not None:
            tier = SastTier.CONFIRMED_FLOW
            source = confirmed.source
            reason = (
                f"a tainted value from {source.kind} reaches this sink "
                "with no sanitizer on the path"
            )
        elif dynamic is not None:
            tier = SastTier.DYNAMIC_UNKNOWN
            source = dynamic.source
            reason = (
                f"a tainted value from {source.kind} reaches this sink via a dynamic construct; "
                "certainty is blocked, so this is not ruled out"
            )
        else:
            return  # all dangerous arguments are clean or sanitized -> no escalation

        sink_step = CallStep(qualname=callee, file=self.rel, line=call.lineno)
        flow = CallPath(steps=(*stack, sink_step))
        self.project.findings.append(
            SastFinding(
                cwe=rule.cwe,
                kind=rule.kind,
                title=rule.title,
                file=self.rel,
                line=call.lineno,
                col=call.col_offset,
                callee=callee,
                tier=tier,
                reason=reason,
                source_kind=source.kind,
                flow=flow,
            )
        )

    # -- roots -----------------------------------------------------------------------------

    def seed_roots(self) -> None:
        """Seed every root (entry points with tainted params; all functions for inline sources)."""
        for func in sorted(self.all_funcs, key=lambda f: f.qualname):
            framework = self._entry_framework_for(func)
            seed: dict[str, _Taint] = {}
            if framework is not None:
                kind = _FRAMEWORK_SOURCE_KIND.get(framework, _DEFAULT_ENTRY_SOURCE_KIND)
                source = _Source(kind, self.rel, func.lineno)
                seed = {
                    name: _Taint(source, frozenset(), False)
                    for name in func.params
                    if name not in ("self", "cls")
                }
            step = CallStep(qualname=func.qualname, file=func.file, line=func.lineno)
            self._emit_walk(func, seed, [step])

    def _entry_framework_for(self, func: _FuncInfo) -> str | None:
        """The framework that makes ``func`` an entry point (params are sources), or ``None``."""
        if func.qualname in self.entry_framework:
            return self.entry_framework[func.qualname]
        if func.class_name is not None and func.class_name in self.entry_framework:
            return self.entry_framework[func.class_name]
        return None


def _fqn_source_kind(fqn: str | None) -> str | None:
    if fqn in _ENV_FQNS:
        return "environment"
    if fqn in _ARGV_FQNS:
        return "argv"
    if fqn in _STDIN_FQNS:
        return "stdin"
    return None


def _entry_maps(tree: ast.Module, rel: str, plugins: Sequence[FrameworkPlugin]) -> dict[str, str]:
    """Run the plugins on this module, returning an entry-point ``name -> framework`` map.

    A plugin's entry-point ``name`` is a function name (route handler / task / signal receiver) or —
    for Django class-based views — a class name; the analyzer matches a function's qualname or its
    enclosing class against this map. Plugins are defensive: one raising never breaks the scan (a
    missed entry point is a false negative, so over-collecting is the safe direction).
    """
    out: dict[str, str] = {}
    for plugin in plugins:
        try:
            entry_points = plugin.entry_points(tree, rel)
        except (ValueError, AttributeError, TypeError):
            continue
        for entry in entry_points:
            out.setdefault(entry.name, entry.framework)
    return out


def analyze_source(
    source: str,
    rel: str,
    *,
    plugins: Sequence[FrameworkPlugin] = DEFAULT_PLUGINS,
    extra_entries: dict[str, str] | None = None,
) -> tuple[SastFinding, ...]:
    """Find source->sink flow escalations in one source string (pure, no I/O).

    Returns only the findings the taint engine can *escalate* — ``CONFIRMED_FLOW`` or
    ``DYNAMIC_UNKNOWN`` with an evidence path. Intra-procedural ``POSSIBLE_FLOW`` / ``SANITIZED``
    classifications come from :func:`vulnadvisor.sast.find_sinks` and are merged in by
    :func:`analyze_taint`. Entry points are detected in this file; ``extra_entries`` supplies
    project-wide registrations (e.g. a Django view declared here but routed in a sibling
    ``urls.py``) so cross-file entry points still seed taint. This is a single-module analysis;
    cross-module flow requires :func:`analyze_taint` over the whole project. Malformed -> ``()``.
    """
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError):
        return ()
    entries = _entry_maps(tree, rel, plugins)
    for name, framework in (extra_entries or {}).items():
        entries.setdefault(name, framework)
    project = _Project()
    project.add(rel, tree, entries)
    return project.run()


@dataclass
class _ParsedModule:
    rel: str
    tree: ast.Module = field(repr=False)


def _parse_project(root: Path) -> list[_ParsedModule]:
    """Parse every first-party ``.py`` under ``root`` (skip unreadable/unparsable files)."""
    modules: list[_ParsedModule] = []
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError):
            continue
        modules.append(_ParsedModule(rel, tree))
    return modules


def analyze_taint(
    project_dir: Path,
    *,
    plugins: Sequence[FrameworkPlugin] = DEFAULT_PLUGINS,
) -> tuple[SastFinding, ...]:
    """Analyze a project: intra-procedural sinks (16.2) escalated by proven taint flow (16.3/20.2).

    Every sink found by :func:`vulnadvisor.sast.find_sinks` is reported; the taint engine raises a
    sink's tier to ``CONFIRMED_FLOW`` (with a source->sink :class:`CallPath`) or ``DYNAMIC_UNKNOWN``
    when it can tie the sink to a recognized source — **across module boundaries**, so a source in
    one file reaching a sink in another via an imported callable still escalates. A sink with no
    proven source keeps its intra-procedural tier. Output is deterministically ordered. Files are
    read defensively: a file that cannot be read or parsed is skipped, never raised.
    """
    root = Path(project_dir)
    baseline = find_sinks(root)
    modules = _parse_project(root)

    # Entry points are collected project-wide (a view defined in one file, routed in another) and
    # shared across every module's analyzer, exactly as the SCA call-path search roots cross-file.
    entries: dict[str, str] = {}
    for module in modules:
        for name, framework in _entry_maps(module.tree, module.rel, plugins).items():
            entries.setdefault(name, framework)

    project = _Project()
    for module in modules:
        project.add(module.rel, module.tree, entries)

    escalations: dict[tuple[str, int, int, str], SastFinding] = {}
    for finding in project.run():
        key = (finding.file, finding.line, finding.col, finding.kind)
        current = escalations.get(key)
        if current is None or tier_concern(finding.tier) > tier_concern(current.tier):
            escalations[key] = finding

    out: list[SastFinding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for hit in baseline:
        key = (hit.file, hit.line, hit.col, hit.kind)
        seen.add(key)
        escalation = escalations.get(key)
        if escalation is not None and tier_concern(escalation.tier) > tier_concern(hit.tier):
            out.append(escalation)
        else:
            out.append(SastFinding.from_sink_hit(hit))
    for key, escalation in escalations.items():
        if key not in seen:  # defensive: never drop a discovered flow
            out.append(escalation)

    out.sort(key=lambda f: (f.file, f.line, f.col, f.cwe, f.kind))
    return tuple(out)
