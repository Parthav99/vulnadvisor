# File: src/vulnadvisor/sast/taint.py
"""Demand-driven taint propagation: prove a flow from a real source to a sink (Task 16.3).

This is the SAST differentiator. Task 16.2 finds every sink and classifies it *intra-procedurally*
(literal -> ``SANITIZED``, non-literal -> ``POSSIBLE_FLOW``). Task 16.3 takes those as a floor and
**escalates** the ones it can tie to a recognized taint source:

* **Sources** seed taint — framework entry-point parameters (FastAPI/Flask routes, Django views and
  signals, Celery tasks — the breadth expansion this task adds), the Flask ``request`` global, and
  ``stdin`` / ``argv`` / the process environment.
* **Propagation** is conservative and intra-/inter-procedural over the *same per-file call graph the
  SCA reachability engine uses*: assignments, calls passing a tainted value to a first-party helper
  (taint flows to the parameter), returns, f-strings / ``%`` / ``+`` concatenation, and containers.
  When unsure, a value is treated as tainted (over-report, then let the tier speak) — never the
  reverse.
* **Sinks** are the §3 rule pack. A tainted value reaching a sink's dangerous argument with no
  CWE-matching sanitizer on the path -> ``CONFIRMED_FLOW`` with the source->sink :class:`CallPath`
  as evidence. A path crossing a dynamic construct (``eval``/``exec``/``getattr`` dispatch, a
  computed callee) -> ``DYNAMIC_UNKNOWN`` — escalated, never quietly dropped.

Soundness direction is always *toward* a finding (docs/sast-design.md §4): a sink the engine cannot
tie to a source keeps its intra-procedural tier; the taint pass only ever raises concern. The
analysis is flow-insensitive within a function (sanitizer state merges by intersection across
paths, so a *partially* sanitized value stays unsanitized — a real sink is never cleared by one safe
branch). The per-source function is pure; the only I/O is reading the project's files.
"""

import ast
from collections.abc import Sequence
from dataclasses import dataclass
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


def _sanitizer_map() -> dict[str, frozenset[str]]:
    """Build ``sanitizer-name -> {cleared CWEs}`` from the rule pack (a sanitizer is CWE-scoped)."""
    out: dict[str, set[str]] = {}
    for rule in rules.RULES:
        for name in rule.sanitizers:
            out.setdefault(name, set()).add(rule.cwe)
    return {name: frozenset(cwes) for name, cwes in out.items()}


_SANITIZERS: dict[str, frozenset[str]] = _sanitizer_map()


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


def _target_names(target: ast.expr) -> list[str]:
    """The simple ``Name`` ids that receive an assignment's value taint.

    Recurses tuple/list unpacking and ``*starred`` targets. A subscript target ``c[k] = v`` taints
    the *whole container* ``c`` (Task 20.1: index-sensitivity is not tracked, so a tainted element
    conservatively taints the container — a sound over-approximation, never a downgrade). ``x.y =``
    attribute writes are still untracked here (object/field taint is Task 20.3).
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
    return []  # x.y = : attribute/field taint is Task 20.3, not tracked here


def _base_name_ids(node: ast.expr) -> list[str]:
    """The root ``Name`` id of a subscript chain (``c[i][j]`` -> ``['c']``), else ``[]``.

    Used for whole-container taint on subscript writes and in-place mutation: the base local that
    holds the container is the thing taint attaches to. An attribute base (``self.items[i]``) is not
    a local name, so it yields ``[]`` (object/field taint is Task 20.3).
    """
    cur: ast.expr = node
    while isinstance(cur, ast.Subscript):
        cur = cur.value
    return [cur.id] if isinstance(cur, ast.Name) else []


class _Analyzer:
    """Per-file taint analysis: discovers source->sink flows and records escalated findings."""

    def __init__(
        self,
        rel: str,
        tree: ast.Module,
        entry_framework: dict[str, str],
    ) -> None:
        self.rel = rel
        self.bindings = sinks._build_bindings(tree)
        self.flask_names = frozenset(
            local for local, fqn in self.bindings.from_import.items() if fqn == _FLASK_REQUEST_FQN
        )
        # name -> framework, where name is a function name (route/task/receiver/FBV) or, for a
        # class-based view, the class name (Django dispatches its HTTP-verb methods).
        self.entry_framework = entry_framework
        self.callable_funcs: dict[str, _FuncInfo] = {}
        self.all_funcs: list[_FuncInfo] = []
        self.findings: list[SastFinding] = []
        self._return_memo: dict[tuple[str, frozenset[str]], _Taint | None] = {}
        self._return_active: set[tuple[str, frozenset[str]]] = set()
        self._emit_visited: set[tuple[str, frozenset[str]]] = set()
        self._collect_funcs(tree)

    # -- structure -------------------------------------------------------------------------

    def _collect_funcs(self, tree: ast.Module) -> None:
        """Collect top-level functions (call targets + roots) and class methods (roots only)."""
        module_body: list[ast.stmt] = []
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                allp, pos = _param_names(stmt)
                info = _FuncInfo(stmt.name, stmt, self.rel, stmt.lineno, allp, pos)
                self.callable_funcs[stmt.name] = info
                self.all_funcs.append(info)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                        allp, pos = _param_names(item)
                        self.all_funcs.append(
                            _FuncInfo(
                                f"{stmt.name}.{item.name}",
                                item,
                                self.rel,
                                item.lineno,
                                allp,
                                pos,
                                class_name=stmt.name,
                            )
                        )
            else:
                module_body.append(stmt)
        module_scope = ast.Module(body=module_body, type_ignores=[])
        self.all_funcs.append(_FuncInfo(_MODULE_KEY, module_scope, self.rel, 1, [], []))

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
        if isinstance(node, ast.Attribute | ast.Subscript | ast.Starred | ast.Await):
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
            if func.id in self.callable_funcs:
                return self._call_summary(self.callable_funcs[func.id], node, tainted)
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
        # An unknown transform may undo sanitization, so drop the cleared set (sound direction).
        return _Taint(combined.source, frozenset(), combined.dynamic)

    def _call_summary(
        self, callee: _FuncInfo, node: ast.Call, tainted: dict[str, _Taint]
    ) -> _Taint | None:
        return self._return_summary(callee, self._map_args(callee, node, tainted))

    def _map_args(
        self, callee: _FuncInfo, node: ast.Call, tainted: dict[str, _Taint]
    ) -> dict[str, _Taint]:
        """Map a call's tainted arguments onto the callee's parameter names."""
        out: dict[str, _Taint] = {}
        for index, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred) or index >= len(callee.positional):
                continue
            taint = self._eval(arg, tainted)
            if taint is not None:
                out[callee.positional[index]] = taint
        for keyword in node.keywords:
            if keyword.arg in callee.params:
                taint = self._eval(keyword.value, tainted)
                if taint is not None:
                    out[keyword.arg] = taint
        return out

    # -- intra-function state (fixpoint) ---------------------------------------------------

    def _local_state(self, func: _FuncInfo, seed: dict[str, _Taint]) -> dict[str, _Taint]:
        """Compute the tainted-variable state for ``func`` given its tainted parameters ``seed``."""
        tainted: dict[str, _Taint] = dict(seed)
        for _ in range(_MAX_ITERS):
            changed = False
            for stmt in ast.walk(func.scope):
                if isinstance(stmt, ast.Assign):
                    value = self._eval(stmt.value, tainted)
                    for target in stmt.targets:
                        for name in _target_names(target):
                            changed |= self._add(tainted, name, value)
                elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                    value = self._eval(stmt.value, tainted)
                    if isinstance(stmt.target, ast.Name):
                        changed |= self._add(tainted, stmt.target.id, value)
                elif isinstance(stmt, ast.AugAssign):
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
                    target_name, value = self._mutation_effect(stmt, tainted)
                    if target_name is not None:
                        changed |= self._add(tainted, target_name, value)
            if not changed:
                break
        return tainted

    def _mutation_effect(
        self, call: ast.Call, tainted: dict[str, _Taint]
    ) -> tuple[str | None, _Taint | None]:
        """Taint carried into a container by an in-place mutator (``c.append(t)`` -> taint ``c``).

        Returns ``(receiver_name, taint)`` when ``call`` is a recognized mutation method on a local
        container and an argument carries taint, else ``(None, None)``. The receiver is the base
        local of the (possibly subscripted) chain; an attribute receiver is left to Task 20.3.
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
        """Whether ``func`` returns a tainted value given tainted parameters ``seed`` (memoized)."""
        key = (func.qualname, frozenset(seed))
        if key in self._return_active:
            return None  # recursion: terminate conservatively (a rare recursive-return miss)
        if key in self._return_memo:
            return self._return_memo[key]
        self._return_active.add(key)
        tainted = self._local_state(func, seed)
        returns: list[_Taint | None] = [
            self._eval(node.value, tainted)
            for node in ast.walk(func.scope)
            if isinstance(node, ast.Return) and node.value is not None
        ]
        summary = self._combine(returns)
        self._return_active.discard(key)
        self._return_memo[key] = summary
        return summary

    # -- sink discovery / emission ---------------------------------------------------------

    def _emit_walk(self, func: _FuncInfo, seed: dict[str, _Taint], stack: list[CallStep]) -> None:
        """Find sinks reachable in ``func`` under ``seed``; recurse into tainted helper calls."""
        key = (func.qualname, frozenset(seed))
        if key in self._emit_visited:
            return
        self._emit_visited.add(key)
        tainted = self._local_state(func, seed)
        for node in ast.walk(func.scope):
            if not isinstance(node, ast.Call):
                continue
            self._check_sink(node, tainted, stack)
            callee_func = self._callee(node)
            if callee_func is not None:
                child_seed = self._map_args(callee_func, node, tainted)
                if child_seed:  # demand-driven: only follow a call carrying taint
                    step = CallStep(
                        qualname=callee_func.qualname,
                        file=callee_func.file,
                        line=callee_func.lineno,
                    )
                    self._emit_walk(callee_func, child_seed, [*stack, step])

    def _callee(self, node: ast.Call) -> _FuncInfo | None:
        func = node.func
        if isinstance(func, ast.Name):
            return self.callable_funcs.get(func.id)
        return None

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
        self.findings.append(
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

    def run(self) -> tuple[SastFinding, ...]:
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
        return tuple(self.findings)

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
    ``urls.py``) so cross-file entry points still seed taint. Malformed source -> ``()``.
    """
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError):
        return ()
    entries = _entry_maps(tree, rel, plugins)
    for name, framework in (extra_entries or {}).items():
        entries.setdefault(name, framework)
    analyzer = _Analyzer(rel, tree, entries)
    return analyzer.run()


def _project_entry_maps(root: Path, plugins: Sequence[FrameworkPlugin]) -> dict[str, str]:
    """Collect the entry-point ``name -> framework`` map across the project (cross-file rooting).

    Frameworks register handlers in one file and define them in another (Django's ``urls.py`` vs
    ``views.py``). Collecting entry-point *names* project-wide — exactly as the SCA call-path search
    does — lets a view defined here but routed elsewhere still be treated as a taint source.
    """
    out: dict[str, str] = {}
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue
        for name, framework in _entry_maps(tree, rel, plugins).items():
            out.setdefault(name, framework)
    return out


def analyze_taint(
    project_dir: Path,
    *,
    plugins: Sequence[FrameworkPlugin] = DEFAULT_PLUGINS,
) -> tuple[SastFinding, ...]:
    """Analyze a project: intra-procedural sinks (16.2) escalated by proven taint flow (16.3).

    Every sink found by :func:`vulnadvisor.sast.find_sinks` is reported; the taint engine raises a
    sink's tier to ``CONFIRMED_FLOW`` (with a source->sink :class:`CallPath`) or ``DYNAMIC_UNKNOWN``
    when it can tie the sink to a recognized source. A sink with no proven source keeps its
    intra-procedural tier. Output is deterministically ordered. Files are read defensively: a file
    that cannot be read or parsed is skipped, never raised.
    """
    root = Path(project_dir)
    baseline = find_sinks(root)
    entries = _project_entry_maps(root, plugins)

    escalations: dict[tuple[str, int, int, str], SastFinding] = {}
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for finding in analyze_source(source, rel, plugins=plugins, extra_entries=entries):
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
