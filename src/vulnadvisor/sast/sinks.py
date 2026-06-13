"""Locate and classify sink calls intra-procedurally (docs/sast-design.md §3, Task 16.2).

A pure AST pass over one file: resolve each call's callee through its imports (so ``import yaml as
y`` and ``from os import system`` match the same rule as ``os.system``), match it against the rule
pack, and assign a *local* taint guess — ``SANITIZED`` when the dangerous argument is a literal
constant or a recognized-sanitizer call, ``POSSIBLE_FLOW`` when it is non-literal (pending the
source->sink proof in Task 16.3). Hardcoded secrets (CWE-798) are matched as literal patterns and
reported ``CONFIRMED_FLOW`` (the literal is the vulnerability).

Soundness direction (per CLAUDE.md): every fallback is *toward* a hit. Unresolvable receivers,
``*args`` splats, non-literal guard values, and unparseable arguments classify conservatively
(``POSSIBLE_FLOW``), never clear a real sink. The pass never raises on malformed code: a file that
will not parse is skipped, a single odd node is handled by falling through to the cautious branch.
No I/O beyond reading the project's files; the per-source function is pure.
"""

import ast
import re
from pathlib import Path

from vulnadvisor.callgraph.import_graph import _iter_python_files
from vulnadvisor.sast import rules
from vulnadvisor.sast.model import SastTier, SinkHit

__all__ = ["find_sinks", "find_sinks_in_source"]

# Compiled once; the rule pack is static.
_SECRET_REGEXES: tuple[tuple[rules.SecretPattern, re.Pattern[str]], ...] = tuple(
    (pattern, re.compile(pattern.regex)) for pattern in rules.SECRET_PATTERNS
)

_POSSIBLE_REASON = (
    "called with a non-literal argument; taint not yet proven (pending flow analysis)"
)


class _Bindings:
    """Per-file import bindings used to resolve a call's callee to a fully-qualified name."""

    def __init__(self, alias_to_module: dict[str, str], from_import: dict[str, str]) -> None:
        self.alias_to_module = alias_to_module  # local name -> dotted module path
        self.from_import = from_import  # local name -> "module.symbol"


def _build_bindings(tree: ast.Module) -> _Bindings:
    """Collect ``import``/``from`` bindings so call targets can be resolved to module FQNs."""
    alias_to_module: dict[str, str] = {}
    from_import: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    alias_to_module[alias.asname] = alias.name  # import a.b as c -> c: a.b
                else:
                    root = alias.name.split(".")[0]
                    alias_to_module[root] = root  # import a.b -> a (accessed as a.b.<...>)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import -> first-party, never a stdlib/third-party sink
                continue
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                from_import[local] = f"{module}.{alias.name}" if module else alias.name
    return _Bindings(alias_to_module, from_import)


def _attr_chain(func: ast.expr) -> tuple[ast.expr, list[str]]:
    """Return ``(root_expr, [attrs from root outward])`` for an attribute chain.

    ``os.path.join`` -> ``(Name('os'), ['path', 'join'])``; a non-attribute node -> ``(node, [])``.
    """
    attrs: list[str] = []
    cur: ast.expr = func
    while isinstance(cur, ast.Attribute):
        attrs.append(cur.attr)
        cur = cur.value
    attrs.reverse()
    return cur, attrs


def _resolve_module_fqn(func: ast.expr, bindings: _Bindings) -> str | None:
    """Resolve an attribute-call target to a module FQN (``os.path.join``), or ``None``."""
    root, attrs = _attr_chain(func)
    if isinstance(root, ast.Name) and attrs and root.id in bindings.alias_to_module:
        return bindings.alias_to_module[root.id] + "." + ".".join(attrs)
    return None


def _match_rule(call: ast.Call, bindings: _Bindings) -> tuple[rules.SinkRule, str] | None:
    """Match a call against the rule pack, returning ``(rule, callee_display)`` or ``None``."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in bindings.from_import:  # from os import system; system(...)
            return _module_rule(bindings.from_import[func.id])
        return _builtin_rule(func.id)  # bare builtin (eval/exec/open), not shadowed by an import
    if isinstance(func, ast.Attribute):
        fqn = _resolve_module_fqn(func, bindings)
        if fqn is not None:
            matched = _module_rule(fqn)
            if matched is not None:
                return matched
        return _method_rule(func.attr)  # unresolved receiver -> method heuristic (cursor.execute)
    return None


def _module_rule(fqn: str) -> tuple[rules.SinkRule, str] | None:
    for rule in rules.RULES:
        if rule.callee_kind is rules.CalleeKind.MODULE and fqn in rule.callees:
            return rule, fqn
    return None


def _builtin_rule(name: str) -> tuple[rules.SinkRule, str] | None:
    for rule in rules.RULES:
        if rule.callee_kind is rules.CalleeKind.BUILTIN and name in rule.callees:
            return rule, name
    return None


def _method_rule(attr: str) -> tuple[rules.SinkRule, str] | None:
    for rule in rules.RULES:
        if rule.callee_kind is rules.CalleeKind.METHOD and attr in rule.callees:
            return rule, attr
    return None


def _ident(node: ast.expr) -> str | None:
    """The trailing identifier of a ``Name`` or ``Attribute`` (for safe-arg matching)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_literal(node: ast.expr) -> bool:
    """Whether ``node`` is a compile-time constant with no external input."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_literal(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_literal(key) and _is_literal(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.JoinedStr):  # f-string: literal only if it has no interpolation
        return all(isinstance(value, ast.Constant) for value in node.values)
    return False


def _is_sanitizer_call(node: ast.expr, sanitizers: frozenset[str], bindings: _Bindings) -> bool:
    """Whether ``node`` is a call to a recognized sanitizer for the sink's CWE."""
    if not sanitizers or not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return bindings.from_import.get(func.id, func.id) in sanitizers or func.id in sanitizers
    if isinstance(func, ast.Attribute):
        fqn = _resolve_module_fqn(func, bindings)
        return (fqn is not None and fqn in sanitizers) or func.attr in sanitizers
    return False


def _guard_satisfied(call: ast.Call, guard: rules.Guard) -> bool:
    """Whether the guard keyword (e.g. ``shell=True``) keeps the call a sink.

    Absent -> safe form (not a sink). A literal matching ``require_value`` -> sink. A literal that
    does not match -> safe. A non-literal value cannot be disproven, so it stays a sink (cautious).
    """
    for keyword in call.keywords:
        if keyword.arg == guard.keyword:
            value = keyword.value
            if isinstance(value, ast.Constant):
                return bool(value.value) is guard.require_value
            return True  # shell=<expr> -> cannot prove it is False; stay cautious
    return False


def _has_safe_arg(call: ast.Call, safe_args: frozenset[str]) -> bool:
    """Whether the call references a safe-path identifier (e.g. ``Loader=SafeLoader``)."""
    if not safe_args:
        return False
    values = list(call.args) + [keyword.value for keyword in call.keywords]
    return any(_ident(value) in safe_args for value in values)


def _selected_args(call: ast.Call, rule: rules.SinkRule) -> list[ast.expr]:
    """The dangerous argument nodes for ``rule`` actually present in ``call``."""
    selected: list[ast.expr] = []
    for index in rule.tainted_positions:
        if index < len(call.args) and not isinstance(call.args[index], ast.Starred):
            selected.append(call.args[index])
    for keyword in call.keywords:
        if keyword.arg in rule.tainted_keywords:
            selected.append(keyword.value)
    return selected


def _classify(
    call: ast.Call, rule: rules.SinkRule, bindings: _Bindings
) -> tuple[SastTier, str] | None:
    """Assign the intra-procedural tier for a matched sink call, or ``None`` if it is not a sink."""
    if rule.guard is not None and not _guard_satisfied(call, rule.guard):
        return None  # the safe form (e.g. subprocess without shell=True)

    has_starred = any(isinstance(arg, ast.Starred) for arg in call.args)
    selected = _selected_args(call, rule)
    if not selected and not has_starred:
        return None  # the dangerous argument is absent (e.g. open() with no path) -> not a sink

    if _has_safe_arg(call, rule.safe_args):
        return SastTier.SANITIZED, "a safe argument (e.g. SafeLoader) is supplied"
    if selected and not has_starred and all(_is_literal(arg) for arg in selected):
        return (
            SastTier.SANITIZED,
            "the dangerous argument is a literal constant (no external input)",
        )
    if any(_is_sanitizer_call(arg, rule.sanitizers, bindings) for arg in selected):
        return SastTier.SANITIZED, "the dangerous argument is wrapped in a recognized sanitizer"
    return SastTier.POSSIBLE_FLOW, _POSSIBLE_REASON


def _call_sinks(tree: ast.Module, rel: str, bindings: _Bindings) -> list[SinkHit]:
    """Every sink-call hit in the tree (calls matched + classified against the rule pack)."""
    hits: list[SinkHit] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        matched = _match_rule(node, bindings)
        if matched is None:
            continue
        rule, callee = matched
        classified = _classify(node, rule, bindings)
        if classified is None:
            continue
        tier, reason = classified
        hits.append(
            SinkHit(
                cwe=rule.cwe,
                kind=rule.kind,
                title=rule.title,
                file=rel,
                line=node.lineno,
                col=node.col_offset,
                callee=callee,
                tier=tier,
                reason=reason,
            )
        )
    return hits


def _secret_value(node: ast.expr) -> str | None:
    """The string value of a constant node, or ``None`` if it is not a string literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _pattern_secret(value: str) -> rules.SecretPattern | None:
    """Return the first secret pattern matching ``value``, if any."""
    for pattern, regex in _SECRET_REGEXES:
        if regex.search(value):
            return pattern
    return None


def _is_placeholder(name: str, value: str) -> bool:
    """Whether a secret-named assignment value is an obvious placeholder, not a real secret."""
    lowered = value.lower()
    return (
        len(value) < rules.SECRET_MIN_VALUE_LEN
        or lowered in rules.SECRET_PLACEHOLDERS
        or lowered == name.lower()
    )


def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    """The simple ``Name`` target ids of an assignment (lowercased keys handled by the caller)."""
    if isinstance(node, ast.AnnAssign):
        return [node.target.id] if isinstance(node.target, ast.Name) else []
    names: list[str] = []
    for target in node.targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
    return names


def _secret_sinks(tree: ast.Module, rel: str) -> list[SinkHit]:
    """Hardcoded-secret hits: strong literal patterns plus secret-named literal assignments."""
    hits: list[SinkHit] = []
    pattern_matched: set[int] = set()  # ids of literal nodes already flagged by a pattern

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        value = _secret_value(node)
        if value is None:
            continue
        pattern = _pattern_secret(value)
        if pattern is not None:
            pattern_matched.add(id(node))
            hits.append(
                SinkHit(
                    cwe="CWE-798",
                    kind=pattern.kind,
                    title=pattern.title,
                    file=rel,
                    line=node.lineno,
                    col=node.col_offset,
                    callee="<string literal>",
                    tier=SastTier.CONFIRMED_FLOW,
                    reason="a string literal matches a known secret pattern",
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        value_node = node.value
        if value_node is None:
            continue
        value = _secret_value(value_node)
        if value is None or id(value_node) in pattern_matched:
            continue
        for name in _assignment_targets(node):
            if name.lower() in rules.SECRET_ASSIGN_NAMES and not _is_placeholder(name, value):
                hits.append(
                    SinkHit(
                        cwe="CWE-798",
                        kind="hardcoded-credential",
                        title="Hardcoded credential",
                        file=rel,
                        line=value_node.lineno,
                        col=value_node.col_offset,
                        callee=name,
                        tier=SastTier.CONFIRMED_FLOW,
                        reason=f"a literal string is assigned to secret-named variable '{name}'",
                    )
                )
    return hits


def _sort_key(hit: SinkHit) -> tuple[str, int, int, str, str]:
    return (hit.file, hit.line, hit.col, hit.cwe, hit.kind)


def find_sinks_in_source(source: str, rel: str) -> tuple[SinkHit, ...]:
    """Find all sink hits in one source string (pure, no I/O). Malformed source -> ``()``."""
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError):
        return ()
    bindings = _build_bindings(tree)
    hits = _call_sinks(tree, rel, bindings) + _secret_sinks(tree, rel)
    hits.sort(key=_sort_key)
    return tuple(hits)


def find_sinks(project_dir: Path) -> tuple[SinkHit, ...]:
    """Find all sink hits under ``project_dir`` (deterministic order). Files are read defensively.

    A file that cannot be read or parsed is skipped, never raised — the scan must complete over any
    project. Output is ordered by ``(file, line, col, cwe, kind)`` so runs are reproducible.
    """
    root = Path(project_dir)
    hits: list[SinkHit] = []
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits.extend(find_sinks_in_source(source, rel))
    hits.sort(key=_sort_key)
    return tuple(hits)
