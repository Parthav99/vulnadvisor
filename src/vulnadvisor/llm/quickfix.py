# File: src/vulnadvisor/llm/quickfix.py
"""Deterministic, high-confidence quick-fixes that run before the model (Task 19.3).

For the handful of CWEs that have an *unambiguous* safe rewrite, we don't need a language model to
fix them — an AST-targeted source edit produces the patch directly, offline, with no API key. The
candidate is **not** trusted on sight: it is fed through the very same 17.1 validation loop
(``apply -> ruff -> mypy -> tests -> re-scan clean``) as a model patch, so a rewrite that cannot be
made safely simply fails validation and the loop falls through to the model. That keeps the quality
bar identical — we never emit an unproven patch — while turning the common cases into instant,
zero-cost, validated fixes instead of "no safe fix".

Covered here are the three CWEs the taint engine detects today and that admit a behaviour-
preserving safe API:

* **CWE-502** ``yaml.load`` / ``yaml.unsafe_load`` -> ``yaml.safe_load`` (and the ``_all`` forms).
* **CWE-78**  ``subprocess(..., shell=True)`` -> ``subprocess(shlex.split(...), shell=False)``.
* **CWE-94**  ``eval(expr)`` -> ``ast.literal_eval(expr)``.

Everything here is pure: source text in, candidate :class:`FixSuggestion` objects out, no I/O. A
builder that cannot produce a safe rewrite for the exact call shape returns ``None`` (it declines),
never a best-effort guess. The remaining CWE templates (weak hash, insecure RNG, TLS verification)
land in M23, once the engine detects them.
"""

import ast
import difflib
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from vulnadvisor.model.fix import FixConfidence, FixProvenance, FixSuggestion
from vulnadvisor.sast.model import SastFinding

__all__ = ["QUICK_FIX_CWES", "SourceFor", "quick_fix_candidates"]

# Reads a project-relative file's text (or ``None`` if unreadable) — injected so this stays pure.
SourceFor = Callable[[str], str | None]

# The (cwe, kind) pairs a deterministic quick-fix exists for; used by callers/metrics.
QUICK_FIX_CWES: frozenset[tuple[str, str]] = frozenset(
    {
        ("CWE-502", "unsafe-deserialization"),
        ("CWE-78", "command-injection"),
        ("CWE-94", "code-injection"),
    }
)

_MAX_SOURCE_BYTES = 1_000_000  # never rewrite a pathologically large file in-memory


@dataclass(frozen=True)
class _Edit:
    """A single source-span replacement (line/col are 1-based line, 0-based UTF-8 byte col)."""

    start_line: int
    start_col: int
    end_line: int
    end_col: int
    text: str


# A builder inspects the matched call (with the parsed module, source, and the finding for its
# resolved callee) and returns ``(edits, rationale)`` for a safe rewrite, or ``None`` to decline.
_Builder = Callable[[ast.Call, ast.Module, str, SastFinding], "tuple[list[_Edit], str] | None"]


def quick_fix_candidates(finding: SastFinding, source_for: SourceFor) -> list[FixSuggestion]:
    """Return deterministic patch candidate(s) for ``finding`` (usually 0 or 1), or ``[]``.

    Resolves the sink call in the finding's file, dispatches to the per-CWE builder, and renders the
    resulting edits as a unified diff wrapped in a high-confidence, ``DETERMINISTIC`` provenance
    :class:`FixSuggestion`. The candidate still has to pass the injected validator upstream — this
    function only *proposes*. Fully defensive: an unreadable/oversized/unparseable file, a missing
    call, or a declining builder all yield ``[]``.
    """
    builder = _BUILDERS.get((finding.cwe, finding.kind))
    if builder is None:
        return []
    source = source_for(finding.file)
    if source is None or len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    call = _find_call(tree, finding.line, finding.col)
    if call is None:
        return []
    built = builder(call, tree, source, finding)
    if built is None:
        return []
    edits, rationale = built
    new_source = _apply_edits(source, edits)
    if new_source == source:
        return []
    diff = _unified_diff(finding.file, source, new_source)
    if not diff.strip():
        return []
    return [
        FixSuggestion(
            diff=diff,
            rationale=rationale,
            confidence=FixConfidence.HIGH,
            provenance=FixProvenance.DETERMINISTIC,
        )
    ]


# --- call location --------------------------------------------------------------------------------


def _find_call(tree: ast.Module, line: int, col: int) -> ast.Call | None:
    """Find the sink :class:`ast.Call` at ``(line, col)`` (the position the engine recorded).

    Prefers an exact ``lineno``/``col_offset`` match (sinks record the call node's own position);
    falls back to the only call starting on that line, so a tiny position drift still resolves but
    an ambiguous line (multiple calls) safely declines.
    """
    exact: list[ast.Call] = []
    on_line: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if node.lineno == line and node.col_offset == col:
            exact.append(node)
        elif node.lineno == line:
            on_line.append(node)
    if exact:
        return exact[0]
    if len(on_line) == 1:
        return on_line[0]
    return None


# --- import + edit helpers ------------------------------------------------------------------------


def _line_byte_starts(source: str) -> list[int]:
    """Byte offset at which each (1-based) source line begins, for span math on ``col_offset``."""
    starts: list[int] = []
    acc = 0
    for line in source.splitlines(keepends=True):
        starts.append(acc)
        acc += len(line.encode("utf-8"))
    starts.append(acc)  # sentinel for a trailing position
    return starts


def _apply_edits(source: str, edits: Sequence[_Edit]) -> str:
    """Apply span replacements to ``source``, right-to-left so earlier offsets stay valid.

    ``ast`` column offsets are UTF-8 byte offsets, so the splice is done on the encoded bytes and
    decoded back — correct for non-ASCII source, identical to char offsets for ASCII.
    """
    starts = _line_byte_starts(source)
    data = source.encode("utf-8")
    spans = sorted(
        (
            (starts[e.start_line - 1] + e.start_col, starts[e.end_line - 1] + e.end_col, e.text)
            for e in edits
        ),
        reverse=True,
    )
    for start, end, text in spans:
        data = data[:start] + text.encode("utf-8") + data[end:]
    return data.decode("utf-8")


def _imported_modules(tree: ast.Module) -> set[str]:
    """Top-level module names already imported (so an added ``import`` is never duplicated)."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
                if alias.asname:
                    names.add(alias.asname)
    return names


def _import_edit(tree: ast.Module, module: str) -> _Edit | None:
    """An edit inserting ``import <module>`` after the last top-level import (``None`` if present).

    When the file has no imports, the import is inserted before the first statement (after a module
    docstring), so the result still parses and ruff keeps it tidy.
    """
    if module in _imported_modules(tree):
        return None
    insert_line = 1
    last_import_end = 0
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            last_import_end = max(last_import_end, node.end_lineno or node.lineno)
    if last_import_end:
        insert_line = last_import_end + 1
    else:
        body = tree.body
        first = body[0] if body else None
        if (
            first is not None
            and isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            insert_line = (first.end_lineno or first.lineno) + 1
        elif first is not None:
            insert_line = first.lineno
    return _Edit(insert_line, 0, insert_line, 0, f"import {module}\n")


def _segment(source: str, node: ast.expr) -> str | None:
    """The exact original source text of ``node`` (preserves aliases/formatting), or ``None``."""
    return ast.get_source_segment(source, node)


def _node_span_edit(node: ast.expr, text: str) -> _Edit | None:
    """An :class:`_Edit` replacing ``node``'s source span with ``text`` (needs an end position)."""
    if node.end_lineno is None or node.end_col_offset is None:
        return None
    return _Edit(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset, text)


def _attr_rename_edit(func: ast.Attribute, new_attr: str) -> _Edit | None:
    """An edit renaming just the trailing ``.attr`` of an attribute call target (keeps receiver).

    So ``y.load`` -> ``y.safe_load`` rewrites only ``load``, leaving an ``import yaml as y`` alias
    untouched. Declines if the attribute has no end position to anchor on.
    """
    if func.end_lineno is None or func.end_col_offset is None:
        return None
    start_col = func.end_col_offset - len(func.attr.encode("utf-8"))
    if start_col < 0:
        return None
    return _Edit(func.end_lineno, start_col, func.end_lineno, func.end_col_offset, new_attr)


# --- CWE-502: yaml.load -> yaml.safe_load ---------------------------------------------------------

_YAML_SAFE = {
    "load": "safe_load",
    "load_all": "safe_load_all",
    "unsafe_load": "safe_load",
    "unsafe_load_all": "safe_load_all",
}
# The fully-qualified yaml callees this rewrite is valid for (CWE-502 also covers pickle/marshal,
# which have *no* safe drop-in — so we gate on the engine's resolved callee, not just the attr).
_YAML_CALLEES = frozenset(f"yaml.{attr}" for attr in _YAML_SAFE)


def _build_yaml_safe_load(
    call: ast.Call, tree: ast.Module, source: str, finding: SastFinding
) -> tuple[list[_Edit], str] | None:
    """Rewrite an unsafe ``yaml.load(...)`` call to the safe loader, dropping a ``Loader=`` arg.

    ``yaml.safe_load`` takes only the stream, so any extra positional/keyword (a ``Loader``) is
    dropped — that *is* the safe form. Requires the stream as the sole leading positional argument;
    a shape we cannot map cleanly (no positional stream, ``*args`` splat) declines to the model.
    Gated on the resolved callee so ``pickle.load`` / ``marshal.load`` (same CWE, no safe form)
    correctly fall through to the model rather than being mangled into a nonexistent ``safe_load``.
    """
    func = call.func
    if finding.callee not in _YAML_CALLEES or not isinstance(func, ast.Attribute):
        return None
    if func.attr not in _YAML_SAFE:
        return None
    new_attr = _YAML_SAFE[func.attr]
    has_starred = any(isinstance(arg, ast.Starred) for arg in call.args)
    rationale = (
        f"Replaced the unsafe `yaml.{func.attr}` with `yaml.{new_attr}`, which never constructs "
        "arbitrary Python objects from the input, removing the deserialization sink (CWE-502)."
    )
    # Simple, common shape: a single positional stream and nothing else -> rename the attr only.
    if len(call.args) == 1 and not call.keywords and not has_starred:
        edit = _attr_rename_edit(func, new_attr)
        return ([edit], rationale) if edit is not None else None
    # Otherwise rebuild as `<receiver>.<safe>(<stream>)`, dropping a Loader argument.
    if not call.args or isinstance(call.args[0], ast.Starred):
        return None
    receiver = _segment(source, func.value)
    stream = _segment(source, call.args[0])
    if receiver is None or stream is None:
        return None
    edit = _node_span_edit(call, f"{receiver}.{new_attr}({stream})")
    return ([edit], rationale) if edit is not None else None


# --- CWE-78: subprocess(shell=True) -> shlex.split(...) + shell=False ----------------------------

# The fully-qualified subprocess callees that take a ``shell=`` keyword (so flipping it is valid).
_SHELL_SUBPROCESS = frozenset(
    f"subprocess.{name}" for name in ("run", "call", "check_call", "check_output", "Popen")
)


def _build_subprocess_shell(
    call: ast.Call, tree: ast.Module, source: str, finding: SastFinding
) -> tuple[list[_Edit], str] | None:
    """Rewrite ``subprocess.run(cmd, shell=True)`` to ``run(shlex.split(cmd), shell=False)``.

    Only fires when ``shell`` is a *literal* ``True`` (we never flip a variable we cannot prove) and
    the command is a single string-shaped positional argument (not already an arg list).
    ``shlex.split`` tokenizes without any shell, so metacharacters in the input can no longer inject
    commands; setting ``shell=False`` clears the engine's guard. Adds ``import shlex`` if needed.
    Gated on the resolved callee so the other CWE-78 sinks (``os.system``/``os.popen``, with no
    ``shell=`` to flip) decline here.
    """
    func = call.func
    if finding.callee not in _SHELL_SUBPROCESS or not isinstance(func, ast.Attribute):
        return None
    shell_kw = next((kw for kw in call.keywords if kw.arg == "shell"), None)
    if shell_kw is None or not (
        isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True
    ):
        return None  # shell is absent or non-literal -> cannot safely flip it
    if not call.args or isinstance(call.args[0], ast.Starred):
        return None
    cmd = call.args[0]
    # An argv list/tuple with shell=True is unusual; a shlex.split() of a list fails -> decline.
    if isinstance(cmd, ast.List | ast.Tuple):
        return None
    cmd_src = _segment(source, cmd)
    if cmd_src is None:
        return None
    cmd_edit = _node_span_edit(cmd, f"shlex.split({cmd_src})")
    shell_edit = _node_span_edit(shell_kw.value, "False")
    if cmd_edit is None or shell_edit is None:
        return None
    edits = [cmd_edit, shell_edit]
    import_edit = _import_edit(tree, "shlex")
    if import_edit is not None:
        edits.append(import_edit)
    rationale = (
        "Tokenized the command with `shlex.split(...)` and set `shell=False`, so the argument is "
        "run as an explicit argv list and is never interpreted by a shell, removing the "
        "command-injection sink (CWE-78)."
    )
    return edits, rationale


# --- CWE-94: eval(expr) -> ast.literal_eval(expr) ------------------------------------------------


def _build_eval_literal(
    call: ast.Call, tree: ast.Module, source: str, finding: SastFinding
) -> tuple[list[_Edit], str] | None:
    """Rewrite a bare ``eval(expr)`` to ``ast.literal_eval(expr)``; declines ``exec``/``compile``.

    Only the single-argument builtin ``eval`` form is rewritten (no ``globals``/``locals`` args,
    which ``literal_eval`` does not accept). ``ast.literal_eval`` evaluates only Python literals, so
    it cannot execute arbitrary code — the standard safe replacement (CWE-94). Adds ``import ast``.
    """
    func = call.func
    if finding.callee != "eval" or not isinstance(func, ast.Name) or func.id != "eval":
        return None  # exec/compile have no literal-only equivalent -> leave to the model
    if len(call.args) != 1 or call.keywords or isinstance(call.args[0], ast.Starred):
        return None
    name_edit = _node_span_edit(func, "ast.literal_eval")
    if name_edit is None:
        return None
    edits = [name_edit]
    import_edit = _import_edit(tree, "ast")
    if import_edit is not None:
        edits.append(import_edit)
    rationale = (
        "Replaced `eval` with `ast.literal_eval`, which parses only Python literals and cannot "
        "execute arbitrary code, removing the code-injection sink (CWE-94)."
    )
    return edits, rationale


# --- dispatch -------------------------------------------------------------------------------------

_BUILDERS: dict[tuple[str, str], _Builder] = {
    ("CWE-502", "unsafe-deserialization"): _build_yaml_safe_load,
    ("CWE-78", "command-injection"): _build_subprocess_shell,
    ("CWE-94", "code-injection"): _build_eval_literal,
}


def _unified_diff(path: str, before: str, after: str) -> str:
    """Render a git-appliable (``-p1``) unified diff between two versions of one file."""
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    text = "".join(diff)
    if text and not text.endswith("\n"):
        text += "\n"
    return text
