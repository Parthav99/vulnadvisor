# File: src/vulnadvisor/llm/fix.py
"""Generate and validate a patch for a first-party (SAST) finding (Task 17.1).

``vulnadvisor fix`` proves a fix rather than trusting one. This module owns the *pure* half of that
work — resolving a finding by id, gathering the minimal code context (only the flow's functions),
building the prompt, defensively parsing the model's structured output, and driving the retry loop —
while the *impure* validation (apply the patch to a throwaway copy, lint, type-check, test, re-scan)
is injected as a callable so the loop is unit-testable with no subprocess or filesystem.

Soundness (CLAUDE.md): the model only proposes; the deterministic validator decides. A patch is
returned only when it passed every check, so an unvalidated patch is never emitted. The single
network call is the model request via the injected :class:`~vulnadvisor.llm.client.LLMClient`
(the user's own key) — every validation step is local.
"""

import ast
import json
from collections.abc import Callable, Sequence

from vulnadvisor.llm.client import LLMClient, LLMError
from vulnadvisor.model.fix import (
    FixAttempt,
    FixConfidence,
    FixOutcome,
    FixResult,
    FixSuggestion,
    ValidationReport,
)
from vulnadvisor.sast.model import SastFinding, SastTier, ScoredSastFinding
from vulnadvisor.sast.remediation import remediation_direction

__all__ = [
    "AmbiguousFindingError",
    "FindingNotFoundError",
    "FixError",
    "Validator",
    "build_fix_messages",
    "extract_code_context",
    "generate_fix",
    "is_alarming",
    "parse_fix_suggestion",
    "resolve_sast_finding",
    "sast_finding_id",
    "sast_signature",
]

# A validator proves a candidate patch; it is injected so the loop runs offline in tests.
Validator = Callable[[FixSuggestion], ValidationReport]

_MAX_DIFF_CHARS = 20_000
_MAX_RATIONALE_CHARS = 600


class FixError(Exception):
    """Base class for expected, user-facing fix failures (resolution, missing key, ...)."""


class FindingNotFoundError(FixError):
    """No first-party finding matches the supplied identifier."""


class AmbiguousFindingError(FixError):
    """The identifier matched more than one finding; the caller must disambiguate."""


# --- finding identity ---------------------------------------------------------------------------


def sast_signature(scored: ScoredSastFinding) -> tuple[str, str, str]:
    """The stable signature of a SAST finding: ``(file, cwe, kind)``.

    Line/column are deliberately excluded: a patch shifts line numbers, so "is this finding still
    present after the fix?" must be answered by file + vulnerability class, not by exact location.
    """
    finding = scored.finding
    return (finding.file, finding.cwe, finding.kind)


def sast_finding_id(scored: ScoredSastFinding) -> str:
    """The human-facing id for a SAST finding: ``<file>:<line>:<kind>`` (matches scan output)."""
    finding = scored.finding
    return f"{finding.file}:{finding.line}:{finding.kind}"


def is_alarming(scored: ScoredSastFinding) -> bool:
    """Whether a finding is anything other than ``SANITIZED`` (i.e. it represents real concern).

    The fix must remove the finding *as a concern*: it is acceptable for a fixed sink to remain in
    the code as a ``SANITIZED`` (deprioritized) finding — that is the goal of, e.g., parameterizing
    a query — but it must no longer be ``CONFIRMED``/``DYNAMIC``/``POSSIBLE``.
    """
    return scored.finding.tier is not SastTier.SANITIZED


def _match_tokens(scored: ScoredSastFinding) -> set[str]:
    """Casefolded identifiers a user may use to reference this finding."""
    finding = scored.finding
    tokens = {
        sast_finding_id(scored),
        f"{finding.file}:{finding.line}",
        finding.file,
        finding.kind,
        finding.cwe,
    }
    return {token.casefold() for token in tokens if token}


def resolve_sast_finding(
    findings: Sequence[ScoredSastFinding], identifier: str
) -> ScoredSastFinding:
    """Resolve ``identifier`` to exactly one SAST finding, or raise a precise error.

    Accepts the full id (``file:line:kind``), ``file:line``, a bare ``file`` / ``kind`` / ``cwe``
    when unambiguous, raising :class:`AmbiguousFindingError` (listing the exact ids) otherwise.
    """
    needle = identifier.strip().casefold()
    matches = [f for f in findings if needle in _match_tokens(f)]
    if not matches:
        raise FindingNotFoundError(
            f"no first-party finding matches '{identifier}'. Use an id from a scan, "
            f"e.g. 'app/views.py:42:command-injection' (or just 'app/views.py:42')."
        )
    if len(matches) > 1:
        ids = ", ".join(sast_finding_id(m) for m in matches)
        raise AmbiguousFindingError(
            f"'{identifier}' matches multiple findings: {ids}. Pass one of these ids."
        )
    return matches[0]


# --- code context -------------------------------------------------------------------------------


def _enclosing_segment(tree: ast.Module, line: int) -> tuple[int, int] | None:
    """Return the 1-based ``(start, end)`` line span of the function enclosing ``line``.

    The span includes any decorators (so framework routes — the taint *source* — are visible). The
    innermost enclosing ``def``/``async def`` wins; ``None`` when ``line`` is at module scope.
    """
    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        end = node.end_lineno
        if end is None:
            continue
        start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
        if start <= line <= end and (best is None or start > best[0]):
            # Prefer the innermost enclosing function (the deepest, i.e. largest start line).
            best = (start, end)
    return best


def _file_context(source: str, lines: Sequence[int]) -> str:
    """Render the functions enclosing ``lines`` from ``source`` (or the whole file if it is short).

    Defensive: an unparseable file degrades to its raw text (capped), never raises.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source[:4000]
    src_lines = source.splitlines()
    spans: list[tuple[int, int]] = []
    for line in lines:
        span = _enclosing_segment(tree, line)
        if span is not None and span not in spans:
            spans.append(span)
    if not spans:
        # Module-scope sink (e.g. a hardcoded secret): show a small window around each line.
        for line in lines:
            spans.append((max(1, line - 3), min(len(src_lines), line + 3)))
    spans.sort()
    chunks = ["\n".join(src_lines[start - 1 : end]) for start, end in spans]
    return "\n\n".join(chunks)


def extract_code_context(finding: SastFinding, source_for: Callable[[str], str | None]) -> str:
    """Gather the minimal code context for ``finding``: only the functions on its flow.

    ``source_for`` maps a project-relative file path to its text (or ``None`` if unreadable), so
    this stays pure and testable. The result lists each involved file with the enclosing function(s)
    of the sink and every flow step — never the whole project.
    """
    by_file: dict[str, list[int]] = {finding.file: [finding.line]}
    if finding.flow is not None:
        for step in finding.flow.steps:
            if step.file and step.line is not None:
                by_file.setdefault(step.file, [])
                if step.line not in by_file[step.file]:
                    by_file[step.file].append(step.line)

    blocks: list[str] = []
    for path in sorted(by_file):
        text = source_for(path)
        if text is None:
            blocks.append(f"# File: {path}\n# (could not read this file)")
            continue
        blocks.append(f"# File: {path}\n{_file_context(text, sorted(by_file[path]))}")
    return "\n\n".join(blocks)


# --- prompt -------------------------------------------------------------------------------------

FIX_SYSTEM_PROMPT = (
    "You are a senior application-security engineer fixing a vulnerability in a developer's own "
    "Python code. You are given a finding from a deterministic taint engine, the source->sink "
    "flow, and the exact functions involved. Produce the SMALLEST patch that removes the "
    "vulnerability without changing the code's intended behavior.\n\n"
    "Rules:\n"
    "- Respond with STRICT JSON and nothing else: "
    '{"diff": "<unified diff>", "rationale": "<2-4 sentences>", '
    '"confidence": "high|medium|low"}.\n'
    "- The diff MUST be a valid unified diff with `--- a/<path>` and `+++ b/<path>` headers using "
    "the project-relative paths shown, applied with `git apply -p1`. Use real `@@` hunks with "
    "surrounding context lines.\n"
    "- Fix the root cause: apply the recognized sanitizer / safe API for this CWE (e.g. "
    "parameterized SQL, an argument list instead of shell=True, yaml.safe_load, an allow-list). "
    "Do NOT merely delete the sink or the feature.\n"
    "- Add any imports your fix needs. Keep changes confined to the shown functions.\n"
    "- No markdown, no code fences, no prose outside the JSON."
)


def build_fix_messages(
    finding: SastFinding, code_context: str, feedback: str | None = None
) -> tuple[str, str]:
    """Return the ``(system, user)`` prompt pair for fixing ``finding``.

    When ``feedback`` is given (a previous attempt's validation failure), it is appended so the
    model can correct course on the next iteration.
    """
    flow = finding.flow.render() if finding.flow is not None else f"{finding.file}:{finding.line}"
    lines = [
        "Fix this finding. Facts from the engine (do not contradict them):",
        "",
        f"CWE: {finding.cwe} ({finding.kind}) - {finding.title}",
        f"Confidence tier: {finding.tier.value}",
        f"Sink: {finding.callee} at {finding.file}:{finding.line}",
        f"Source->sink flow: {flow}",
        f"Recommended direction: {remediation_direction(finding.cwe)}",
        "",
        "Relevant code (the flow's functions only):",
        "```python",
        code_context,
        "```",
    ]
    if feedback:
        lines += [
            "",
            "Your previous patch did NOT pass validation: " + feedback,
            "Produce a corrected patch that addresses this.",
        ]
    lines += [
        "",
        'Return only: {"diff": "...", "rationale": "...", "confidence": "..."}',
    ]
    return FIX_SYSTEM_PROMPT, "\n".join(lines)


# --- response parsing ---------------------------------------------------------------------------


def parse_fix_suggestion(raw: str) -> FixSuggestion | None:
    """Strictly validate the model's text into a :class:`FixSuggestion`, else ``None``.

    Defensive per CLAUDE.md: tolerates code fences / surrounding prose, requires a non-empty diff
    and rationale, and coerces an unknown/absent confidence to ``MEDIUM`` rather than rejecting.
    """
    obj = _extract_json_object(raw)
    if obj is None:
        return None
    diff = obj.get("diff")
    rationale = obj.get("rationale")
    if not isinstance(diff, str) or not isinstance(rationale, str):
        return None
    diff = diff.strip("\n")
    rationale = rationale.strip()
    if not diff.strip() or not rationale:
        return None
    if not diff.endswith("\n"):
        diff += "\n"  # git apply needs a trailing newline on the final hunk line
    return FixSuggestion(
        diff=diff[:_MAX_DIFF_CHARS],
        rationale=rationale[:_MAX_RATIONALE_CHARS],
        confidence=_coerce_confidence(obj.get("confidence")),
    )


def _coerce_confidence(value: object) -> FixConfidence:
    """Map an arbitrary confidence value to the enum, defaulting to ``MEDIUM``."""
    if isinstance(value, str):
        try:
            return FixConfidence(value.strip().lower())
        except ValueError:
            return FixConfidence.MEDIUM
    return FixConfidence.MEDIUM


def _extract_json_object(text: str) -> dict[str, object] | None:
    """Parse a JSON object from model text, tolerating code fences or surrounding prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1] if cleaned.count("```") >= 2 else cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    for candidate in (cleaned, _braced_span(cleaned)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _braced_span(text: str) -> str | None:
    """Return the substring from the first ``{`` to the last ``}``, if both are present."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


# --- the retry loop -----------------------------------------------------------------------------


def generate_fix(
    *,
    finding: SastFinding,
    code_context: str,
    client: LLMClient,
    validate: Validator,
    max_attempts: int = 3,
) -> FixResult:
    """Drive the propose->validate->retry loop and return the validated patch, or "no safe fix".

    Each iteration asks ``client`` for a patch, parses it, and runs the injected ``validate``. On
    success the validated :class:`FixSuggestion` is returned immediately. On failure the validation
    feedback is fed into the next prompt. After ``max_attempts`` without a passing patch the outcome
    is :attr:`~vulnadvisor.model.fix.FixOutcome.NO_SAFE_FIX` and ``suggestion`` is ``None`` — an
    unvalidated patch is never returned.
    """
    attempts: list[FixAttempt] = []
    feedback: str | None = None
    for _ in range(max(1, max_attempts)):
        system, user = build_fix_messages(finding, code_context, feedback)
        try:
            raw = client.complete(system=system, user=user)
        except LLMError as exc:
            attempts.append(FixAttempt(note=f"model call failed: {exc}"))
            feedback = "the previous request errored; return a complete, valid JSON patch"
            continue

        suggestion = parse_fix_suggestion(raw)
        if suggestion is None:
            attempts.append(FixAttempt(note="response was not a valid fix JSON object"))
            feedback = (
                "your previous response was not valid JSON with non-empty 'diff' and "
                "'rationale' fields; return strict JSON only"
            )
            continue

        report = validate(suggestion)
        attempts.append(FixAttempt(suggestion=suggestion, report=report))
        if report.ok:
            return FixResult(
                outcome=FixOutcome.VALIDATED, suggestion=suggestion, attempts=tuple(attempts)
            )
        feedback = report.failure_feedback()

    return FixResult(outcome=FixOutcome.NO_SAFE_FIX, suggestion=None, attempts=tuple(attempts))
