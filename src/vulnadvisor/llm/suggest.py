# File: src/vulnadvisor/llm/suggest.py
"""Run the validated fix loop over many findings and collect the patches (Task 17.2, CI half).

``vulnadvisor fix --suggest-json`` is the non-interactive sibling of ``vulnadvisor fix``: in CI it
attempts a machine-validated patch for every alarming first-party finding and writes the validated
ones to a JSON document uploaded alongside the scan report. The platform's GitHub App then renders
those patches as in-line ``suggestion`` comments — so the developer's code never leaves CI.

This module owns the *pure* orchestration (which findings to fix, build the per-finding context,
run the loop, keep the validated results) with both the model ``client`` and the per-finding
``validate`` factory injected, so the whole sweep is unit-testable with no subprocess or network.
Soundness (17.1) is inherited unchanged: only a patch that passed the full validator is kept.
"""

from collections.abc import Callable, Sequence

from vulnadvisor.llm.client import LLMClient
from vulnadvisor.llm.fix import (
    Validator,
    extract_code_context,
    generate_fix,
    is_alarming,
    sast_finding_id,
)
from vulnadvisor.model.fix import FixConfidence, FixOutcome
from vulnadvisor.model.suggestion import SuggestionReport, ValidatedFix
from vulnadvisor.sast.model import ScoredSastFinding

__all__ = ["build_validated_fix", "generate_suggestions"]

# A validator factory binds the impure validator to one target finding (17.1 ``build_validator``).
ValidatorFor = Callable[[ScoredSastFinding], Validator]
# Reads a project-relative file's text (or ``None`` if unreadable) — injected to stay pure.
SourceFor = Callable[[str], str | None]


def _flow_text(scored: ScoredSastFinding) -> str:
    """The rendered source->sink path for the PR story, or the bare sink site when there is none."""
    finding = scored.finding
    if finding.flow is not None:
        return finding.flow.render()
    return f"{finding.file}:{finding.line}"


def build_validated_fix(
    scored: ScoredSastFinding, diff: str, rationale: str, confidence: object
) -> ValidatedFix:
    """Assemble the uploadable :class:`ValidatedFix` from a finding and its validated patch."""
    finding = scored.finding
    return ValidatedFix(
        finding_id=sast_finding_id(scored),
        file=finding.file,
        line=finding.line,
        cwe=finding.cwe,
        kind=finding.kind,
        title=finding.title,
        tier=finding.tier.value,
        flow=_flow_text(scored),
        rationale=rationale,
        confidence=confidence if isinstance(confidence, FixConfidence) else FixConfidence.MEDIUM,
        diff=diff,
    )


def generate_suggestions(
    *,
    findings: Sequence[ScoredSastFinding],
    client: LLMClient,
    validator_for: ValidatorFor,
    source_for: SourceFor,
    tool_version: str,
    max_attempts: int = 3,
    on_result: Callable[[ScoredSastFinding, bool], None] | None = None,
) -> SuggestionReport:
    """Attempt a validated fix for every alarming finding; return the validated ones as a report.

    Each alarming finding (``SANITIZED`` findings are skipped — there is nothing to fix) is run
    through the injected ``validate`` from ``validator_for``; only :attr:`FixOutcome.VALIDATED`
    results are kept. ``on_result`` (if given) is called with ``(finding, validated?)`` after each
    attempt, so the CLI can stream progress without this function touching I/O.
    """
    fixes: list[ValidatedFix] = []
    for scored in findings:
        if not is_alarming(scored):
            continue
        context = extract_code_context(scored.finding, source_for)
        result = generate_fix(
            finding=scored.finding,
            code_context=context,
            client=client,
            validate=validator_for(scored),
            max_attempts=max_attempts,
        )
        validated = result.outcome is FixOutcome.VALIDATED and result.suggestion is not None
        if validated and result.suggestion is not None:
            fixes.append(
                build_validated_fix(
                    scored,
                    result.suggestion.diff,
                    result.suggestion.rationale,
                    result.suggestion.confidence,
                )
            )
        if on_result is not None:
            on_result(scored, validated)
    return SuggestionReport(tool_version=tool_version, fixes=tuple(fixes))
