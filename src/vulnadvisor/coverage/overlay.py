"""Overlay runtime coverage onto a scan, annotating findings with runtime evidence.

This is the Task 16.6 differentiator: marry the static structure (reachability tiers, taint flows)
with dynamic evidence from a real test run. The overlay is **pure** and **sound by construction**:

* It only ever *sets* a finding's ``runtime`` annotation; it never touches ``tier``, ``score``, or
  the ranking. So no coverage input can downgrade a finding (the release-blocking soundness rule).
* ``RUNTIME_CONFIRMED`` requires positive proof — a line tied to the finding actually executed.
* ``NOT_OBSERVED`` is advisory only: the suite covered the finding's files but ran none of its
  lines. Tests are not production, so this never implies "safe".

A finding's *evidence lines* are the first-party ``file:line`` locations that prove its vulnerable
usage: for SCA, the import sites, dynamic-construct sites, and call-path steps; for SAST, the sink
location plus every step of the source->sink flow. If coverage includes those files and at least
one such line executed, the finding is runtime-confirmed; if it includes them but none executed,
it is not-observed; if it does not include them at all, we say nothing (no annotation).
"""

from collections.abc import Iterable

from vulnadvisor.coverage.parse import CoverageData
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.model.runtime import ObservedLine, RuntimeEvidence, RuntimeStatus
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.sast.model import SastTier, ScoredSastFinding

__all__ = [
    "annotate_sast_finding",
    "annotate_sca_finding",
    "apply_coverage_overlay",
]

# Type alias kept local to avoid importing ScanReport (would be a cli<-engine layering inversion).
_Line = tuple[str, int]


def apply_coverage_overlay(
    findings: Iterable[ScoredFinding],
    sast_findings: Iterable[ScoredSastFinding],
    coverage: CoverageData,
) -> tuple[list[ScoredFinding], list[ScoredSastFinding]]:
    """Return the findings re-annotated with runtime evidence from ``coverage`` (order preserved).

    Both lists are returned as new objects; scores, tiers, and ordering are untouched.
    """
    return (
        [annotate_sca_finding(f, coverage) for f in findings],
        [annotate_sast_finding(f, coverage) for f in sast_findings],
    )


def annotate_sca_finding(finding: ScoredFinding, coverage: CoverageData) -> ScoredFinding:
    """Attach runtime evidence to a dependency finding, or return it unchanged.

    Confidently-safe (``NOT_IMPORTED``) and un-analyzed findings have no first-party usage to
    confirm, so they are never annotated. Every other tier can be runtime-confirmed (the escalation
    is sound for all of them) or marked not-observed.
    """
    reachability = finding.reachability
    if reachability is None or reachability.tier is ReachabilityTier.NOT_IMPORTED:
        return finding
    evidence = _evidence_for(_sca_evidence_lines(reachability), coverage)
    if evidence is None:
        return finding
    return finding.model_copy(update={"runtime": evidence})


def annotate_sast_finding(finding: ScoredSastFinding, coverage: CoverageData) -> ScoredSastFinding:
    """Attach runtime evidence to a code (SAST) finding, or return it unchanged.

    ``SANITIZED`` findings are already shown safe (a recognized sanitizer on every path), so there
    is nothing to confirm and they are never annotated. All other tiers can be confirmed or marked
    not-observed from the sink/flow locations.
    """
    if finding.finding.tier is SastTier.SANITIZED:
        return finding
    evidence = _evidence_for(_sast_evidence_lines(finding), coverage)
    if evidence is None:
        return finding
    return finding.model_copy(update={"runtime": evidence})


def _evidence_for(lines: set[_Line], coverage: CoverageData) -> RuntimeEvidence | None:
    """Derive the runtime verdict for a finding from its evidence ``lines`` and ``coverage``.

    Returns ``None`` (no annotation) when coverage does not include any of the finding's files —
    we can neither confirm nor honestly call it not-observed. When the files *are* covered, an
    executed evidence line yields ``RUNTIME_CONFIRMED``; otherwise ``NOT_OBSERVED`` (advisory).
    """
    covered = [(file, line) for (file, line) in lines if coverage.covers_file(file)]
    if not covered:
        return None
    executed = sorted((file, line) for (file, line) in covered if line in coverage.executed(file))
    if executed:
        observed = tuple(ObservedLine(file=file, line=line) for file, line in executed)
        shown = ", ".join(f"{file}:{line}" for file, line in executed[:3])
        more = "" if len(executed) <= 3 else f" (+{len(executed) - 3} more)"
        return RuntimeEvidence(
            status=RuntimeStatus.RUNTIME_CONFIRMED,
            reason=f"Runtime coverage shows this code executed at {shown}{more}.",
            observed=observed,
        )
    return RuntimeEvidence(
        status=RuntimeStatus.NOT_OBSERVED,
        reason=(
            "Runtime coverage included these files but executed none of this finding's lines; "
            "advisory only - a test suite is not production, so this does not lower the tier."
        ),
    )


def _sca_evidence_lines(reachability: Reachability) -> set[_Line]:
    """The first-party ``file:line`` locations that evidence a dependency finding's usage."""
    lines: set[_Line] = set()
    for import_site in reachability.evidence:
        lines.add((import_site.file, import_site.lineno))
    for dynamic_site in reachability.dynamic_evidence:
        lines.add((dynamic_site.file, dynamic_site.lineno))
    for path in reachability.call_paths:
        for step in path.steps:
            if step.file is not None and step.line is not None:
                lines.add((step.file, step.line))
    return lines


def _sast_evidence_lines(scored: ScoredSastFinding) -> set[_Line]:
    """The first-party ``file:line`` locations that evidence a code finding (sink + flow steps)."""
    finding = scored.finding
    lines: set[_Line] = {(finding.file, finding.line)}
    if finding.flow is not None:
        for step in finding.flow.steps:
            if step.file is not None and step.line is not None:
                lines.add((step.file, step.line))
    return lines
