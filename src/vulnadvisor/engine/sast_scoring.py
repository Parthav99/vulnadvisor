"""Deterministic scoring for first-party (SAST) findings + the one-ranked-list ordering (16.4).

SCA scoring blends CVSS + EPSS + KEV. **None of those exist for a bug in code we just wrote** —
there is no CVE, no EPSS probability, no KEV listing. So a SAST finding's severity comes from a
fixed **CWE -> base-severity table** (``docs/sast-design.md`` §5), fed into the *same*
:func:`vulnadvisor.engine.scoring.compute_score` machinery with EPSS and KEV absent. The confidence
tier then discounts it exactly the way reachability discounts SCA findings
(:func:`~vulnadvisor.engine.scoring.apply_reachability`):

* ``CONFIRMED-FLOW`` -> full severity (a proven source->sink path).
* ``DYNAMIC-UNKNOWN`` -> full severity retained — **uncertainty is not a discount** (soundness);
  only the rationale records the dynamic block.
* ``POSSIBLE-FLOW`` -> a documented partial discount (:data:`POSSIBLE_FLOW_PRIORITY_FACTOR`): the
  sink is reached but no entry-point source was tied to it. Still ranked, never zeroed.
* ``SANITIZED`` -> scaled into the INFO band and relabeled (mirrors ``NOT_IMPORTED``): reported for
  visibility, deprioritized hard, never dropped.

Everything here is pure and reproducible — the LLM never touches it. The discount constants are
published next to the SCA ones and pinned by table-driven tests (the reviewer decision in §13.1:
the ``POSSIBLE-FLOW`` factor is fixed here, with a test asserting the resulting cross-type ranking).

Reusing ``compute_score`` for the discounted value (by feeding it a scaled "severity") keeps the
band/verdict thresholds in one place — there is no second copy of the band table to drift.
"""

from collections.abc import Iterable

from vulnadvisor.engine.scoring import compute_score
from vulnadvisor.model.score import Score, ScoredFinding
from vulnadvisor.sast.model import SastFinding, SastTier, ScoredSastFinding

__all__ = [
    "CWE_BASE_SEVERITY",
    "DEFAULT_CWE_SEVERITY",
    "POSSIBLE_FLOW_PRIORITY_FACTOR",
    "SANITIZED_PRIORITY_CAP",
    "SANITIZED_PRIORITY_FACTOR",
    "SANITIZED_VERDICT",
    "UnifiedFinding",
    "cwe_base_severity",
    "order_unified",
    "score_sast_finding",
    "score_sast_findings",
]

# A scored finding of either kind. Both carry ``.score``; the report ranks them together.
UnifiedFinding = ScoredFinding | ScoredSastFinding

# CWE -> base severity (0-10), docs/sast-design.md §5. There is no CVSS for first-party code; this
# is the auditable, published severity class. An unknown CWE falls back to a moderate default (never
# zeroed — soundness), the same posture as an unknown CVSS in the SCA engine.
CWE_BASE_SEVERITY: dict[str, float] = {
    "CWE-89": 9.0,  # SQL injection — data exfiltration / RCE-adjacent
    "CWE-78": 9.5,  # OS command injection — direct RCE
    "CWE-94": 9.5,  # code injection (eval/exec) — direct RCE
    "CWE-95": 9.5,  # code injection (eval of directive) — direct RCE
    "CWE-502": 9.0,  # unsafe deserialization — RCE in practice
    "CWE-22": 7.5,  # path traversal — arbitrary file read/write
    "CWE-918": 7.5,  # SSRF — internal pivot, metadata theft
    "CWE-798": 7.0,  # hardcoded secret — credential exposure
}
DEFAULT_CWE_SEVERITY = 5.0

# Tier discounts. CONFIRMED-FLOW and DYNAMIC-UNKNOWN keep full severity (factor 1.0); the latter is
# *not* discounted because an un-ruled-out dynamic flow is no safer than a proven one (soundness).
POSSIBLE_FLOW_PRIORITY_FACTOR = 0.6  # sink reached, source unproven — discounted, never zeroed
SANITIZED_PRIORITY_FACTOR = 0.05  # mirrors NOT_IMPORTED_PRIORITY_FACTOR
SANITIZED_PRIORITY_CAP = 5.0  # mirrors NOT_IMPORTED_PRIORITY_CAP — capped into INFO
SANITIZED_VERDICT = "Sanitized on every path"

_TIER_RATIONALE: dict[SastTier, str] = {
    SastTier.CONFIRMED_FLOW: "CONFIRMED-FLOW (a source->sink path is proven)",
    SastTier.DYNAMIC_UNKNOWN: (
        "DYNAMIC-UNKNOWN (a dynamic construct blocks certainty; not ruled out)"
    ),
    SastTier.POSSIBLE_FLOW: (
        f"POSSIBLE-FLOW (sink reached, source not proven; discounted "
        f"{POSSIBLE_FLOW_PRIORITY_FACTOR:g}x)"
    ),
    SastTier.SANITIZED: "SANITIZED (a recognized sanitizer covers every path)",
}


def cwe_base_severity(cwe: str) -> float:
    """Return the published base severity (0-10) for a CWE, or the moderate default if unknown."""
    return CWE_BASE_SEVERITY.get(cwe, DEFAULT_CWE_SEVERITY)


def _score_for_value(target: float) -> Score:
    """Run ``compute_score`` so a 0-10 ``target`` severity yields ``value == target * 10``.

    With EPSS unknown and not in KEV, ``compute_score`` sets ``value = round(target * 10, 1)`` and
    derives the band/verdict — so this reuses the single band table rather than copying it.
    """
    return compute_score(cvss_base=target, epss_probability=None, in_kev=False)


def score_sast_finding(finding: SastFinding) -> ScoredSastFinding:
    """Compute the deterministic :class:`ScoredSastFinding` for one first-party finding.

    The CWE base severity is the ceiling; the confidence tier discounts it (full for
    CONFIRMED/DYNAMIC, partial for POSSIBLE, capped to INFO for SANITIZED). The rationale is
    SAST-specific (no CVSS/EPSS wording) and ``cvss_known`` is ``False`` — there is no CVSS for
    first-party code.
    """
    severity = cwe_base_severity(finding.cwe)
    tier = finding.tier

    if tier is SastTier.SANITIZED:
        target = min(severity * SANITIZED_PRIORITY_FACTOR, SANITIZED_PRIORITY_CAP)
    elif tier is SastTier.POSSIBLE_FLOW:
        target = severity * POSSIBLE_FLOW_PRIORITY_FACTOR
    else:  # CONFIRMED_FLOW / DYNAMIC_UNKNOWN: full severity (uncertainty is not a discount)
        target = severity

    base = _score_for_value(target)
    verdict = SANITIZED_VERDICT if tier is SastTier.SANITIZED else base.verdict
    score = base.model_copy(
        update={
            "verdict": verdict,
            "cvss_base": None,
            "cvss_used": severity,
            "cvss_known": False,
            "rationale": f"{finding.cwe} base severity {severity:.1f}; {_TIER_RATIONALE[tier]}",
        }
    )
    return ScoredSastFinding(finding=finding, score=score)


def score_sast_findings(findings: Iterable[SastFinding]) -> list[ScoredSastFinding]:
    """Score every SAST finding (ordering is the report's job — see :func:`order_unified`)."""
    return [score_sast_finding(finding) for finding in findings]


def _unified_sort_key(item: UnifiedFinding) -> tuple[object, ...]:
    """Deterministic cross-type ranking: highest priority first, stable per-type tie-breakers.

    For SCA-only input this reproduces ``engine.scoring.order_findings`` exactly (the type rank is a
    constant among SCA findings), so existing snapshots are unchanged.
    """
    if isinstance(item, ScoredFinding):
        matched = item.matched
        return (
            -item.score.value,
            0,
            matched.advisory.id,
            matched.dependency.name,
            matched.dependency.version or "",
        )
    finding = item.finding
    return (-item.score.value, 1, finding.file, f"{finding.line:08d}", finding.cwe, finding.kind)


def order_unified(findings: Iterable[UnifiedFinding]) -> list[UnifiedFinding]:
    """Order SCA and SAST findings into one ranked list, highest priority first (deterministic)."""
    return sorted(findings, key=_unified_sort_key)
