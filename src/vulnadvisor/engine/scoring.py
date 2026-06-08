"""Deterministic priority scoring — the heart of "triage, not scan".

Priority is computed purely from three signals and is fully reproducible (no randomness, no
clock, no I/O). The LLM layer never touches this number; it only explains the result.

Formula (0-100 priority)
------------------------
Let ``sev = severity / 10`` (CVSS base score normalized to 0..1) and ``epss`` the EPSS exploit
probability (0..1).

* If EPSS is **known**:   ``risk = 0.6 * epss + 0.4 * sev``
* If EPSS is **unknown**: ``risk = sev``  (we do not let a missing EPSS zero out real severity)

``value = round(100 * risk, 1)``. EPSS is weighted above severity on purpose: triage is about
*real-world exploit likelihood*, which is what cuts the noise a pure-severity scanner produces.

Soundness guards
----------------
* **KEV dominates.** If the vuln is in CISA KEV (proven exploited in the wild), ``value`` is
  floored to 90 (the CRITICAL band) regardless of the other signals.
* **Unknown CVSS never means "ignore".** A missing/unparseable CVSS falls back to a moderate
  default severity (5.0) and is flagged ``cvss_known = False`` rather than scored as 0.

Bands -> verdicts:  >=90 CRITICAL "Fix now" · >=70 HIGH "Fix this sprint" ·
>=40 MEDIUM "Plan a fix" · >=15 LOW "Monitor" · else INFO "Deprioritize".
"""

from collections.abc import Iterable

from vulnadvisor.engine.cvss import cvss_base_score
from vulnadvisor.model.advisory import Advisory, MatchedAdvisory
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.model.score import PriorityBand, Score, ScoredFinding

__all__ = [
    "DEFAULT_SEVERITY",
    "EPSS_WEIGHT",
    "KEV_PRIORITY_FLOOR",
    "NOT_IMPORTED_PRIORITY_FACTOR",
    "NOT_IMPORTED_VERDICT",
    "SEVERITY_WEIGHT",
    "advisory_severity",
    "apply_reachability",
    "compute_score",
    "order_findings",
    "score_match",
    "score_matches",
]

DEFAULT_SEVERITY = 5.0
EPSS_WEIGHT = 0.6
SEVERITY_WEIGHT = 0.4
KEV_PRIORITY_FLOOR = 90.0

# A NOT-IMPORTED finding is the only confidently-safe tier: deprioritize it hard (but never
# drop it). The score is scaled down and capped into the INFO band, and relabeled.
NOT_IMPORTED_PRIORITY_FACTOR = 0.05
NOT_IMPORTED_PRIORITY_CAP = 5.0
NOT_IMPORTED_VERDICT = "No path from your code"

_REACHABILITY_LABELS: dict[ReachabilityTier, str] = {
    ReachabilityTier.IMPORTED_AND_CALLED: "IMPORTED-AND-CALLED",
    ReachabilityTier.IMPORTED: "IMPORTED",
    ReachabilityTier.DYNAMIC_UNKNOWN: "DYNAMIC-UNKNOWN (usage could not be ruled out)",
    ReachabilityTier.NOT_IMPORTED: "NOT-IMPORTED (no path from your code)",
}

# (inclusive lower bound, band) in descending order.
_BANDS: tuple[tuple[float, PriorityBand], ...] = (
    (90.0, PriorityBand.CRITICAL),
    (70.0, PriorityBand.HIGH),
    (40.0, PriorityBand.MEDIUM),
    (15.0, PriorityBand.LOW),
    (0.0, PriorityBand.INFO),
)

_VERDICTS: dict[PriorityBand, str] = {
    PriorityBand.CRITICAL: "Fix now",
    PriorityBand.HIGH: "Fix this sprint",
    PriorityBand.MEDIUM: "Plan a fix",
    PriorityBand.LOW: "Monitor",
    PriorityBand.INFO: "Deprioritize",
}


def advisory_severity(advisory: Advisory) -> tuple[float | None, float]:
    """Return ``(cvss_base_or_None, severity_used)`` for an advisory.

    Prefers an explicit ``cvss_score``; else derives it from the CVSS vector; else falls back to
    :data:`DEFAULT_SEVERITY` (with the first element ``None`` to mark it unknown).
    """
    base = advisory.cvss_score
    if base is None:
        base = cvss_base_score(advisory.cvss_vector)
    if base is None:
        return None, DEFAULT_SEVERITY
    return base, base


def _band_for(value: float) -> PriorityBand:
    """Return the priority band for a numeric ``value``."""
    for lower, band in _BANDS:
        if value >= lower:
            return band
    return PriorityBand.INFO


def _rationale(
    *, in_kev: bool, epss: float | None, cvss_base: float | None, severity: float
) -> str:
    """Build a deterministic plain-text explanation of the scoring signals."""
    parts: list[str] = []
    if in_kev:
        parts.append("KEV-listed (known exploited in the wild)")
    parts.append(f"EPSS {epss:.3f}" if epss is not None else "EPSS unknown")
    parts.append(
        f"CVSS {cvss_base:.1f}"
        if cvss_base is not None
        else f"CVSS unknown (assumed {severity:.1f})"
    )
    return "; ".join(parts)


def compute_score(
    *, cvss_base: float | None, epss_probability: float | None, in_kev: bool
) -> Score:
    """Compute the deterministic :class:`Score` from the three risk signals."""
    severity = cvss_base if cvss_base is not None else DEFAULT_SEVERITY
    sev_norm = severity / 10.0

    if epss_probability is None:
        risk = sev_norm
    else:
        risk = EPSS_WEIGHT * epss_probability + SEVERITY_WEIGHT * sev_norm

    value = round(100.0 * risk, 1)
    if in_kev:
        value = max(value, KEV_PRIORITY_FLOOR)
    value = min(100.0, max(0.0, value))

    band = _band_for(value)
    return Score(
        value=value,
        band=band,
        verdict=_VERDICTS[band],
        cvss_base=cvss_base,
        cvss_used=severity,
        cvss_known=cvss_base is not None,
        epss_probability=epss_probability,
        in_kev=in_kev,
        rationale=_rationale(
            in_kev=in_kev, epss=epss_probability, cvss_base=cvss_base, severity=severity
        ),
    )


def apply_reachability(score: Score, reachability: Reachability) -> Score:
    """Return ``score`` adjusted for reachability.

    NOT-IMPORTED (confidently safe) is scaled down and capped into the INFO band and relabeled
    "No path from your code". Every other tier keeps its full priority — we never silently
    downgrade a finding we could not prove safe — and only annotates the rationale.
    """
    label = _REACHABILITY_LABELS[reachability.tier]
    if reachability.tier is ReachabilityTier.NOT_IMPORTED:
        value = min(round(score.value * NOT_IMPORTED_PRIORITY_FACTOR, 1), NOT_IMPORTED_PRIORITY_CAP)
        return score.model_copy(
            update={
                "value": value,
                "band": _band_for(value),
                "verdict": NOT_IMPORTED_VERDICT,
                "rationale": f"{score.rationale}; {label}",
            }
        )
    return score.model_copy(update={"rationale": f"{score.rationale}; {label}"})


def score_match(
    matched: MatchedAdvisory, reachability: Reachability | None = None
) -> ScoredFinding:
    """Score a single matched advisory, optionally adjusting for its reachability tier."""
    cvss_base, _ = advisory_severity(matched.advisory)
    epss = matched.epss.probability if matched.epss is not None else None
    score = compute_score(cvss_base=cvss_base, epss_probability=epss, in_kev=matched.in_kev)
    if reachability is not None:
        score = apply_reachability(score, reachability)
    return ScoredFinding(matched=matched, score=score, reachability=reachability)


def _sort_key(finding: ScoredFinding) -> tuple[float, str, str, str]:
    """Deterministic ordering: highest score first, then stable tie-breakers."""
    return (
        -finding.score.value,
        finding.matched.advisory.id,
        finding.matched.dependency.name,
        finding.matched.dependency.version or "",
    )


def order_findings(findings: Iterable[ScoredFinding]) -> list[ScoredFinding]:
    """Deterministically order scored findings (highest priority first)."""
    return sorted(findings, key=_sort_key)


def score_matches(matches: Iterable[MatchedAdvisory]) -> list[ScoredFinding]:
    """Score and deterministically sort matched advisories (highest priority first)."""
    return sorted((score_match(m) for m in matches), key=_sort_key)
