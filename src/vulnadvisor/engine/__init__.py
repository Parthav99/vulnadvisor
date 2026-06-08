"""Engine: deterministic scoring and the triage verdict."""

from vulnadvisor.engine.cvss import cvss_base_score
from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.engine.scoring import (
    DEFAULT_SEVERITY,
    EPSS_WEIGHT,
    KEV_PRIORITY_FLOOR,
    NOT_IMPORTED_VERDICT,
    SEVERITY_WEIGHT,
    advisory_severity,
    apply_reachability,
    compute_score,
    order_findings,
    score_match,
    score_matches,
)

__all__ = [
    "DEFAULT_SEVERITY",
    "EPSS_WEIGHT",
    "KEV_PRIORITY_FLOOR",
    "NOT_IMPORTED_VERDICT",
    "SEVERITY_WEIGHT",
    "advisory_severity",
    "apply_reachability",
    "compute_score",
    "cvss_base_score",
    "order_findings",
    "resolve_safe_fix",
    "score_match",
    "score_matches",
]
