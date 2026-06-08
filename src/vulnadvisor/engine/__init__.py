"""Engine: deterministic scoring and the triage verdict."""

from vulnadvisor.engine.cvss import cvss_base_score
from vulnadvisor.engine.scoring import (
    DEFAULT_SEVERITY,
    EPSS_WEIGHT,
    KEV_PRIORITY_FLOOR,
    SEVERITY_WEIGHT,
    advisory_severity,
    compute_score,
    score_match,
    score_matches,
)

__all__ = [
    "DEFAULT_SEVERITY",
    "EPSS_WEIGHT",
    "KEV_PRIORITY_FLOOR",
    "SEVERITY_WEIGHT",
    "advisory_severity",
    "compute_score",
    "cvss_base_score",
    "score_match",
    "score_matches",
]
