"""Engine: deterministic scoring and the triage verdict."""

from vulnadvisor.engine.cvss import cvss_base_score
from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.engine.sast_scoring import (
    CWE_BASE_SEVERITY,
    POSSIBLE_FLOW_PRIORITY_FACTOR,
    UnifiedFinding,
    cwe_base_severity,
    order_unified,
    score_sast_finding,
    score_sast_findings,
)
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
    "CWE_BASE_SEVERITY",
    "DEFAULT_SEVERITY",
    "EPSS_WEIGHT",
    "KEV_PRIORITY_FLOOR",
    "NOT_IMPORTED_VERDICT",
    "POSSIBLE_FLOW_PRIORITY_FACTOR",
    "SEVERITY_WEIGHT",
    "UnifiedFinding",
    "advisory_severity",
    "apply_reachability",
    "compute_score",
    "cvss_base_score",
    "cwe_base_severity",
    "order_findings",
    "order_unified",
    "resolve_safe_fix",
    "score_match",
    "score_matches",
    "score_sast_finding",
    "score_sast_findings",
]
