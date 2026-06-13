"""Dynamic-coverage overlay (Task 16.6): resolve ambiguous findings with runtime truth.

Parsing a coverage.py JSON report (:mod:`vulnadvisor.coverage.parse`) and overlaying its executed
lines onto a scan (:mod:`vulnadvisor.coverage.overlay`) are kept separate and pure: the parser
turns raw JSON into a normalized :class:`CoverageData`, and the overlay annotates findings with
:class:`~vulnadvisor.model.runtime.RuntimeEvidence` **without ever changing a tier or score**.
"""

from vulnadvisor.coverage.overlay import apply_coverage_overlay
from vulnadvisor.coverage.parse import CoverageData, CoverageParseError, parse_coverage

__all__ = [
    "CoverageData",
    "CoverageParseError",
    "apply_coverage_overlay",
    "parse_coverage",
]
