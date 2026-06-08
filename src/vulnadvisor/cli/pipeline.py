"""Wire the scan pipeline: dependencies -> advisory match -> deterministic scoring.

The ``AdvisoryMatcher`` is injected so the pipeline can be exercised end-to-end in tests without
any network access.
"""

from collections.abc import Sequence
from pathlib import Path

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.deps.parsers import collect_dependencies
from vulnadvisor.engine.scoring import score_matches
from vulnadvisor.model.score import ScoredFinding

__all__ = ["ScanReport", "scan_project"]


class ScanReport:
    """The result of scanning a project: ranked findings plus any degraded sources."""

    def __init__(self, findings: Sequence[ScoredFinding], degraded_sources: Sequence[str]) -> None:
        """Store the ranked ``findings`` and the ``degraded_sources`` list."""
        self.findings = list(findings)
        self.degraded_sources = tuple(degraded_sources)


def scan_project(path: Path, matcher: AdvisoryMatcher) -> ScanReport:
    """Collect dependencies under ``path``, match advisories, and score the results."""
    dependencies = collect_dependencies(path)
    result = matcher.match(dependencies)
    findings = score_matches(result.matches)
    return ScanReport(findings, result.degraded_sources)
