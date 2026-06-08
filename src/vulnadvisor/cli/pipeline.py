"""Wire the scan pipeline: dependencies -> advisory match -> deterministic scoring.

The ``AdvisoryMatcher`` is injected so the pipeline can be exercised end-to-end in tests without
any network access.
"""

from collections.abc import Sequence
from pathlib import Path

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.callgraph.import_graph import build_import_graph
from vulnadvisor.deps.parsers import collect_dependencies
from vulnadvisor.engine.scoring import order_findings, score_match
from vulnadvisor.model.reachability import Reachability
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.reachability.tiering import compute_reachability

__all__ = ["ScanReport", "scan_project"]


class ScanReport:
    """The result of scanning a project: ranked findings plus any degraded sources."""

    def __init__(self, findings: Sequence[ScoredFinding], degraded_sources: Sequence[str]) -> None:
        """Store the ranked ``findings`` and the ``degraded_sources`` list."""
        self.findings = list(findings)
        self.degraded_sources = tuple(degraded_sources)


def scan_project(path: Path, matcher: AdvisoryMatcher) -> ScanReport:
    """Collect dependencies under ``path``, match advisories, assign reachability, and score.

    Reachability is computed once per dependency from the project's import graph, then folded
    into the deterministic score (NOT-IMPORTED deprioritized; DYNAMIC-UNKNOWN never downgraded).
    """
    dependencies = collect_dependencies(path)
    result = matcher.match(dependencies)
    graph = build_import_graph(path)

    reachability_by_dep: dict[str, Reachability] = {}
    findings: list[ScoredFinding] = []
    for matched in result.matches:
        dep_name = matched.dependency.name
        reachability = reachability_by_dep.get(dep_name)
        if reachability is None:
            reachability = compute_reachability(matched.dependency, graph)
            reachability_by_dep[dep_name] = reachability
        findings.append(score_match(matched, reachability))

    return ScanReport(order_findings(findings), result.degraded_sources)
