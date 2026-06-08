from collections.abc import Callable
from pathlib import Path

import pytest

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.callgraph import build_import_graph
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.engine.scoring import apply_reachability, compute_score, score_match
from vulnadvisor.model import (
    Advisory,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
    PriorityBand,
    Reachability,
    ReachabilityTier,
)
from vulnadvisor.reachability import compute_reachability

PROJECTS = Path(__file__).resolve().parent.parent / "fixtures" / "projects"


def _pyyaml() -> Dependency:
    return Dependency(
        name="pyyaml",
        raw_name="PyYAML",
        version="6.0",
        source=DependencySource.REQUIREMENTS_TXT,
    )


# --- security-critical tiering gate (Fixtures A / B / C) ---------------------------------------


def test_fixture_a_imported() -> None:
    graph = build_import_graph(PROJECTS / "reach_imported")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.IMPORTED
    assert reach.evidence  # shows the import site as evidence
    assert reach.evidence[0].file == "app.py"


def test_fixture_b_not_imported() -> None:
    graph = build_import_graph(PROJECTS / "reach_not_imported")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.NOT_IMPORTED
    assert "no path" in reach.reason.lower()


def test_fixture_c_dynamic_unknown() -> None:
    graph = build_import_graph(PROJECTS / "reach_dynamic")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN
    assert reach.dynamic_evidence  # the importlib site is recorded


def test_zero_false_negatives_across_fixture_suite() -> None:
    # Release-blocking invariant: a reachable/uncertain package is NEVER marked confidently safe.
    for project in ("reach_imported", "reach_dynamic"):
        graph = build_import_graph(PROJECTS / project)
        reach = compute_reachability(_pyyaml(), graph)
        assert reach.tier is not ReachabilityTier.NOT_IMPORTED, project


# --- escalation safeguards --------------------------------------------------------------------


def test_no_source_files_escalates_to_dynamic_unknown(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("PyYAML==6.0\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_parse_error_blocks_not_imported(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_low_confidence_mapping_blocks_not_imported(tmp_path: Path) -> None:
    # An unknown distribution resolves to a LOW-confidence best-guess import name; if we do not
    # find it, we must not claim NOT_IMPORTED (the real import name might differ).
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    unknown = Dependency(
        name="totally-unknown-xyz",
        raw_name="totally-unknown-xyz",
        version="1.0",
        source=DependencySource.REQUIREMENTS_TXT,
    )
    reach = compute_reachability(unknown, graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


# --- engine wiring ----------------------------------------------------------------------------


def _matched() -> MatchedAdvisory:
    return MatchedAdvisory(
        dependency=_pyyaml(),
        advisory=Advisory(id="GHSA-x", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        epss=EpssScore(cve="CVE-0000-0001", probability=0.9, percentile=0.99),
        in_kev=True,
    )


def _reach(tier: ReachabilityTier) -> Reachability:
    return Reachability(tier=tier, reason="test")


def test_not_imported_is_deprioritized() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.NOT_IMPORTED))
    assert adjusted.value < base.value
    assert adjusted.band is PriorityBand.INFO
    assert adjusted.verdict == "No path from your code"


def test_dynamic_unknown_keeps_full_priority() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.DYNAMIC_UNKNOWN))
    assert adjusted.value == base.value  # never silently downgraded
    assert "DYNAMIC-UNKNOWN" in adjusted.rationale


def test_imported_keeps_full_priority() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.IMPORTED))
    assert adjusted.value == base.value
    assert "IMPORTED" in adjusted.rationale


def test_score_match_threads_reachability() -> None:
    finding = score_match(_matched(), _reach(ReachabilityTier.NOT_IMPORTED))
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.NOT_IMPORTED
    assert finding.score.verdict == "No path from your code"


# --- end-to-end pipeline ----------------------------------------------------------------------


def test_pipeline_imported_stays_high(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(PROJECTS / "reach_imported", fake_matcher())
    assert report.findings
    finding = report.findings[0]
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.IMPORTED
    assert finding.score.band is PriorityBand.CRITICAL  # KEV + high EPSS, kept high


def test_pipeline_not_imported_is_deprioritized(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(PROJECTS / "reach_not_imported", fake_matcher())
    assert report.findings
    finding = report.findings[0]
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.NOT_IMPORTED
    assert finding.score.band is PriorityBand.INFO
    assert finding.score.verdict == "No path from your code"


@pytest.mark.parametrize("project", ["reach_imported", "reach_dynamic"])
def test_pipeline_never_marks_reachable_as_safe(
    project: str, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    report = scan_project(PROJECTS / project, fake_matcher())
    for finding in report.findings:
        assert finding.reachability is not None
        assert finding.reachability.tier is not ReachabilityTier.NOT_IMPORTED
