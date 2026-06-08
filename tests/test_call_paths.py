from collections.abc import Callable
from pathlib import Path

import pytest

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.callgraph import build_import_graph, find_vulnerable_call_paths
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.model import (
    Dependency,
    DependencySource,
    ReachabilityTier,
)
from vulnadvisor.reachability import compute_reachability, refine_reachability

PROJECTS = Path(__file__).resolve().parent.parent / "fixtures" / "projects"
YAML_IMPORTS = ("yaml",)
YAML_VULN = frozenset({"load"})


def _pyyaml() -> Dependency:
    return Dependency(
        name="pyyaml",
        raw_name="PyYAML",
        version="5.3.1",
        source=DependencySource.REQUIREMENTS_TXT,
    )


# --- core call-path search --------------------------------------------------------------------


def test_finds_call_path() -> None:
    result = find_vulnerable_call_paths(
        PROJECTS / "reach_called", import_names=YAML_IMPORTS, vulnerable_names=YAML_VULN
    )
    assert result.paths
    rendered = result.paths[0].render()
    assert "yaml.load" in rendered
    # The path runs through the first-party functions, ending at the call site with a location.
    qualnames = [step.qualname for step in result.paths[0].steps]
    assert "main" in qualnames
    assert "parse" in qualnames
    assert "app.py:" in rendered


def test_no_call_path_when_only_imported() -> None:
    result = find_vulnerable_call_paths(
        PROJECTS / "reach_imported_only", import_names=YAML_IMPORTS, vulnerable_names=YAML_VULN
    )
    assert result.paths == ()
    assert result.has_dynamic is False


def test_dynamic_dispatch_flagged_without_path() -> None:
    result = find_vulnerable_call_paths(
        PROJECTS / "reach_dynamic_dispatch", import_names=YAML_IMPORTS, vulnerable_names=YAML_VULN
    )
    assert result.paths == ()
    assert result.has_dynamic is True  # getattr(yaml, ...) is reflective dispatch
    assert result.reflections  # recorded as a package reflection for the resolver


def test_no_symbols_means_no_paths() -> None:
    result = find_vulnerable_call_paths(
        PROJECTS / "reach_called", import_names=YAML_IMPORTS, vulnerable_names=frozenset()
    )
    assert result.paths == ()


# --- refinement into reachability tiers (security-critical gate) ------------------------------


def _refined(project: str) -> ReachabilityTier:
    graph = build_import_graph(PROJECTS / project)
    base = compute_reachability(_pyyaml(), graph)
    refined = refine_reachability(_pyyaml(), base, graph, PROJECTS / project, YAML_VULN)
    return refined.tier


def test_called_upgrades_to_imported_and_called() -> None:
    graph = build_import_graph(PROJECTS / "reach_called")
    base = compute_reachability(_pyyaml(), graph)
    refined = refine_reachability(_pyyaml(), base, graph, PROJECTS / "reach_called", YAML_VULN)
    assert refined.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert refined.call_paths
    assert "yaml.load" in refined.reason


def test_imported_only_stays_imported() -> None:
    assert _refined("reach_imported_only") is ReachabilityTier.IMPORTED


def test_dynamic_downgrades_to_dynamic_unknown() -> None:
    assert _refined("reach_dynamic_dispatch") is ReachabilityTier.DYNAMIC_UNKNOWN


def test_zero_false_negatives_call_level() -> None:
    # A reachable (called) or uncertain (dynamic) finding is NEVER reported as merely IMPORTED-safe
    # and NEVER as NOT_IMPORTED.
    assert _refined("reach_called") is ReachabilityTier.IMPORTED_AND_CALLED
    assert _refined("reach_dynamic_dispatch") is not ReachabilityTier.NOT_IMPORTED


def test_no_symbol_names_leaves_base_unchanged() -> None:
    graph = build_import_graph(PROJECTS / "reach_called")
    base = compute_reachability(_pyyaml(), graph)
    refined = refine_reachability(_pyyaml(), base, graph, PROJECTS / "reach_called", frozenset())
    assert refined.tier is base.tier  # no symbols -> no function-level change


# --- end-to-end pipeline with a symbol provider -----------------------------------------------


def test_pipeline_reports_imported_and_called(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(
        PROJECTS / "reach_called",
        fake_matcher(),
        symbol_names_for=lambda _advisory: YAML_VULN,
    )
    assert report.findings
    finding = report.findings[0]
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert finding.reachability.call_paths


@pytest.mark.parametrize(
    ("project", "expected"),
    [
        ("reach_called", ReachabilityTier.IMPORTED_AND_CALLED),
        ("reach_imported_only", ReachabilityTier.IMPORTED),
        ("reach_dynamic_dispatch", ReachabilityTier.DYNAMIC_UNKNOWN),
    ],
)
def test_pipeline_tiers(
    project: str,
    expected: ReachabilityTier,
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(
        PROJECTS / project, fake_matcher(), symbol_names_for=lambda _advisory: YAML_VULN
    )
    assert report.findings
    assert report.findings[0].reachability is not None
    assert report.findings[0].reachability.tier is expected
