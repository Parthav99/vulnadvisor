"""Tests for the dynamic-coverage overlay (Task 16.6).

Covers the validation gate: executed-symbol escalation, the not-observed annotation, malformed
coverage JSON rejected gracefully, out-of-project coverage ignored, and the release-blocking
soundness invariant that **no coverage input can downgrade a tier**.
"""

import json
from pathlib import Path

import pytest

from vulnadvisor.coverage.overlay import (
    annotate_sast_finding,
    annotate_sca_finding,
    apply_coverage_overlay,
)
from vulnadvisor.coverage.parse import CoverageData, CoverageParseError, parse_coverage
from vulnadvisor.engine.sast_scoring import score_sast_findings
from vulnadvisor.engine.scoring import score_match
from vulnadvisor.model.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    MatchedAdvisory,
)
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.imports import (
    DynamicImportKind,
    DynamicImportSite,
    ImportKind,
    ImportSite,
)
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.model.runtime import RuntimeStatus
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.sast.model import SastFinding, SastTier, ScoredSastFinding

# --------------------------------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------------------------------


def _matched() -> MatchedAdvisory:
    return MatchedAdvisory(
        dependency=Dependency(
            name="pyyaml",
            raw_name="PyYAML",
            version="5.3.1",
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id="CVE-2020-14343",
            aliases=("CVE-2020-14343",),
            summary="PyYAML full_load RCE.",
            affected=(
                AffectedPackage(
                    name="pyyaml", ranges=(AffectedRange(introduced="0", fixed="5.4"),)
                ),
            ),
        ),
        in_kev=False,
    )


def _sca(
    tier: ReachabilityTier,
    *,
    evidence: tuple[ImportSite, ...] = (),
    dynamic_evidence: tuple[DynamicImportSite, ...] = (),
    call_paths: tuple[CallPath, ...] = (),
) -> ScoredFinding:
    reach = Reachability(
        tier=tier,
        reason="test",
        evidence=evidence,
        dynamic_evidence=dynamic_evidence,
        call_paths=call_paths,
    )
    return score_match(_matched(), reach)


def _import_site(file: str, line: int) -> ImportSite:
    return ImportSite(file=file, lineno=line, col=0, kind=ImportKind.IMPORT)


def _dynamic_site(file: str, line: int) -> DynamicImportSite:
    return DynamicImportSite(
        file=file, lineno=line, col=0, kind=DynamicImportKind.IMPORTLIB, detail="import_module(x)"
    )


def _sast(
    tier: SastTier, *, file: str, line: int, flow: CallPath | None = None
) -> ScoredSastFinding:
    finding = SastFinding(
        cwe="CWE-78",
        kind="command-injection",
        title="OS command injection",
        file=file,
        line=line,
        col=0,
        callee="os.system",
        tier=tier,
        reason="test",
        flow=flow,
    )
    return score_sast_findings([finding])[0]


def _coverage(executed: dict[str, list[int]]) -> CoverageData:
    return CoverageData(executed_lines={k: frozenset(v) for k, v in executed.items()})


# --------------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------------


def _write_coverage(tmp_path: Path, files: dict[str, dict[str, object]]) -> str:
    return json.dumps({"meta": {"version": "7.0"}, "files": files, "totals": {}})


def test_parse_line_coverage(tmp_path: Path) -> None:
    raw = _write_coverage(tmp_path, {"app/db.py": {"executed_lines": [1, 5, 42]}})
    data = parse_coverage(raw, tmp_path)
    assert data.covers_file("app/db.py")
    assert data.executed("app/db.py") == frozenset({1, 5, 42})
    assert data.file_count == 1


def test_parse_branch_coverage_reads_executed_lines(tmp_path: Path) -> None:
    # Branch mode adds executed_branches but executed_lines is still present -> one code path.
    raw = _write_coverage(
        tmp_path,
        {"app/db.py": {"executed_lines": [10], "executed_branches": [[10, 11]]}},
    )
    data = parse_coverage(raw, tmp_path)
    assert data.executed("app/db.py") == frozenset({10})


def test_parse_absolute_paths_normalized(tmp_path: Path) -> None:
    abs_path = (tmp_path / "pkg" / "x.py").as_posix()
    raw = _write_coverage(tmp_path, {abs_path: {"executed_lines": [3]}})
    data = parse_coverage(raw, tmp_path)
    assert data.executed("pkg/x.py") == frozenset({3})


def test_parse_ignores_files_outside_project(tmp_path: Path) -> None:
    outside = (tmp_path.parent / "elsewhere" / "y.py").resolve().as_posix()
    raw = _write_coverage(
        tmp_path,
        {"app/in.py": {"executed_lines": [1]}, outside: {"executed_lines": [99]}},
    )
    data = parse_coverage(raw, tmp_path)
    assert data.covers_file("app/in.py")
    assert not data.covers_file("../elsewhere/y.py")
    assert data.file_count == 1


def test_parse_coerces_garbage_line_values(tmp_path: Path) -> None:
    raw = _write_coverage(
        tmp_path,
        {"app/x.py": {"executed_lines": [1, "two", 3.5, True, None, -4, 0, 7]}},
    )
    data = parse_coverage(raw, tmp_path)
    # Only positive ints survive; bools/strings/floats/None/non-positive are dropped.
    assert data.executed("app/x.py") == frozenset({1, 7})


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all {",
        "[1, 2, 3]",  # valid JSON but not an object
        json.dumps({"meta": {}}),  # no files key
        json.dumps({"files": "nope"}),  # files not an object
    ],
)
def test_parse_malformed_rejected_gracefully(raw: str, tmp_path: Path) -> None:
    with pytest.raises(CoverageParseError):
        parse_coverage(raw, tmp_path)


def test_parse_skips_malformed_file_entries(tmp_path: Path) -> None:
    raw = json.dumps({"files": {"app/ok.py": {"executed_lines": [2]}, "app/bad.py": "not-a-dict"}})
    data = parse_coverage(raw, tmp_path)
    assert data.executed("app/ok.py") == frozenset({2})
    assert not data.covers_file("app/bad.py")  # non-dict entry skipped
    assert data.file_count == 1


def test_parse_unions_duplicate_normalized_paths(tmp_path: Path) -> None:
    abs_path = (tmp_path / "app" / "x.py").as_posix()
    raw = json.dumps(
        {"files": {"app/x.py": {"executed_lines": [1]}, abs_path: {"executed_lines": [2]}}}
    )
    data = parse_coverage(raw, tmp_path)
    assert data.executed("app/x.py") == frozenset({1, 2})


# --------------------------------------------------------------------------------------------------
# SCA overlay
# --------------------------------------------------------------------------------------------------


def test_sca_executed_import_site_is_runtime_confirmed() -> None:
    finding = _sca(ReachabilityTier.IMPORTED, evidence=(_import_site("app/main.py", 10),))
    coverage = _coverage({"app/main.py": [10, 11]})
    annotated = annotate_sca_finding(finding, coverage)
    assert annotated.runtime is not None
    assert annotated.runtime.status is RuntimeStatus.RUNTIME_CONFIRMED
    assert [(o.file, o.line) for o in annotated.runtime.observed] == [("app/main.py", 10)]
    # The static tier and score are untouched.
    assert annotated.reachability is not None
    assert annotated.reachability.tier is ReachabilityTier.IMPORTED
    assert annotated.score == finding.score


def test_sca_executed_call_path_step_confirms_dynamic_unknown() -> None:
    path = CallPath(
        steps=(
            CallStep(qualname="main", file="app/main.py", line=3),
            CallStep(qualname="yaml.load", file="app/main.py", line=8),
        )
    )
    finding = _sca(ReachabilityTier.DYNAMIC_UNKNOWN, call_paths=(path,))
    coverage = _coverage({"app/main.py": [8]})
    annotated = annotate_sca_finding(finding, coverage)
    assert annotated.runtime is not None
    assert annotated.runtime.is_confirmed
    assert ("app/main.py", 8) in [(o.file, o.line) for o in annotated.runtime.observed]


def test_sca_dynamic_evidence_line_confirms() -> None:
    finding = _sca(
        ReachabilityTier.DYNAMIC_UNKNOWN, dynamic_evidence=(_dynamic_site("app/loader.py", 4),)
    )
    coverage = _coverage({"app/loader.py": [4]})
    annotated = annotate_sca_finding(finding, coverage)
    assert annotated.runtime is not None and annotated.runtime.is_confirmed


def test_sca_covered_but_unexecuted_is_not_observed() -> None:
    finding = _sca(ReachabilityTier.IMPORTED, evidence=(_import_site("app/main.py", 10),))
    coverage = _coverage({"app/main.py": [1, 2, 3]})  # file covered, line 10 never ran
    annotated = annotate_sca_finding(finding, coverage)
    assert annotated.runtime is not None
    assert annotated.runtime.status is RuntimeStatus.NOT_OBSERVED
    assert annotated.runtime.observed == ()


def test_sca_uncovered_file_yields_no_annotation() -> None:
    finding = _sca(ReachabilityTier.IMPORTED, evidence=(_import_site("app/main.py", 10),))
    coverage = _coverage({"other/elsewhere.py": [10]})
    annotated = annotate_sca_finding(finding, coverage)
    assert annotated.runtime is None


def test_sca_not_imported_never_annotated() -> None:
    finding = _sca(ReachabilityTier.NOT_IMPORTED)
    coverage = _coverage({"app/main.py": [10]})
    assert annotate_sca_finding(finding, coverage).runtime is None


# --------------------------------------------------------------------------------------------------
# SAST overlay
# --------------------------------------------------------------------------------------------------


def test_sast_executed_sink_confirms_possible_flow() -> None:
    finding = _sast(SastTier.POSSIBLE_FLOW, file="app/run.py", line=20)
    coverage = _coverage({"app/run.py": [20]})
    annotated = annotate_sast_finding(finding, coverage)
    assert annotated.runtime is not None and annotated.runtime.is_confirmed
    assert annotated.finding.tier is SastTier.POSSIBLE_FLOW  # tier unchanged


def test_sast_flow_step_confirms() -> None:
    flow = CallPath(
        steps=(
            CallStep(qualname="handler", file="app/api.py", line=5),
            CallStep(qualname="os.system", file="app/run.py", line=20),
        )
    )
    finding = _sast(SastTier.CONFIRMED_FLOW, file="app/run.py", line=20, flow=flow)
    coverage = _coverage({"app/api.py": [5]})  # an intermediate flow step executed
    annotated = annotate_sast_finding(finding, coverage)
    assert annotated.runtime is not None and annotated.runtime.is_confirmed


def test_sast_covered_unexecuted_is_not_observed() -> None:
    finding = _sast(SastTier.POSSIBLE_FLOW, file="app/run.py", line=20)
    coverage = _coverage({"app/run.py": [1, 2]})
    annotated = annotate_sast_finding(finding, coverage)
    assert annotated.runtime is not None
    assert annotated.runtime.status is RuntimeStatus.NOT_OBSERVED


def test_sast_sanitized_never_annotated() -> None:
    finding = _sast(SastTier.SANITIZED, file="app/run.py", line=20)
    coverage = _coverage({"app/run.py": [20]})
    assert annotate_sast_finding(finding, coverage).runtime is None


# --------------------------------------------------------------------------------------------------
# apply_coverage_overlay + soundness
# --------------------------------------------------------------------------------------------------


def test_apply_overlay_preserves_order_and_returns_new_lists() -> None:
    sca = [_sca(ReachabilityTier.IMPORTED, evidence=(_import_site("a.py", 1),))]
    sast = [_sast(SastTier.POSSIBLE_FLOW, file="b.py", line=2)]
    coverage = _coverage({"a.py": [1], "b.py": [2]})
    out_sca, out_sast = apply_coverage_overlay(sca, sast, coverage)
    assert len(out_sca) == 1 and len(out_sast) == 1
    assert out_sca[0].runtime is not None and out_sca[0].runtime.is_confirmed
    assert out_sast[0].runtime is not None and out_sast[0].runtime.is_confirmed
    # Inputs are not mutated (new objects returned).
    assert sca[0].runtime is None and sast[0].runtime is None


def test_soundness_no_coverage_input_downgrades_a_tier() -> None:
    """Exhaustive: across every tier and a range of coverage inputs, the tier never changes."""
    sca_findings = [
        _sca(tier, evidence=(_import_site("app/main.py", 10),), call_paths=())
        for tier in ReachabilityTier
    ]
    sast_findings = [_sast(tier, file="app/main.py", line=10) for tier in SastTier]
    coverage_inputs = [
        _coverage({}),  # empty
        _coverage({"app/main.py": []}),  # covered, nothing ran -> not-observed
        _coverage({"app/main.py": [10]}),  # executed -> confirmed
        _coverage({"app/main.py": list(range(1, 100))}),  # everything ran
        _coverage({"unrelated.py": [10]}),  # different file
    ]
    for coverage in coverage_inputs:
        out_sca, out_sast = apply_coverage_overlay(sca_findings, sast_findings, coverage)
        for before, after in zip(sca_findings, out_sca, strict=True):
            assert after.reachability is not None and before.reachability is not None
            assert after.reachability.tier is before.reachability.tier
            assert after.score == before.score
        for before_s, after_s in zip(sast_findings, out_sast, strict=True):
            assert after_s.finding.tier is before_s.finding.tier
            assert after_s.score == before_s.score
