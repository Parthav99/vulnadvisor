"""Task 16.4 — deterministic SAST scoring + the one-ranked-list (SCA + SAST) integration.

Pins the CWE->severity table, the tier discounts (including the POSSIBLE-FLOW factor the design
deferred to 16.4), the cross-type ranking guarantee (an unproven-source sink never outranks a
proven dependency flaw of comparable severity), and the JSON 1.2 / SARIF code-finding output.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.protocols import Validator

from vulnadvisor.engine.sast_scoring import (
    POSSIBLE_FLOW_PRIORITY_FACTOR,
    SANITIZED_PRIORITY_CAP,
    SANITIZED_VERDICT,
    cwe_base_severity,
    order_unified,
    score_sast_finding,
    score_sast_findings,
)
from vulnadvisor.engine.scoring import order_findings
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.model.score import PriorityBand, ScoredFinding
from vulnadvisor.output.json_report import build_report
from vulnadvisor.output.sarif import build_sarif
from vulnadvisor.sast.model import SastFinding, SastTier, ScoredSastFinding
from vulnadvisor.sast.taint import analyze_taint

_ROOT = Path(__file__).resolve().parent.parent
SARIF_SCHEMA = _ROOT / "fixtures" / "schemas" / "sarif-2.1.0.json"
SNAP = _ROOT / "fixtures" / "snapshots"
MIXED_FIXTURE = _ROOT / "fixtures" / "projects" / "taint_mixed"


def _sast(
    cwe: str = "CWE-78",
    kind: str = "command-injection",
    tier: SastTier = SastTier.CONFIRMED_FLOW,
    *,
    with_flow: bool = True,
) -> SastFinding:
    """Build a SAST finding with (optionally) a source->sink evidence path."""
    flow = (
        CallPath(
            steps=(
                CallStep(qualname="run", file="app/run.py", line=8),
                CallStep(qualname="os.system", file="app/run.py", line=12),
            )
        )
        if with_flow
        else None
    )
    return SastFinding(
        cwe=cwe,
        kind=kind,
        title="OS command injection",
        file="app/run.py",
        line=12,
        col=4,
        callee="os.system",
        tier=tier,
        reason="a tainted value from http-parameter reaches this sink with no sanitizer",
        source_kind="http-parameter" if with_flow else None,
        flow=flow,
    )


# --- CWE -> severity table ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        ("CWE-78", 9.5),
        ("CWE-94", 9.5),
        ("CWE-89", 9.0),
        ("CWE-502", 9.0),
        ("CWE-22", 7.5),
        ("CWE-918", 7.5),
        ("CWE-798", 7.0),
        ("CWE-9999", 5.0),  # unknown -> moderate default, never zeroed (soundness)
    ],
)
def test_cwe_base_severity(cwe: str, expected: float) -> None:
    assert cwe_base_severity(cwe) == expected


# --- tier discounts ----------------------------------------------------------------------------


def test_confirmed_flow_keeps_full_severity() -> None:
    scored = score_sast_finding(_sast(cwe="CWE-78", tier=SastTier.CONFIRMED_FLOW))
    assert scored.score.value == 95.0
    assert scored.score.band is PriorityBand.CRITICAL
    assert scored.score.cvss_known is False  # no CVSS for first-party code
    assert "CONFIRMED-FLOW" in scored.score.rationale


def test_dynamic_unknown_is_not_discounted() -> None:
    # Uncertainty is not a discount (soundness): DYNAMIC keeps the full CWE severity.
    confirmed = score_sast_finding(_sast(cwe="CWE-94", tier=SastTier.CONFIRMED_FLOW))
    dynamic = score_sast_finding(_sast(cwe="CWE-94", tier=SastTier.DYNAMIC_UNKNOWN))
    assert dynamic.score.value == confirmed.score.value == 95.0
    assert "DYNAMIC-UNKNOWN" in dynamic.score.rationale


def test_possible_flow_is_discounted_but_not_zeroed() -> None:
    scored = score_sast_finding(_sast(cwe="CWE-89", tier=SastTier.POSSIBLE_FLOW))
    # CWE-89 base 9.0 -> 90.0 full; the pinned 0.6x factor -> 54.0 (MEDIUM), still ranked.
    assert scored.score.value == pytest.approx(90.0 * POSSIBLE_FLOW_PRIORITY_FACTOR)
    assert scored.score.value == 54.0
    assert scored.score.band is PriorityBand.MEDIUM
    assert scored.score.value > 0.0


def test_sanitized_is_capped_into_info() -> None:
    scored = score_sast_finding(_sast(cwe="CWE-78", tier=SastTier.SANITIZED))
    assert scored.score.value <= SANITIZED_PRIORITY_CAP
    assert scored.score.band is PriorityBand.INFO
    assert scored.score.verdict == SANITIZED_VERDICT


# --- the one ranked list (cross-type) ----------------------------------------------------------


def test_order_unified_matches_order_findings_for_sca_only(
    sample_findings: list[ScoredFinding],
) -> None:
    # SCA-only input must rank identically to the established SCA ordering (no snapshot drift).
    assert order_unified(list(sample_findings)) == order_findings(sample_findings)


def test_possible_flow_never_outranks_a_proven_dependency_flaw(
    sample_findings: list[ScoredFinding],
) -> None:
    proven_dep = sample_findings[0]  # KEV jinja2, priority 90 (CRITICAL)
    possible_code = score_sast_finding(_sast(cwe="CWE-78", tier=SastTier.POSSIBLE_FLOW))
    ranked = order_unified([possible_code, proven_dep])
    assert ranked[0] is proven_dep
    assert ranked[1] is possible_code
    assert proven_dep.score.value > possible_code.score.value


def test_order_unified_is_deterministic() -> None:
    a = score_sast_finding(_sast(cwe="CWE-78", kind="command-injection"))
    b = score_sast_finding(_sast(cwe="CWE-89", kind="sql-injection"))
    findings = [b, a]
    assert order_unified(findings) == order_unified(list(reversed(findings)))


# --- JSON 1.2 (mixed) --------------------------------------------------------------------------


def test_build_report_merges_both_types(sample_findings: list[ScoredFinding]) -> None:
    code = score_sast_finding(_sast(cwe="CWE-78", tier=SastTier.CONFIRMED_FLOW))
    report = build_report(sample_findings, ("OSV",), tool_version="2.0.0", sast_findings=[code])
    assert report["schema_version"] == "1.2"
    assert report["summary"]["total"] == 3
    types = [f["finding_type"] for f in report["findings"]]
    assert types.count("dependency") == 2
    assert types.count("code") == 1
    # The CWE-78 CONFIRMED code finding (95) outranks both dependency findings.
    first = report["findings"][0]
    assert first["finding_type"] == "code"
    assert first["rule"] == {
        "cwe": "CWE-78",
        "kind": "command-injection",
        "title": "OS command injection",
    }
    assert first["location"] == {"file": "app/run.py", "line": 12, "column": 4}
    assert first["flow"]["tier"] == "confirmed-flow"
    assert first["flow"]["path"] == ["run -> os.system (app/run.py:12)"]
    assert first["score"]["cvss_known"] is False
    assert first["fix"]["has_fix"] is False
    assert "shlex.quote" in first["fix"]["direction"]


def test_code_finding_without_flow_has_empty_path() -> None:
    code = score_sast_finding(_sast(tier=SastTier.POSSIBLE_FLOW, with_flow=False))
    report = build_report([], (), tool_version="2.0.0", sast_findings=[code])
    flow = report["findings"][0]["flow"]
    assert flow["path"] == []
    assert flow["source"]["file"] == "app/run.py"  # source == sink when no flow


# --- SARIF (mixed) -----------------------------------------------------------------------------


def test_sarif_code_finding_validates_and_carries_cwe_taxonomy(
    sample_findings: list[ScoredFinding],
) -> None:
    code = score_sast_finding(_sast(cwe="CWE-78", tier=SastTier.CONFIRMED_FLOW))
    log = build_sarif(sample_findings, ("OSV",), tool_version="2.0.0", sast_findings=[code])

    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    validator: Validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(log), key=lambda e: list(e.path))
    assert errors == [], "\n".join(f"{list(e.path)}: {e.message}" for e in errors)

    run = log["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert "vulnadvisor/command-injection" in rule_ids
    # CWE taxonomy is present and the code rule relates to it.
    taxonomy = run["taxonomies"][0]
    assert taxonomy["name"] == "CWE"
    assert any(t["id"] == "CWE-78" for t in taxonomy["taxa"])
    code_result = next(r for r in run["results"] if r["ruleId"] == "vulnadvisor/command-injection")
    assert code_result["codeFlows"][0]["threadFlows"][0]["locations"]
    sink_uri = code_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert sink_uri == "app/run.py"


# --- mixed fixture: one ranked list across both types (snapshot) -------------------------------


def _ranking_view(report: dict) -> list[dict]:
    """A compact, stable view of the ranked findings for snapshotting (no volatile fields)."""
    view = []
    for finding in report["findings"]:
        if finding["finding_type"] == "dependency":
            ident = finding["advisory"]["display_id"]
        else:
            loc = finding["location"]
            ident = f"{finding['rule']['kind']}@{loc['file']}:{loc['line']}"
        view.append(
            {
                "type": finding["finding_type"],
                "id": ident,
                "band": finding["score"]["band"],
                "priority": finding["score"]["value"],
            }
        )
    return view


def test_mixed_fixture_one_ranked_list(sample_findings: list[ScoredFinding]) -> None:
    """Real taint over a mixed fixture + dependency findings = one priority-ranked list."""
    sast: list[ScoredSastFinding] = score_sast_findings(analyze_taint(MIXED_FIXTURE))
    # The fixture has exactly: one CONFIRMED os.system, one SANITIZED (shlex.quote), one POSSIBLE
    # orphan helper — all CWE-78. A missed CONFIRMED here would be release-blocking.
    tiers = sorted(f.finding.tier.value for f in sast)
    assert tiers == ["confirmed-flow", "possible-flow", "sanitized"]

    report = build_report(sample_findings, (), tool_version="2.0.0", sast_findings=sast)
    view = _ranking_view(report)

    # Priority is monotonically non-increasing across the merged list (the ranking invariant).
    priorities = [row["priority"] for row in view]
    assert priorities == sorted(priorities, reverse=True)

    SNAP.mkdir(parents=True, exist_ok=True)
    expected = SNAP / "mixed_ranking.json"
    rendered = json.dumps(view, indent=2)
    if not expected.exists():
        expected.write_text(rendered, encoding="utf-8")
    assert rendered == expected.read_text(encoding="utf-8")
