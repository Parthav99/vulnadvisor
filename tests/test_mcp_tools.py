"""Unit tests for the pure MCP tool logic (no MCP SDK, no network, no filesystem)."""

from typing import Any

import pytest

from vulnadvisor.mcp.tools import (
    AmbiguousFindingError,
    FindingNotFoundError,
    McpToolError,
    compact_finding,
    explain_finding_facts,
    filter_findings,
    finding_id,
    get_finding_detail,
    scan_summary,
)


def _finding(
    *,
    package: str,
    advisory_id: str,
    display_id: str,
    band: str,
    priority: float,
    tier: str | None,
    in_kev: bool = False,
    aliases: tuple[str, ...] = (),
    cve_ids: tuple[str, ...] = (),
    call_paths: tuple[str, ...] = (),
    has_fix: bool = True,
) -> dict[str, Any]:
    """Build one finding dict in the shape build_report() emits."""
    reachability: dict[str, Any] | None = (
        None
        if tier is None
        else {
            "tier": tier,
            "reason": f"{package} reachability reason",
            "evidence": [{"file": "app.py", "line": 1}],
            "call_paths": list(call_paths),
        }
    )
    return {
        "dependency": {
            "name": package,
            "version": "1.0",
            "source": "requirements.txt",
            "is_direct": True,
        },
        "advisory": {
            "id": advisory_id,
            "display_id": display_id,
            "aliases": list(aliases),
            "cve_ids": list(cve_ids),
            "summary": f"{package} vuln",
            "cvss_base": 7.5,
            "cvss_vector": None,
            "source": "OSV",
        },
        "epss": {"probability": 0.5, "percentile": 0.9},
        "in_kev": in_kev,
        "score": {
            "value": priority,
            "band": band,
            "verdict": f"{band} verdict",
            "rationale": "because reasons",
            "cvss_known": True,
        },
        "reachability": reachability,
        "fix": {
            "command": "uv pip install x" if has_fix else None,
            "fixed_version": "1.1" if has_fix else None,
            "has_fix": has_fix,
            "is_major_jump": False,
            "available_fixes": ["1.1"] if has_fix else [],
            "note": "" if has_fix else "no fix available",
        },
    }


def _report() -> dict[str, Any]:
    """A three-finding report spanning tiers, bands, and KEV state."""
    findings = [
        _finding(
            package="jinja2",
            advisory_id="GHSA-jinja",
            display_id="CVE-2019-10906",
            band="critical",
            priority=95.0,
            tier="imported-and-called",
            in_kev=True,
            aliases=("CVE-2019-10906",),
            cve_ids=("CVE-2019-10906",),
            call_paths=("main -> render -> jinja2.from_string (app.py:42)",),
        ),
        _finding(
            package="flask",
            advisory_id="PYSEC-2018-1",
            display_id="CVE-2018-1000656",
            band="low",
            priority=20.0,
            tier="imported",
            aliases=("CVE-2018-1000656",),
            cve_ids=("CVE-2018-1000656",),
        ),
        _finding(
            package="requests",
            advisory_id="GHSA-req",
            display_id="GHSA-req",
            band="medium",
            priority=50.0,
            tier="not-imported",
            has_fix=False,
        ),
    ]
    return {
        "schema_version": "1.1",
        "tool": {"name": "vulnadvisor", "version": "9.9.9"},
        "degraded_sources": [],
        "summary": {
            "total": 3,
            "by_band": {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0},
        },
        "findings": findings,
    }


def test_finding_id_is_package_and_advisory() -> None:
    report = _report()
    assert finding_id(report["findings"][0]) == "jinja2:GHSA-jinja"


def test_compact_finding_shape() -> None:
    row = compact_finding(_report()["findings"][0])
    assert row == {
        "finding_id": "jinja2:GHSA-jinja",
        "display_id": "CVE-2019-10906",
        "package": "jinja2",
        "version": "1.0",
        "band": "critical",
        "priority": 95.0,
        "verdict": "critical verdict",
        "tier": "imported-and-called",
        "in_kev": True,
    }


def test_scan_summary_counts_tiers_and_actionable() -> None:
    summary = scan_summary(_report(), "/proj")
    assert summary["scanned_path"] == "/proj"
    assert summary["total"] == 3
    assert summary["by_tier"] == {
        "imported-and-called": 1,
        "imported": 1,
        "dynamic-unknown": 0,
        "not-imported": 1,
        "unknown": 0,
    }
    # not-imported is the only confidently-safe tier, so 2 of 3 are actionable.
    assert summary["actionable"] == 2
    assert len(summary["findings"]) == 3


def test_filter_by_tier() -> None:
    result = filter_findings(_report(), tier="imported")
    assert result["count"] == 1
    assert result["findings"][0]["package"] == "flask"


def test_filter_by_band_and_kev() -> None:
    assert filter_findings(_report(), band="critical")["count"] == 1
    assert filter_findings(_report(), in_kev=True)["count"] == 1
    assert filter_findings(_report(), in_kev=False)["count"] == 2


def test_filter_by_package_is_case_insensitive() -> None:
    assert filter_findings(_report(), package="JINJA2")["count"] == 1


def test_filter_min_score() -> None:
    result = filter_findings(_report(), min_score=50)
    assert {row["package"] for row in result["findings"]} == {"jinja2", "requests"}


def test_filter_limit_reports_total_matched() -> None:
    result = filter_findings(_report(), limit=1)
    assert result["count"] == 1
    assert result["total_matched"] == 3


def test_filter_unknown_tier_raises() -> None:
    with pytest.raises(McpToolError, match="unknown tier"):
        filter_findings(_report(), tier="bogus")


def test_filter_unknown_band_raises() -> None:
    with pytest.raises(McpToolError, match="unknown band"):
        filter_findings(_report(), band="severe")


def test_get_finding_by_cve_alias() -> None:
    detail = get_finding_detail(_report(), "cve-2019-10906")
    assert detail["finding_id"] == "jinja2:GHSA-jinja"
    assert detail["reachability"]["call_paths"][0].startswith("main -> render")
    assert detail["reachability"]["evidence"] == [{"file": "app.py", "line": 1}]


def test_get_finding_by_finding_id() -> None:
    detail = get_finding_detail(_report(), "flask:PYSEC-2018-1")
    assert detail["dependency"]["name"] == "flask"


def test_get_finding_not_found_raises() -> None:
    with pytest.raises(FindingNotFoundError):
        get_finding_detail(_report(), "CVE-0000-0000")


def test_get_finding_ambiguous_raises() -> None:
    # Two findings share an injected duplicate token to force ambiguity.
    report = _report()
    report["findings"][1]["advisory"]["aliases"].append("CVE-2019-10906")
    with pytest.raises(AmbiguousFindingError, match="multiple findings"):
        get_finding_detail(report, "CVE-2019-10906")


def test_explain_facts_are_deterministic_engine_truth() -> None:
    facts = explain_finding_facts(_report(), "jinja2:GHSA-jinja")
    assert facts["priority"] == {
        "score": 95.0,
        "band": "critical",
        "verdict": "critical verdict",
        "rationale": "because reasons",
    }
    assert facts["reachability"]["tier"] == "imported-and-called"
    # The tier meaning text is surfaced so the client can explain *why* it matters.
    assert "call path" in facts["reachability"]["meaning"].lower()
    assert facts["exploitability"]["in_kev"] is True
    joined = " ".join(facts["facts"])
    assert "CISA KEV" in joined
    assert "Call path: main -> render" in joined
    assert "fix is available" in joined


def test_explain_no_fix_states_it() -> None:
    facts = explain_finding_facts(_report(), "requests:GHSA-req")
    assert facts["fix"]["has_fix"] is False
    assert any("No fixed version" in fact for fact in facts["facts"])
    # not-imported tier meaning calls out it is the confidently-safe tier.
    assert "safe" in facts["reachability"]["meaning"].lower()
