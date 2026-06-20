"""MCP server tests: protocol round-trip, last-report persistence, lean core wheel."""

import json
from collections.abc import Callable
from importlib.metadata import requires
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult
from packaging.requirements import Requirement

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.mcp.server import build_server
from vulnadvisor.mcp.session import McpSession
from vulnadvisor.mcp.state import ReportStore
from vulnadvisor.mcp.tools import NoScanError


def _project(tmp_path: Path) -> Path:
    """A tiny project that imports jinja2, so the seeded advisory is reachable (IMPORTED)."""
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import jinja2\n", encoding="utf-8")
    return tmp_path


def _session(matcher: AdvisoryMatcher, store: ReportStore | None = None) -> McpSession:
    """A session whose scan runs offline against the recorded-fixture matcher."""
    return McpSession(
        lambda path: scan_project(path, matcher),
        store if store is not None else ReportStore(),
        tool_version="9.9.9",
    )


def _payload(result: CallToolResult) -> dict[str, Any]:
    """Parse a tool result's JSON text body, asserting it is not an error."""
    text = result.content[0].text if result.content else ""  # type: ignore[union-attr]
    assert not result.isError, text
    return json.loads(text)


# --- core wheel stays lean -------------------------------------------------------------------


def test_core_wheel_runtime_deps_unchanged() -> None:
    """The published wheel still has exactly three runtime deps; mcp/semgrep are extra-only.

    Both ``mcp`` (the MCP server, 15.3) and ``semgrep`` (the fusion adapter, 21.2) are optional
    extras invoked out-of-process — they must never leak into the core runtime dependency set.
    """
    reqs = requires("vulnadvisor") or []
    runtime: set[str] = set()
    extra_only: set[str] = set()
    for raw in reqs:
        req = Requirement(raw)
        if "extra ==" in raw:  # gated behind an optional extra, not a core runtime dep
            extra_only.add(req.name)
            continue
        runtime.add(req.name)
    assert runtime == {"packaging", "pydantic", "typer"}
    assert "mcp" in extra_only, "mcp must be declared only under the [mcp] extra"
    assert "semgrep" in extra_only, "semgrep must be declared only under the [semgrep] extra"


def test_server_reports_vulnadvisor_version(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    """The advertised MCP server version is VulnAdvisor's, not the MCP SDK's."""
    server = build_server(_session(fake_matcher()))
    assert server.name == "vulnadvisor"
    assert server._mcp_server.version == "9.9.9"


# --- protocol round-trip ---------------------------------------------------------------------


async def test_mcp_roundtrip(tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]) -> None:
    project = _project(tmp_path)
    server = build_server(_session(fake_matcher()))

    async with create_connected_server_and_client_session(server) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools.tools} == {
            "scan",
            "list_findings",
            "get_finding",
            "explain_finding",
        }
        # Every tool advertises a JSON-Schema input contract (schema-valid surface).
        scan_tool = next(t for t in tools.tools if t.name == "scan")
        assert scan_tool.inputSchema["properties"]["path"]["type"] == "string"

        scanned = _payload(await client.call_tool("scan", {"path": str(project)}))
        assert scanned["total"] == 1
        assert scanned["scanned_path"] == str(project.resolve())
        row = scanned["findings"][0]
        assert row["package"] == "jinja2"
        assert row["display_id"] == "CVE-2019-10906"
        assert row["in_kev"] is True
        assert row["tier"] == "imported"

        listed = _payload(await client.call_tool("list_findings", {"tier": "imported"}))
        assert listed["count"] == 1
        assert listed["findings"][0]["package"] == "jinja2"

        detail = _payload(await client.call_tool("get_finding", {"id": "CVE-2019-10906"}))
        assert detail["finding_id"] == "jinja2:GHSA-462w-v97r-4m45"
        assert detail["advisory"]["display_id"] == "CVE-2019-10906"
        assert detail["reachability"]["tier"] == "imported"
        assert any(ev["file"] == "app.py" for ev in detail["reachability"]["evidence"])

        facts = _payload(await client.call_tool("explain_finding", {"id": "jinja2"}))
        assert facts["priority"]["band"] == "critical"
        assert facts["reachability"]["meaning"]
        assert facts["exploitability"]["in_kev"] is True


async def test_list_findings_before_scan_is_a_tool_error(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    server = build_server(_session(fake_matcher()))
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("list_findings", {})
        assert result.isError
        assert "scan(path)" in result.content[0].text  # type: ignore[union-attr]


async def test_unknown_tier_filter_is_a_tool_error(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    server = build_server(_session(fake_matcher()))
    async with create_connected_server_and_client_session(server) as client:
        await client.call_tool("scan", {"path": str(_project(tmp_path))})
        result = await client.call_tool("list_findings", {"tier": "bogus"})
        assert result.isError
        assert "unknown tier" in result.content[0].text  # type: ignore[union-attr]


# --- last-report persistence (SQLite) --------------------------------------------------------


def test_last_report_persists_across_sessions(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    """A second session reads the last scan from the SQLite store without re-scanning."""
    db = tmp_path / "report.sqlite"
    project = _project(tmp_path)

    writer_store = ReportStore(db)
    _session(fake_matcher(), writer_store).run_scan(str(project))
    writer_store.close()

    # A brand-new session (no scan called) resolves the persisted report.
    reader_store = ReportStore(db)
    reader = _session(fake_matcher(), reader_store)
    listed = reader.list_findings()
    assert listed["count"] == 1
    assert listed["findings"][0]["package"] == "jinja2"
    detail = reader.get_finding("CVE-2019-10906")
    assert detail["finding_id"] == "jinja2:GHSA-462w-v97r-4m45"
    reader_store.close()


def test_session_without_scan_or_store_raises(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    session = _session(fake_matcher())
    with pytest.raises(NoScanError):
        session.list_findings()


def test_corrupt_store_row_degrades_to_no_scan(tmp_path: Path) -> None:
    """A malformed persisted payload loads as 'no scan', never raising into a tool call."""
    import sqlite3

    db = tmp_path / "report.sqlite"
    ReportStore(db).close()  # create the schema
    # Write a non-JSON payload directly, simulating a corrupt row.
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT OR REPLACE INTO last_report (id, value, scanned_path, saved_at) "
        "VALUES (1, ?, ?, ?)",
        ("{not json", "/p", 0.0),
    )
    conn.commit()
    conn.close()
    assert ReportStore(db).load() is None
