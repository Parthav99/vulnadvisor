# File: src/vulnadvisor/mcp/server.py
"""The MCP stdio server wiring (the only module that imports the third-party ``mcp`` SDK).

Registers four tools over a :class:`~vulnadvisor.mcp.session.McpSession` and runs them on a stdio
transport. The production session scans with the same engine defaults the CLI uses (incremental
cache, type-informed resolution, framework entry points) but with no LLM explanation — the MCP
contract is deterministic engine truth; an editor agent supplies the wording.

This module is imported lazily by the ``vulnadvisor mcp`` CLI command, so a user without the
optional ``[mcp]`` extra gets a clear install hint instead of an import traceback.
"""

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from vulnadvisor.cli.pipeline import ScanReport, scan_project
from vulnadvisor.mcp.session import McpSession
from vulnadvisor.mcp.state import ReportStore, default_report_store_path
from vulnadvisor.store.analysis_cache import AnalysisCache, default_analysis_cache_path

__all__ = ["build_server", "run_default_scan", "run_stdio"]

_INSTRUCTIONS = (
    "VulnAdvisor triages Python dependency vulnerabilities by whether they are actually reachable "
    "from this project's code, ranked by a deterministic priority engine. Call scan(path) first, "
    "then list_findings to triage, get_finding for full evidence (including the call path), and "
    "explain_finding for the engine's deterministic facts. Reachability tiers, in order of "
    "concern: imported-and-called > imported > dynamic-unknown > not-imported (the only "
    "confidently-safe tier). Priority is computed by the engine and is authoritative — never "
    "re-rank it; dynamic-unknown is never safe."
)


def run_default_scan(path: Path) -> ScanReport:
    """Scan ``path`` with production engine defaults (no LLM; that is the client's job)."""
    # Imported here to keep the heavy CLI builders out of module import time.
    from vulnadvisor.cli.main import (
        build_matcher,
        build_symbol_names_for,
        build_type_resolver,
    )

    analysis_cache = AnalysisCache(default_analysis_cache_path())
    try:
        return scan_project(
            path,
            build_matcher(),
            symbol_names_for=build_symbol_names_for(),
            analysis_cache=analysis_cache,
            resolver=build_type_resolver(),
            frameworks=None,
        )
    finally:
        analysis_cache.close()


def build_session() -> McpSession:
    """Build the production session: a default scan over a per-user persistent report store."""
    from vulnadvisor.cli.main import _resolve_version

    store = ReportStore(default_report_store_path())
    return McpSession(run_default_scan, store, tool_version=_resolve_version())


def build_server(session: McpSession) -> FastMCP:
    """Register the four triage tools over ``session`` and return the FastMCP server."""
    server = FastMCP("vulnadvisor", instructions=_INSTRUCTIONS)
    # FastMCP defaults the advertised server version to the MCP SDK's version; report VulnAdvisor's
    # own version to clients instead (FastMCP exposes no constructor arg for it in this SDK).
    server._mcp_server.version = session.tool_version

    @server.tool(
        description=(
            "Scan a Python project directory (or manifest file) for vulnerable dependencies and "
            "rank them by reachability + deterministic priority. Returns counts and a compact list "
            "of every finding; this becomes the report the other tools read."
        )
    )
    def scan(path: str) -> dict[str, Any]:
        return session.run_scan(path)

    @server.tool(
        description=(
            "List findings from the most recent scan as compact rows, newest scan, priority order. "
            "All filters are optional: tier (imported-and-called|imported|dynamic-unknown|"
            "not-imported), band (critical|high|medium|low|info), package name, min_score (0-100), "
            "in_kev (true|false), limit."
        )
    )
    def list_findings(
        tier: str | None = None,
        band: str | None = None,
        package: str | None = None,
        min_score: float | None = None,
        in_kev: bool | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        return session.list_findings(
            tier=tier,
            band=band,
            package=package,
            min_score=min_score,
            in_kev=in_kev,
            limit=limit,
        )

    @server.tool(
        description=(
            "Get the full evidence for one finding: advisory, deterministic score, reachability "
            "tier with import sites and the concrete call path, and the fix. Accepts a finding_id, "
            "advisory id, display id (CVE-XXXX-YYYY), or alias from a list_findings result."
        )
    )
    def get_finding(id: str) -> dict[str, Any]:
        return session.get_finding(id)

    @server.tool(
        description=(
            "Return the deterministic facts behind one finding (priority, reachability tier and "
            "its meaning, exploitability signals, fix) for you to explain in your own words. The "
            "engine owns the truth and the ranking; you own the wording."
        )
    )
    def explain_finding(id: str) -> dict[str, Any]:
        return session.explain_finding(id)

    return server


def run_stdio() -> None:
    """Build the production server and serve it over stdio (blocks until the client disconnects)."""
    server = build_server(build_session())
    server.run()
