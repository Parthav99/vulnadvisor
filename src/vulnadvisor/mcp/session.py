# File: src/vulnadvisor/mcp/session.py
"""The stateful glue between MCP tool calls and the scan engine + last-report store.

A session holds the *current* report in memory once a scan runs, and persists it to a
:class:`~vulnadvisor.mcp.state.ReportStore`. Read tools resolve the report from memory first, then
fall back to the persisted last scan — so a freshly-started server can still triage the most recent
scan offline. The scan function is injected, so the whole session is exercisable in tests with an
offline matcher and an in-memory store (no network, no MCP SDK).
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from vulnadvisor.cli.pipeline import ScanReport
from vulnadvisor.mcp.state import ReportStore, StoredReport
from vulnadvisor.mcp.tools import (
    NoScanError,
    explain_finding_facts,
    filter_findings,
    get_finding_detail,
    scan_summary,
)
from vulnadvisor.output.json_report import build_report

__all__ = ["McpSession", "ScanFn"]

ScanFn = Callable[[Path], ScanReport]


class McpSession:
    """Holds the current/last scan report and serves the four MCP tools against it."""

    def __init__(self, scan_fn: ScanFn, store: ReportStore, *, tool_version: str) -> None:
        """Wire a session to its ``scan_fn``, persistent ``store``, and the ``tool_version``."""
        self._scan_fn = scan_fn
        self._store = store
        self._tool_version = tool_version
        self._current: StoredReport | None = None

    @property
    def tool_version(self) -> str:
        """The VulnAdvisor version reported in reports and as the MCP server version."""
        return self._tool_version

    def run_scan(self, path: str) -> dict[str, Any]:
        """Scan ``path``, persist the report as the latest, and return the scan summary."""
        target = Path(path)
        if not target.exists():
            raise NoScanError(f"path does not exist: {path}")
        report = self._scan_fn(target)
        document = build_report(
            report.findings, report.degraded_sources, tool_version=self._tool_version
        )
        scanned_path = str(target.resolve())
        saved_at = self._store.save(document, scanned_path)
        self._current = StoredReport(report=document, scanned_path=scanned_path, saved_at=saved_at)
        return scan_summary(document, scanned_path)

    def _report(self) -> StoredReport:
        """Return the in-memory report, else the last persisted one, else raise ``NoScanError``."""
        if self._current is not None:
            return self._current
        loaded = self._store.load()
        if loaded is None:
            raise NoScanError("no scan results yet; call scan(path) first")
        self._current = loaded
        return loaded

    def list_findings(
        self,
        *,
        tier: str | None = None,
        band: str | None = None,
        package: str | None = None,
        min_score: float | None = None,
        in_kev: bool | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Filtered compact rows from the current/last report (see :func:`filter_findings`)."""
        stored = self._report()
        result = filter_findings(
            stored.report,
            tier=tier,
            band=band,
            package=package,
            min_score=min_score,
            in_kev=in_kev,
            limit=limit,
        )
        result["scanned_path"] = stored.scanned_path
        return result

    def get_finding(self, identifier: str) -> dict[str, Any]:
        """Full evidence + call path for one finding in the current/last report."""
        return get_finding_detail(self._report().report, identifier)

    def explain_finding(self, identifier: str) -> dict[str, Any]:
        """Deterministic facts for one finding (the client's LLM supplies the wording)."""
        return explain_finding_facts(self._report().report, identifier)
