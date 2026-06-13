# File: src/vulnadvisor/mcp/state.py
"""Persist the most recent scan report so a fresh MCP session can triage it offline.

The MCP server keeps the current report in memory for the life of a session, but it also writes it
to a single-row SQLite table here. That lets a *new* ``vulnadvisor mcp`` process answer
``list_findings`` / ``get_finding`` / ``explain_finding`` against the last scan without re-running
it — matching the task's "SQLite cache + last report", and staying fully offline.

A corrupt or absent row simply loads as ``None`` (the caller then asks the user to run a scan); a
malformed payload never raises into a tool call.
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["ReportStore", "StoredReport", "default_report_store_path"]


@dataclass(frozen=True)
class StoredReport:
    """A persisted scan report: the JSON report document plus where and when it was produced."""

    report: dict[str, Any]
    scanned_path: str
    saved_at: float


def default_report_store_path() -> Path:
    """Return the local last-report database path, creating its parent directory if needed.

    Honors ``VULNADVISOR_CACHE`` (a directory or file path) when set; otherwise uses a per-user
    cache directory. Like every other VulnAdvisor store, it stays on the user's machine.
    """
    override = os.environ.get("VULNADVISOR_CACHE")
    if override:
        candidate = Path(override)
        directory = candidate if candidate.is_dir() or candidate.suffix == "" else candidate.parent
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "mcp_report.sqlite"
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    base = Path(root) if root else Path.home() / ".cache"
    directory = base / "vulnadvisor"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "mcp_report.sqlite"


# A single, replace-in-place row (id is pinned to 1): we only ever keep the *latest* scan.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS last_report (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value TEXT NOT NULL,
    scanned_path TEXT NOT NULL,
    saved_at REAL NOT NULL
)
"""


class ReportStore:
    """A SQLite-backed store of the single most-recent scan report."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        """Open (or create) the store at ``path`` (``:memory:`` for an ephemeral one)."""
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def save(self, report: dict[str, Any], scanned_path: str, *, now: float | None = None) -> float:
        """Persist ``report`` as the latest scan; returns the timestamp it was saved at."""
        moment = time.time() if now is None else now
        self._conn.execute(
            "INSERT OR REPLACE INTO last_report (id, value, scanned_path, saved_at) "
            "VALUES (1, ?, ?, ?)",
            (json.dumps(report), scanned_path, moment),
        )
        self._conn.commit()
        return moment

    def load(self) -> StoredReport | None:
        """Return the last persisted report, or ``None`` if absent or corrupt (never raises)."""
        row = self._conn.execute(
            "SELECT value, scanned_path, saved_at FROM last_report WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        try:
            report = json.loads(row[0])
        except (json.JSONDecodeError, TypeError, ValueError):
            # Defensive: a malformed payload must never crash a tool call — treat it as "no scan".
            return None
        if not isinstance(report, dict):
            return None
        return StoredReport(report=report, scanned_path=str(row[1]), saved_at=float(row[2]))

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
