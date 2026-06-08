"""A small TTL'd key-value cache backed by SQLite.

Used to avoid re-fetching advisory/risk data from public APIs on every run. Values are opaque
strings (callers store JSON). ``now`` is injectable so expiry is deterministic in tests.
"""

import os
import sqlite3
import time
from pathlib import Path

__all__ = ["SqliteCache", "default_cache_path"]


def default_cache_path() -> Path:
    """Return the local cache database path, creating its parent directory if needed.

    Honors ``VULNADVISOR_CACHE`` (a full file path) when set; otherwise uses a per-user cache
    directory. The cache stays on the user's machine — VulnAdvisor never phones home.
    """
    override = os.environ.get("VULNADVISOR_CACHE")
    if override:
        path = Path(override)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    base = Path(root) if root else Path.home() / ".cache"
    directory = base / "vulnadvisor"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "cache.sqlite"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    ttl REAL NOT NULL
)
"""


class SqliteCache:
    """A persistent key/value store with per-entry time-to-live.

    A negative ``ttl`` means the entry never expires.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        """Open (or create) the cache database at ``path`` (``:memory:`` for an ephemeral one)."""
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def get(self, key: str, *, now: float | None = None) -> str | None:
        """Return the cached value for ``key``, or ``None`` if absent or expired."""
        moment = time.time() if now is None else now
        row = self._conn.execute(
            "SELECT value, fetched_at, ttl FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        value, fetched_at, ttl = str(row[0]), float(row[1]), float(row[2])
        if ttl >= 0 and (moment - fetched_at) > ttl:
            self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn.commit()
            return None
        return value

    def set(self, key: str, value: str, ttl: float, *, now: float | None = None) -> None:
        """Store ``value`` under ``key`` with a time-to-live of ``ttl`` seconds."""
        moment = time.time() if now is None else now
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, value, fetched_at, ttl) VALUES (?, ?, ?, ?)",
            (key, value, moment, ttl),
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
