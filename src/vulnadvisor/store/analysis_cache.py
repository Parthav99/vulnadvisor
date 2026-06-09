# File: src/vulnadvisor/store/analysis_cache.py
"""Content-addressed cache of per-file static analysis, for fast CI re-runs.

The expensive part of a scan is parsing every ``.py`` file and walking its AST. That work is a
pure function of the file's *content*: if the bytes are unchanged, the analysis is unchanged.
This cache stores each file's :class:`FileAnalysis` under a key derived from its content hash, so
a repeat scan with no code change re-parses nothing, and editing one file invalidates only that
one file's entry (its hash changes; every other key still hits).

The cache is purely a speed optimization and is *soundness-neutral*: a corrupt or missing entry
simply falls back to re-analyzing the file. Content hashing — not a timer — is the only
invalidation, so a stale entry can never mask a real, current finding.
"""

import hashlib
import os
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from vulnadvisor.model.imports import FileAnalysis

__all__ = [
    "AnalysisCache",
    "cache_key",
    "content_hash",
    "default_analysis_cache_path",
]


def content_hash(text: str) -> str:
    """Return the SHA-256 hex digest of ``text`` (the file's content fingerprint)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Bumped whenever the static-analysis schema changes (new fields / classification), so that
# entries written by an older analyzer are treated as misses and re-analyzed rather than
# deserialized into stale, possibly-less-conservative results.
_ANALYSIS_VERSION = "4"


def cache_key(rel: str, text: str) -> str:
    """Return the cache key for a file at project-relative ``rel`` with the given ``text``.

    The relative path is part of the key because a :class:`FileAnalysis` embeds it (so two
    identical-content files — e.g. empty ``__init__.py`` — must not share an entry). The content
    hash makes any edit produce a fresh key, invalidating exactly that file; the analysis-version
    prefix invalidates every entry when the analyzer itself changes.
    """
    return f"{_ANALYSIS_VERSION}\x00{rel}\x00{content_hash(text)}"


def default_analysis_cache_path() -> Path:
    """Return the local per-file-analysis cache path, creating its parent directory if needed.

    Honors ``VULNADVISOR_CACHE`` (a directory or file path) when set; otherwise uses a per-user
    cache directory. The cache stays on the user's machine — VulnAdvisor never phones home.
    """
    override = os.environ.get("VULNADVISOR_CACHE")
    if override:
        candidate = Path(override)
        directory = candidate if candidate.is_dir() or candidate.suffix == "" else candidate.parent
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "analysis.sqlite"
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    base = Path(root) if root else Path.home() / ".cache"
    directory = base / "vulnadvisor"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "analysis.sqlite"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_analysis (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


class AnalysisCache:
    """A SQLite-backed, content-addressed store of :class:`FileAnalysis` results.

    Keys come from :func:`cache_key` (relative path + content hash). ``hits`` and ``misses`` count
    lookups so callers (and tests) can prove that an unchanged file was not re-analyzed. A stored
    value that fails to deserialize is treated as a miss — the cache never raises into a scan.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        """Open (or create) the analysis cache at ``path`` (``:memory:`` for an ephemeral one)."""
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> FileAnalysis | None:
        """Return the cached analysis for ``key``, or ``None`` on a miss or corrupt entry."""
        row = self._conn.execute("SELECT value FROM file_analysis WHERE key = ?", (key,)).fetchone()
        if row is None:
            self.misses += 1
            return None
        try:
            analysis = FileAnalysis.model_validate_json(str(row[0]))
        except ValidationError:
            # Defensive: a malformed entry must never crash a scan — re-analyze instead.
            self.misses += 1
            return None
        self.hits += 1
        return analysis

    def set(self, key: str, analysis: FileAnalysis) -> None:
        """Store ``analysis`` under ``key`` (idempotent; an existing entry is replaced)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO file_analysis (key, value) VALUES (?, ?)",
            (key, analysis.model_dump_json()),
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
