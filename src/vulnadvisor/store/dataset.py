"""Persistent store for the advisory -> vulnerable-symbol dataset (the moat).

Each advisory's :class:`SymbolExtraction` is stored as one row keyed by ``advisory_id`` (the
primary key), so lookups are O(1) and writes are idempotent (``INSERT OR REPLACE``). The payload
is the extraction serialized as JSON, so the schema stays stable as the model evolves.
"""

import os
import sqlite3
import time
from pathlib import Path

from vulnadvisor.model.symbols import SymbolExtraction

__all__ = ["SymbolDataset", "default_dataset_path"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS symbol_extractions (
    advisory_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at REAL NOT NULL
)
"""


def default_dataset_path() -> Path:
    """Return the local symbol-dataset path, creating its parent directory if needed.

    Honors ``VULNADVISOR_DATASET`` (a full file path); otherwise uses the per-user data dir.
    """
    override = os.environ.get("VULNADVISOR_DATASET")
    if override:
        path = Path(override)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    base = Path(root) if root else Path.home() / ".local" / "share"
    directory = base / "vulnadvisor"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "symbols.sqlite"


class SymbolDataset:
    """A SQLite-backed store of ``advisory_id -> SymbolExtraction``."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        """Open (or create) the dataset database at ``path``."""
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def upsert(self, extraction: SymbolExtraction, *, now: float | None = None) -> None:
        """Insert or replace the extraction for its advisory (idempotent by advisory id)."""
        moment = time.time() if now is None else now
        self._conn.execute(
            "INSERT OR REPLACE INTO symbol_extractions (advisory_id, payload, updated_at) "
            "VALUES (?, ?, ?)",
            (extraction.advisory_id, extraction.model_dump_json(), moment),
        )
        self._conn.commit()

    def get(self, advisory_id: str) -> SymbolExtraction | None:
        """Return the stored extraction for ``advisory_id``, or ``None`` if absent."""
        row = self._conn.execute(
            "SELECT payload FROM symbol_extractions WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()
        if row is None:
            return None
        return SymbolExtraction.model_validate_json(str(row[0]))

    def has(self, advisory_id: str) -> bool:
        """Return whether an extraction is stored for ``advisory_id``."""
        row = self._conn.execute(
            "SELECT 1 FROM symbol_extractions WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()
        return row is not None

    def count(self) -> int:
        """Return the number of stored advisories."""
        row = self._conn.execute("SELECT COUNT(*) FROM symbol_extractions").fetchone()
        return int(row[0])

    def advisory_ids(self) -> list[str]:
        """Return all stored advisory ids, sorted."""
        rows = self._conn.execute(
            "SELECT advisory_id FROM symbol_extractions ORDER BY advisory_id"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
