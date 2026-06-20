# File: src/vulnadvisor/store/file_facts.py
"""Content-addressed cache of per-file *analysis facts* — the substrate for incremental scans.

A scan's expensive work is a pure function of two inputs: the file's **content** and the **rule
pack** the analysis runs under. This cache stores, per file, the parsed facts a scan needs —
imports/definitions (the import graph), located sinks, and per-function taint summaries — under a
key derived from the file's content hash, the analyzer version, **and the rule-pack hash**. A repeat
scan with no code or rule change re-parses nothing; editing one file changes only that file's key;
editing the rule pack changes the rule-pack-hash component of *every* key, busting the whole cache.

The cache is a pure speed optimization and **soundness-neutral**: a missing, corrupt, or
schema-mismatched entry is treated as a miss and the file is re-analyzed. Because invalidation is by
content/rule hash — never a timer — a stale entry can never mask a current finding. See
``docs/incremental-design.md`` for the full design and the correctness obligation.

This module is the *store* (Task 22.1): the data models, the key scheme, and the SQLite layer. The
incremental scanner that fills these facts and recomputes a changed file's dependent closure is
Task 22.2; deterministic parallel population is Task 22.3.
"""

import sqlite3
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnadvisor.model.imports import FileAnalysis
from vulnadvisor.sast.model import SinkHit
from vulnadvisor.store.analysis_cache import content_hash, default_analysis_cache_path

__all__ = [
    "FileFacts",
    "FileFactsCache",
    "FunctionTaintSummary",
    "default_facts_cache_path",
    "facts_cache_key",
]


# Bumped whenever the *shape* of the cached facts changes (a new field on FileFacts, a changed
# SinkHit/FileAnalysis schema, or a change to how summaries are computed) so entries written by an
# older analyzer are treated as misses rather than deserialized into stale, possibly-less-
# conservative results. This is the "analyzer version" component of the key; the rule-pack hash is
# the orthogonal "rules changed" component (see facts_cache_key).
_FACTS_VERSION = "1"


class FunctionTaintSummary(BaseModel):
    """A reusable per-function taint summary: does a tainted parameter taint this function's result?

    The demand-driven taint engine (``sast/taint.py``) computes these to keep cross-module search
    tractable — once a function's behavior under a set of tainted parameters is known, callers reuse
    it instead of re-descending. Caching the summary lets an incremental scan (Task 22.2) skip
    re-deriving a function whose file is unchanged. A function identified project-wide by
    ``module`` + ``qualname``, analyzed with the named parameters tainted.

    Attributes:
        module: The importable dotted module name (e.g. ``"pkg.helpers"``).
        qualname: The function's qualified name within the module (e.g. ``"Service.handle"``).
        tainted_params: The parameter names assumed tainted for this summary (order-insensitive;
            stored sorted so the record is canonical).
        taints_return: Whether a value flowing out of the function's ``return`` is tainted.
        sink_lines: 1-based line numbers of sinks this function reaches under the tainted params
            (evidence anchors; conservative — present does not by itself prove a confirmed flow).
    """

    model_config = ConfigDict(frozen=True)

    module: str
    qualname: str
    tainted_params: tuple[str, ...]
    taints_return: bool
    sink_lines: tuple[int, ...] = ()


class FileFacts(BaseModel):
    """The complete cached static-analysis facts for a single file.

    Bundles the three fact kinds a scan needs from a file so one cache hit serves the whole scan:
    the :class:`FileAnalysis` (imports, dynamic sites, parse errors — feeds the import/call graph),
    the located :class:`SinkHit`s (the intra-procedural SAST baseline), and any
    :class:`FunctionTaintSummary` records. ``taint_summaries`` is empty for the pure per-file
    builder (Task 22.1); the demand-driven engine (Task 22.2) fills it once cross-module summaries
    are proven, under the same content+rule key, so a cached summary is always consistent with the
    file and rules it was computed under.
    """

    model_config = ConfigDict(frozen=True)

    rel: str
    analysis: FileAnalysis
    sinks: tuple[SinkHit, ...] = ()
    taint_summaries: tuple[FunctionTaintSummary, ...] = ()


def facts_cache_key(rel: str, text: str, rule_pack_hash: str) -> str:
    r"""Return the cache key for the file at project-relative ``rel`` with content ``text``.

    The key composes three independent invalidation signals (``docs/incremental-design.md``):

    * the **analyzer version** (``_FACTS_VERSION``) — busts everything when the fact schema changes;
    * the **rule-pack hash** (from :func:`vulnadvisor.sast.rules.rule_pack_hash`) — busts everything
      when any sink/sanitizer/secret rule changes, because the sinks and summaries depend on it;
    * the file's **content hash** — invalidates exactly the edited file, and is why two
      identical-content files do not collide only because ``rel`` is also in the key (a
      :class:`FileFacts` embeds ``rel``, so distinct files must not share an entry).

    ``\x00`` (NUL) separates the parts so no concatenation ambiguity can collide two inputs.
    """
    return f"{_FACTS_VERSION}\x00{rule_pack_hash}\x00{rel}\x00{content_hash(text)}"


def default_facts_cache_path() -> Path:
    """Return the local per-file facts cache path (sibling to the analysis cache, distinct file).

    Reuses the analysis cache's directory resolution (honoring ``VULNADVISOR_CACHE``) but a separate
    database file, so the richer facts schema versions independently of the import-only cache. The
    cache stays on the user's machine — VulnAdvisor never phones home.
    """
    return default_analysis_cache_path().with_name("file_facts.sqlite")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_facts (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


class FileFactsCache:
    """A SQLite-backed, content-and-rule-addressed store of :class:`FileFacts`.

    Keys come from :func:`facts_cache_key`. ``hits`` and ``misses`` count lookups so callers (and
    tests) can prove an unchanged file under unchanged rules was not re-analyzed. A stored value
    that fails to deserialize — a corrupt row, or one written under an incompatible schema — is
    treated as a miss; the cache never raises into a scan, and a re-analysis overwrites it.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        """Open (or create) the facts cache at ``path`` (``:memory:`` for an ephemeral one)."""
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> FileFacts | None:
        """Return the cached facts for ``key``, or ``None`` on a miss or corrupt entry."""
        row = self._conn.execute("SELECT value FROM file_facts WHERE key = ?", (key,)).fetchone()
        if row is None:
            self.misses += 1
            return None
        try:
            facts = FileFacts.model_validate_json(str(row[0]))
        except ValidationError:
            # Defensive: a malformed/old-schema entry must never crash a scan — re-analyze instead.
            self.misses += 1
            return None
        self.hits += 1
        return facts

    def set(self, key: str, facts: FileFacts) -> None:
        """Store ``facts`` under ``key`` (idempotent; an existing entry is replaced)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO file_facts (key, value) VALUES (?, ?)",
            (key, facts.model_dump_json()),
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
