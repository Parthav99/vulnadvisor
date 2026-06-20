# File: src/vulnadvisor/sast/facts.py
"""Build the per-file analysis facts that the incremental cache stores (Task 22.1).

A single pure function turns one file's text into a :class:`FileFacts` record: the import-graph
:class:`FileAnalysis` (reusing the import analyzer) and the intra-procedural sinks (reusing the sink
matcher). Both inputs — the source text and the rule pack — are explicit, so the result is a
deterministic function of content and rules, exactly matching the cache key.

Per-function taint summaries are left empty here: they are a *demand-driven, cross-module* fact that
the taint engine proves while walking the call graph (Task 22.2 fills them into ``FileFacts`` under
the same content+rule key). Keeping this builder summary-free makes it pure and single-file, with no
whole-project graph dependency — the right granularity for the cache's per-file unit.
"""

from vulnadvisor.callgraph.import_graph import _analyze_source
from vulnadvisor.sast.sinks import find_sinks_in_source
from vulnadvisor.store.file_facts import FileFacts

__all__ = ["build_file_facts"]


def build_file_facts(rel: str, text: str) -> FileFacts:
    """Return the per-file :class:`FileFacts` for project-relative ``rel`` with content ``text``.

    Pure and single-file: parses ``text`` once for imports/dynamic sites and once for sinks, with no
    I/O and no cross-file knowledge. A syntax error is captured in the embedded
    :class:`~vulnadvisor.model.imports.FileAnalysis` (``parse_error``) rather than raised, so a
    malformed file still produces a valid, cacheable record.
    """
    analysis = _analyze_source(text, rel, rel)
    sinks = find_sinks_in_source(text, rel)
    return FileFacts(rel=rel, analysis=analysis, sinks=sinks)
