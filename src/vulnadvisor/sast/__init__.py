"""SAST: reachability-aware first-party Python taint engine (M16).

Finds vulnerabilities in the user's *own* code — SQLi, command/code injection, unsafe
deserialization, path traversal, SSRF, hardcoded secrets — ranked by the same deterministic engine
and reported with the same tiers-and-evidence as the dependency reachability engine. See
``docs/sast-design.md`` for the architecture.

Task 16.2 ships the intra-procedural sink detector (``rules`` + ``sinks``); Task 16.3 proves the
source->sink flow over the existing call graph (``taint``), escalating sinks tied to a real source
to ``CONFIRMED_FLOW`` / ``DYNAMIC_UNKNOWN`` with an evidence path.
"""

from vulnadvisor.sast.model import SastFinding, SastTier, SinkHit, tier_concern
from vulnadvisor.sast.sinks import find_sinks, find_sinks_in_source
from vulnadvisor.sast.taint import analyze_source, analyze_taint

__all__ = [
    "SastFinding",
    "SastTier",
    "SinkHit",
    "analyze_source",
    "analyze_taint",
    "find_sinks",
    "find_sinks_in_source",
    "tier_concern",
]
