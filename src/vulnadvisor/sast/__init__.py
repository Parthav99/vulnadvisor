"""SAST: reachability-aware first-party Python taint engine (M16).

Finds vulnerabilities in the user's *own* code — SQLi, command/code injection, unsafe
deserialization, path traversal, SSRF, hardcoded secrets — ranked by the same deterministic engine
and reported with the same tiers-and-evidence as the dependency reachability engine. See
``docs/sast-design.md`` for the architecture.

Task 16.2 ships the intra-procedural sink detector (``rules`` + ``sinks``); Task 16.3 proves the
source->sink flow over the existing call graph.
"""

from vulnadvisor.sast.model import SastTier, SinkHit
from vulnadvisor.sast.sinks import find_sinks, find_sinks_in_source

__all__ = ["SastTier", "SinkHit", "find_sinks", "find_sinks_in_source"]
