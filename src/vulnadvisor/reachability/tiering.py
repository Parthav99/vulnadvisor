"""Assign a reachability tier to a dependency given the project's import graph.

This is the security-critical step: a wrong "not imported" is a false negative that can hide a
real breach. The rules are therefore conservative — we only ever return ``NOT_IMPORTED`` when we
are confident, and escalate to ``DYNAMIC_UNKNOWN`` whenever anything could be hiding usage.

Decision order for a dependency:

1. **IMPORTED** — one of its import names appears as an absolute import root in the code
   (evidence: the import sites, file:line).
2. **DYNAMIC_UNKNOWN** — not statically imported, *but* one of: no source files were analyzed,
   dynamic import/exec constructs exist, files failed to parse, or the package's import name is
   only a low-confidence guess. Any of these means we cannot rule out usage.
3. **NOT_IMPORTED** — analyzed real code, found no import, and have no reason for doubt. The only
   confidently-safe verdict.
"""

from vulnadvisor.deps.import_mapping import resolve_import_names
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.model.import_mapping import ImportMapping, MappingConfidence
from vulnadvisor.model.imports import ImportGraph, ImportSite
from vulnadvisor.model.reachability import Reachability, ReachabilityTier

__all__ = ["assign_tier", "compute_reachability"]


def _matched_sites(mapping: ImportMapping, graph: ImportGraph) -> tuple[ImportSite, ...]:
    """Return the import sites that import any of the mapping's top-level import names."""
    roots = graph.import_roots()
    seen: set[tuple[str, int, int]] = set()
    sites: list[ImportSite] = []
    for import_name in mapping.import_names:
        root = import_name.split(".")[0]
        for site in roots.get(root, ()):
            key = (site.file, site.lineno, site.col)
            if key not in seen:
                seen.add(key)
                sites.append(site)
    sites.sort(key=lambda s: (s.file, s.lineno, s.col))
    return tuple(sites)


def assign_tier(dependency: Dependency, mapping: ImportMapping, graph: ImportGraph) -> Reachability:
    """Assign a :class:`Reachability` to ``dependency`` using its import mapping and the graph."""
    matched = _matched_sites(mapping, graph)
    if matched:
        first = matched[0]
        names = ", ".join(mapping.import_names)
        return Reachability(
            tier=ReachabilityTier.IMPORTED,
            reason=f"imported as '{names}' in your code (e.g. {first.file}:{first.lineno})",
            evidence=matched,
        )

    if graph.analyzed_file_count == 0:
        return Reachability(
            tier=ReachabilityTier.DYNAMIC_UNKNOWN,
            reason="no Python source files were found to analyze, so usage cannot be ruled out",
        )

    causes: list[str] = []
    if graph.dynamic_sites:
        causes.append("dynamic imports/exec (importlib/__import__/eval/exec)")
    if graph.parse_errors:
        causes.append("source files that could not be parsed")
    if mapping.confidence is MappingConfidence.LOW:
        causes.append(f"a low-confidence import-name mapping ({', '.join(mapping.import_names)})")

    if causes:
        return Reachability(
            tier=ReachabilityTier.DYNAMIC_UNKNOWN,
            reason="not found in static imports, but " + "; ".join(causes) + " could hide usage",
            dynamic_evidence=graph.dynamic_sites,
        )

    return Reachability(
        tier=ReachabilityTier.NOT_IMPORTED,
        reason="the package is never imported in your code (no path from your code)",
    )


def compute_reachability(dependency: Dependency, graph: ImportGraph) -> Reachability:
    """Resolve ``dependency``'s import names and assign its reachability tier."""
    mapping = resolve_import_names(dependency.raw_name or dependency.name)
    return assign_tier(dependency, mapping, graph)
