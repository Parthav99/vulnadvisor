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

from collections.abc import Iterable
from pathlib import Path

from vulnadvisor.callgraph.call_paths import (
    CallGraphResult,
    PackageReflection,
    find_vulnerable_call_paths,
)
from vulnadvisor.callgraph.type_resolver import TypeResolver
from vulnadvisor.deps.import_mapping import resolve_import_names
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.model.import_mapping import ImportMapping, MappingConfidence
from vulnadvisor.model.imports import ImportGraph, ImportSite
from vulnadvisor.model.reachability import Reachability, ReachabilityTier

__all__ = ["assign_tier", "compute_reachability", "refine_reachability"]


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

    # Only dynamic sites that are *not* provably first-party-only can hide third-party usage. A
    # plugin loader that provably targets the project's own modules (relative/__name__-prefixed, or
    # a constant first-party prefix) cannot import an unused third-party distribution, so it must
    # not block the NOT_IMPORTED verdict. eval/exec and opaque targets still escalate.
    unproven_dynamic = graph.unproven_dynamic_sites()
    causes: list[str] = []
    if unproven_dynamic:
        causes.append("dynamic imports/exec (importlib/__import__/eval/exec)")
    if graph.parse_errors:
        causes.append("source files that could not be parsed")
    if mapping.confidence is MappingConfidence.LOW:
        causes.append(f"a low-confidence import-name mapping ({', '.join(mapping.import_names)})")

    if causes:
        return Reachability(
            tier=ReachabilityTier.DYNAMIC_UNKNOWN,
            reason="not found in static imports, but " + "; ".join(causes) + " could hide usage",
            dynamic_evidence=unproven_dynamic,
        )

    return Reachability(
        tier=ReachabilityTier.NOT_IMPORTED,
        reason="the package is never imported in your code (no path from your code)",
    )


def compute_reachability(dependency: Dependency, graph: ImportGraph) -> Reachability:
    """Resolve ``dependency``'s import names and assign its reachability tier."""
    mapping = resolve_import_names(dependency.raw_name or dependency.name)
    return assign_tier(dependency, mapping, graph)


def refine_reachability(
    dependency: Dependency,
    base: Reachability,
    graph: ImportGraph,
    project_dir: Path,
    vulnerable_names: Iterable[str],
    *,
    resolver: TypeResolver | None = None,
    entry_points: Iterable[str] = (),
) -> Reachability:
    """Upgrade/downgrade a package-level tier using function-level call-path analysis.

    * A concrete call path to a vulnerable symbol upgrades to ``IMPORTED_AND_CALLED`` (path shown).
    * An ``IMPORTED`` finding where dispatch could hide a call (reflective ``getattr`` on the
      package, or an opaque ``eval``/``exec``/computed callee) downgrades to ``DYNAMIC_UNKNOWN`` —
      we never claim the symbol is not called.
    * When a ``resolver`` is available it resolves reflective accesses by inferred type: one
      that provably targets a *non-vulnerable* attribute no longer forces the downgrade (M7
      precision), while one that resolves *to* the vulnerable symbol upgrades to
      ``IMPORTED_AND_CALLED``. With no resolver, every reflection stays conservative (M6).
    * ``entry_points`` are framework-registered handler/view names; a vuln reached only through such
      a handler is found and rooted at it (M7 framework plugins).
    """
    names = frozenset(vulnerable_names)
    if not names or base.tier is ReachabilityTier.NOT_IMPORTED:
        return base

    mapping = resolve_import_names(dependency.raw_name or dependency.name)
    result = find_vulnerable_call_paths(
        project_dir,
        import_names=mapping.import_names,
        vulnerable_names=names,
        entry_points=entry_points,
    )

    if result.paths:
        return Reachability(
            tier=ReachabilityTier.IMPORTED_AND_CALLED,
            reason=f"a call path to the vulnerable symbol exists: {result.paths[0].render()}",
            evidence=base.evidence,
            call_paths=tuple(result.paths),
        )

    reflective_hit, unresolved_reflection = _resolve_reflections(
        result, project_dir, names, resolver
    )

    if reflective_hit is not None:
        path = reflective_hit
        return Reachability(
            tier=ReachabilityTier.IMPORTED_AND_CALLED,
            reason=f"a reflective call resolves to the vulnerable symbol: {path.render()}",
            evidence=base.evidence,
            call_paths=(path,),
        )

    unproven_dynamic = graph.unproven_dynamic_sites()
    dispatch_hides_call = (
        unresolved_reflection or result.has_opaque_dynamic or bool(unproven_dynamic)
    )
    if base.tier is ReachabilityTier.IMPORTED and dispatch_hides_call:
        return Reachability(
            tier=ReachabilityTier.DYNAMIC_UNKNOWN,
            reason=(
                "imported, and dynamic dispatch (e.g. getattr / reflection) is present, so a call "
                "to the vulnerable symbol cannot be ruled out"
            ),
            evidence=base.evidence,
            dynamic_evidence=unproven_dynamic,
        )

    return base


def _resolve_reflections(
    result: CallGraphResult,
    project_dir: Path,
    vulnerable_names: frozenset[str],
    resolver: TypeResolver | None,
) -> tuple[CallPath | None, bool]:
    """Classify reflective accesses with the resolver.

    Returns ``(reflective_hit, any_unresolved)``: ``reflective_hit`` is a one-step call path when a
    reflection provably resolves *to* a vulnerable attribute; ``any_unresolved`` is ``True`` if any
    reflection could not be ruled out (no resolver, no type info, or it includes a vulnerable name
    among other possibilities). Soundness: a reflection only stops forcing the conservative tier
    when the resolver returns a concrete attribute set that excludes every vulnerable name.
    """
    if not result.reflections:
        return None, False
    if resolver is None or not resolver.available:
        return None, True  # no type info -> every reflection stays conservative (M6)

    any_unresolved = False
    for reflection in result.reflections:
        attrs = resolver.resolve_attrs(project_dir, reflection)
        if attrs is None:
            any_unresolved = True
            continue
        hit = attrs & vulnerable_names
        if hit:
            return _reflective_path(reflection, sorted(hit)[0]), any_unresolved
        # Resolved to a concrete, non-vulnerable attribute set -> this reflection is safe.
    return None, any_unresolved


def _reflective_path(reflection: PackageReflection, attr: str) -> CallPath:
    """Build a one-step call path for a reflective call resolved to a vulnerable attribute."""
    step = CallStep(
        qualname=f"getattr({reflection.alias}, ...) -> {reflection.alias}.{attr}",
        file=reflection.file,
        line=reflection.lineno,
    )
    return CallPath(steps=(step,))
