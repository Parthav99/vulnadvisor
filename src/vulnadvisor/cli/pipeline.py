"""Wire the scan pipeline: dependencies -> advisory match -> reachability -> scoring, plus SAST.

The ``AdvisoryMatcher`` is injected so the pipeline can be exercised end-to-end in tests without
any network access. An optional ``symbol_names_for`` callback supplies an advisory's known
vulnerable symbol names (from the local dataset), enabling function-level call-path reachability.

A scan runs **two** analyses by default (Task 16.4): third-party dependency reachability (SCA) and
first-party taint (SAST). ``run_sca`` / ``run_sast`` toggle each (the CLI ``--sca-only`` /
``--sast-only`` flags) — running SAST alone needs no network, so it works fully offline.

Optionally (Task 21.4, the CLI ``--with-semgrep`` / ``--external`` flags) one or more
:class:`~vulnadvisor.sast.external.base.ExternalToolAdapter`s run alongside the native taint engine;
their findings are **fused** onto ours (``sast/external/fusion.py``) — corroborated, de-duplicated,
and re-tiered through our reachability — and any tool-degraded reasons join ``degraded_sources``.
"""

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.callgraph.frameworks import (
    DEFAULT_PLUGINS,
    FrameworkPlugin,
    collect_entry_points,
    entry_point_names,
)
from vulnadvisor.callgraph.import_graph import build_import_graph
from vulnadvisor.callgraph.type_resolver import TypeResolver
from vulnadvisor.deps.parsers import collect_dependencies
from vulnadvisor.engine.sast_scoring import score_sast_findings
from vulnadvisor.engine.scoring import order_findings, score_match
from vulnadvisor.model.advisory import Advisory, MatchedAdvisory
from vulnadvisor.model.imports import ImportGraph
from vulnadvisor.model.reachability import Reachability
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.reachability.tiering import compute_reachability, refine_reachability
from vulnadvisor.sast.external.base import ExternalToolAdapter
from vulnadvisor.sast.external.fusion import fuse_findings
from vulnadvisor.sast.model import SastFinding, ScoredSastFinding
from vulnadvisor.sast.taint import analyze_taint
from vulnadvisor.store.analysis_cache import AnalysisCache

__all__ = ["ScanReport", "scan_project"]

SymbolNamesFor = Callable[[Advisory], frozenset[str]]


class ScanReport:
    """The result of scanning a project: ranked SCA + SAST findings plus any degraded sources."""

    def __init__(
        self,
        findings: Sequence[ScoredFinding],
        degraded_sources: Sequence[str],
        sast_findings: Sequence[ScoredSastFinding] = (),
    ) -> None:
        """Store the ranked dependency ``findings``, ``sast_findings``, and ``degraded_sources``."""
        self.findings = list(findings)
        self.sast_findings = list(sast_findings)
        self.degraded_sources = tuple(degraded_sources)


def scan_project(
    path: Path,
    matcher: AdvisoryMatcher,
    *,
    symbol_names_for: SymbolNamesFor | None = None,
    analysis_cache: AnalysisCache | None = None,
    resolver: TypeResolver | None = None,
    frameworks: Sequence[FrameworkPlugin] | None = None,
    run_sca: bool = True,
    run_sast: bool = True,
    external: Sequence[ExternalToolAdapter] = (),
) -> ScanReport:
    """Collect dependencies under ``path``, match advisories, assign reachability, score, and SAST.

    Package-level reachability is computed once per dependency from the import graph. When
    ``symbol_names_for`` supplies vulnerable symbol names for an advisory, function-level call-path
    analysis refines the tier (IMPORTED-AND-CALLED with the path, or DYNAMIC-UNKNOWN), per finding.
    An optional ``analysis_cache`` skips re-parsing files whose content is unchanged across runs.
    An optional type ``resolver`` (e.g. Pyright) narrows reflective dispatch to cut false positives.
    ``frameworks`` selects which framework plugins expose handler/view entry points (defaults to
    all; pass an empty list to disable framework awareness).

    ``run_sca`` runs the dependency analysis (matching needs the network/cache); ``run_sast`` runs
    the first-party taint analysis (offline). At least one is normally on; both default to on.
    ``external`` adapters (e.g. Semgrep OSS) run alongside SAST and have their findings fused onto
    the native ones; they are ignored when ``run_sast`` is off.
    """
    plugins = DEFAULT_PLUGINS if frameworks is None else frameworks

    findings: list[ScoredFinding] = []
    degraded_sources: tuple[str, ...] = ()
    if run_sca:
        dependencies = collect_dependencies(path)
        result = matcher.match(dependencies)
        degraded_sources = tuple(result.degraded_sources)
        graph = build_import_graph(path, cache=analysis_cache)
        entry_points = (
            entry_point_names(collect_entry_points(path, plugins)) if plugins else frozenset()
        )
        base_by_dep: dict[str, Reachability] = {}
        for matched in result.matches:
            base = base_by_dep.get(matched.dependency.name)
            if base is None:
                base = compute_reachability(matched.dependency, graph)
                base_by_dep[matched.dependency.name] = base
            reachability = _refine(
                matched, base, graph, path, symbol_names_for, resolver, entry_points
            )
            findings.append(score_match(matched, reachability))

    sast_findings: list[ScoredSastFinding] = []
    if run_sast:
        # ``plugins`` is DEFAULT_PLUGINS when frameworks weren't overridden, or the caller's list
        # (possibly empty, for --no-frameworks) — pass it through so SAST honors the same choice.
        native = analyze_taint(path, plugins=plugins)
        fused, external_degraded = _fuse_external(native, external, path)
        degraded_sources = (*degraded_sources, *external_degraded)
        sast_findings = score_sast_findings(fused)

    return ScanReport(order_findings(findings), degraded_sources, sast_findings)


def _fuse_external(
    native: Sequence[SastFinding],
    adapters: Sequence[ExternalToolAdapter],
    path: Path,
) -> tuple[tuple[SastFinding, ...], tuple[str, ...]]:
    """Run each external adapter over ``path`` and fuse its findings onto ``native`` (Task 21.4).

    Each adapter is a clean degraded-or-findings result (a tool absent / failed / partial run never
    raises into the scan). Findings are overlaid through ``fuse_findings`` — corroborated against
    our own taint proof, de-duplicated, and re-tiered by reachability — and every tool's degraded
    reasons are collected for ``degraded_sources``. With no adapters this is the identity (native
    list unchanged), so the default native-only scan is byte-for-byte as before.
    """
    if not adapters:
        return tuple(native), ()
    fused: tuple[SastFinding, ...] = tuple(native)
    degraded: list[str] = []
    for adapter in adapters:
        result = adapter.scan(path)
        degraded.extend(result.degraded)
        if result.findings:
            fused = fuse_findings(fused, result.findings)
    return fused, tuple(degraded)


def _refine(
    matched: MatchedAdvisory,
    base: Reachability,
    graph: ImportGraph,
    path: Path,
    symbol_names_for: SymbolNamesFor | None,
    resolver: TypeResolver | None,
    entry_points: Iterable[str],
) -> Reachability:
    """Apply function-level refinement when vulnerable symbol names are available."""
    if symbol_names_for is None:
        return base
    names = symbol_names_for(matched.advisory)
    if not names:
        return base
    return refine_reachability(
        matched.dependency,
        base,
        graph,
        path,
        names,
        resolver=resolver,
        entry_points=entry_points,
    )
