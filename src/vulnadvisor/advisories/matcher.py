"""Orchestrate OSV + EPSS + KEV lookups for a dependency list into a single result.

Per-source failures are caught and recorded in ``MatchResult.degraded_sources`` so the scan can
continue and clearly signal that data is incomplete — a degraded source must never be read as
"confidently safe".
"""

from collections.abc import Iterable, Sequence

from vulnadvisor.advisories.clients import EpssClient, KevClient, OSVClient
from vulnadvisor.advisories.transport import TransportError
from vulnadvisor.model.advisory import Advisory, EpssScore, MatchedAdvisory, MatchResult
from vulnadvisor.model.dependency import Dependency

__all__ = ["AdvisoryMatcher"]


class AdvisoryMatcher:
    """Combine advisory matching (OSV) with EPSS and KEV enrichment."""

    def __init__(self, osv: OSVClient, epss: EpssClient, kev: KevClient) -> None:
        """Bind the matcher to the three source clients."""
        self._osv = osv
        self._epss = epss
        self._kev = kev

    def match(self, dependencies: Iterable[Dependency]) -> MatchResult:
        """Return advisories for ``dependencies`` enriched with EPSS scores and KEV flags."""
        deps = list(dependencies)
        degraded: set[str] = set()

        advisories_by_dep: list[tuple[Dependency, list[Advisory]]] = []
        all_cves: set[str] = set()
        for dep in deps:
            try:
                advisories = self._osv.query(dep)
            except TransportError:
                degraded.add("OSV")
                advisories = []
            advisories_by_dep.append((dep, advisories))
            for advisory in advisories:
                all_cves.update(advisory.cve_ids)

        epss_scores = self._lookup_epss(all_cves, degraded)
        kev_set = self._lookup_kev(degraded)

        matches: list[MatchedAdvisory] = []
        for dep, advisories in advisories_by_dep:
            for advisory in advisories:
                matches.append(
                    MatchedAdvisory(
                        dependency=dep,
                        advisory=advisory,
                        epss=_best_epss(advisory.cve_ids, epss_scores),
                        in_kev=any(cve in kev_set for cve in advisory.cve_ids),
                    )
                )

        return MatchResult(matches=tuple(matches), degraded_sources=tuple(sorted(degraded)))

    def _lookup_epss(self, cves: set[str], degraded: set[str]) -> dict[str, EpssScore]:
        """Look up EPSS scores, recording ``EPSS`` as degraded on transport failure."""
        if not cves:
            return {}
        try:
            return self._epss.scores(cves)
        except TransportError:
            degraded.add("EPSS")
            return {}

    def _lookup_kev(self, degraded: set[str]) -> set[str]:
        """Look up the KEV set, recording ``KEV`` as degraded on transport failure."""
        try:
            return self._kev.cve_set()
        except TransportError:
            degraded.add("KEV")
            return set()


def _best_epss(cve_ids: Sequence[str], scores: dict[str, EpssScore]) -> EpssScore | None:
    """Return the highest-probability EPSS score among an advisory's CVEs, if any."""
    candidates = [scores[cve] for cve in cve_ids if cve in scores]
    if not candidates:
        return None
    return max(candidates, key=lambda score: score.probability)
