"""Analytics API (Task 13.3): org-wide aggregates computed server-side, strictly tenant-scoped.

Four read endpoints under ``/v1/orgs/{org}/analytics/``, each answering one dashboard question:

* ``overview`` — current posture: totals by band/tier, KEV count, repos at risk. Aggregated over
  each repo's **latest scan** (any ref) — the org's most recent knowledge, never double-counting
  historical scans.
* ``trend`` — per-day actionable/deprioritized/reachable-called across the org (each day's latest
  scan per repo, summed across repos; mirrors the repo trend semantics from 11.4).
* ``packages`` — top risky packages by max priority then finding count, over latest scans.
* ``resolution`` — median days from first-seen to fixed per band, reconstructed from consecutive
  scan diffs per (repo, ref) timeline.

Tenant isolation matches 11.4: non-members get 404 via :func:`require_org`. All aggregation uses
the denormalized finding columns (tier/band/priority/package), so compacted scans (payload pruned
by :mod:`vulnadvisor_platform.compact`) never distort the numbers; the KEV count reads
``payload['in_kev']`` from latest scans only, which compaction always preserves.
"""

import uuid
from collections import defaultdict
from datetime import timedelta
from statistics import median
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Select, func, select

from vulnadvisor.model.reachability import ReachabilityTier
from vulnadvisor.model.score import PriorityBand
from vulnadvisor_platform.access import require_org
from vulnadvisor_platform.analytics import (
    FindingKey,
    ResolutionEpisode,
    parse_window,
    resolution_episodes,
)
from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.models import Finding, Repository, Scan
from vulnadvisor_platform.schemas import (
    AnalyticsOverview,
    OrgTrendResponse,
    PackageRisk,
    PackagesResponse,
    ResolutionResponse,
    ResolutionStats,
    TrendPoint,
)
from vulnadvisor_platform.security import CurrentUser
from vulnadvisor_platform.trends import summarize_tiers

router = APIRouter(tags=["analytics"])

_NOT_IMPORTED = ReachabilityTier.NOT_IMPORTED.value


def _latest_scan_ids(org_id: uuid.UUID) -> Select[Any]:
    """Subquery selecting each org repo's most recent scan id (keyset order: created_at, id)."""
    rank = (
        func.row_number()
        .over(partition_by=Scan.repo_id, order_by=(Scan.created_at.desc(), Scan.id.desc()))
        .label("rank")
    )
    ranked = (
        select(Scan.id.label("scan_id"), rank)
        .join(Repository, Repository.id == Scan.repo_id)
        .where(Repository.org_id == org_id)
        .subquery()
    )
    return select(ranked.c.scan_id).where(ranked.c.rank == 1)


@router.get("/v1/orgs/{org_slug}/analytics/overview", response_model=AnalyticsOverview)
async def analytics_overview(
    org_slug: str, user: CurrentUser, session: SessionDep
) -> AnalyticsOverview:
    """Current org posture over each repo's latest scan: band/tier totals, KEV, repos at risk."""
    org, _ = await require_org(session, user, org_slug)
    latest = _latest_scan_ids(org.id)

    repo_count = (
        await session.execute(
            select(func.count()).select_from(Repository).where(Repository.org_id == org.id)
        )
    ).scalar_one()

    tier_rows = (
        await session.execute(
            select(Finding.tier, func.count())
            .where(Finding.scan_id.in_(latest))
            .group_by(Finding.tier)
        )
    ).all()
    by_tier = {tier.value: 0 for tier in ReachabilityTier}
    for tier, count in tier_rows:
        by_tier[tier] = by_tier.get(tier, 0) + count
    totals = summarize_tiers({tier: count for tier, count in tier_rows})

    band_rows = (
        await session.execute(
            select(Finding.band, func.count())
            .where(Finding.scan_id.in_(latest))
            .group_by(Finding.band)
        )
    ).all()
    by_band = {band.value: 0 for band in PriorityBand}
    for band, count in band_rows:
        by_band[band] = by_band.get(band, 0) + count

    kev_count = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.scan_id.in_(latest),
                Finding.payload["in_kev"].as_boolean().is_(True),
            )
        )
    ).scalar_one()

    repos_at_risk = (
        await session.execute(
            select(func.count(func.distinct(Scan.repo_id)))
            .select_from(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Finding.scan_id.in_(latest), Finding.tier != _NOT_IMPORTED)
        )
    ).scalar_one()

    return AnalyticsOverview(
        org_id=org.id,
        repo_count=repo_count,
        repos_at_risk=repos_at_risk,
        total_findings=sum(count for _, count in tier_rows),
        actionable=totals.actionable,
        deprioritized=totals.deprioritized,
        reachable_called=totals.reachable_called,
        kev_count=kev_count,
        by_band=by_band,
        by_tier=by_tier,
    )


@router.get("/v1/orgs/{org_slug}/analytics/trend", response_model=OrgTrendResponse)
async def analytics_trend(
    org_slug: str,
    user: CurrentUser,
    session: SessionDep,
    window: str = "30d",
) -> OrgTrendResponse:
    """Per-day org-wide tier totals: each day's latest scan per repo, summed across repos."""
    org, _ = await require_org(session, user, org_slug)
    days = parse_window(window)
    cutoff = utcnow() - timedelta(days=days)

    scan_rows = (
        await session.execute(
            select(Scan.id, Scan.repo_id, Scan.created_at)
            .join(Repository, Repository.id == Scan.repo_id)
            .where(Repository.org_id == org.id, Scan.created_at >= cutoff)
            .order_by(Scan.created_at, Scan.id)
        )
    ).all()
    # Ascending order means the last write per (day, repo) is that day's latest scan.
    selected: dict[tuple[str, uuid.UUID], uuid.UUID] = {}
    for scan_id, repo_id, created_at in scan_rows:
        selected[(created_at.date().isoformat(), repo_id)] = scan_id

    scan_day = {scan_id: day for (day, _repo_id), scan_id in selected.items()}
    # Every day with at least one scan gets a point, even if that day's scans were clean.
    per_day: dict[str, dict[str, int]] = {}
    for day, _repo_id in selected:
        per_day.setdefault(day, {})
    if scan_day:
        tier_rows = (
            await session.execute(
                select(Finding.scan_id, Finding.tier, func.count())
                .where(Finding.scan_id.in_(set(scan_day)))
                .group_by(Finding.scan_id, Finding.tier)
            )
        ).all()
        for scan_id, tier, count in tier_rows:
            day_counts = per_day[scan_day[scan_id]]
            day_counts[tier] = day_counts.get(tier, 0) + count

    points = []
    for day in sorted(per_day):
        totals = summarize_tiers(per_day[day])
        points.append(
            TrendPoint(
                date=day,
                actionable=totals.actionable,
                deprioritized=totals.deprioritized,
                reachable_called=totals.reachable_called,
            )
        )
    return OrgTrendResponse(org_id=org.id, window_days=days, points=points)


@router.get("/v1/orgs/{org_slug}/analytics/packages", response_model=PackagesResponse)
async def analytics_packages(
    org_slug: str,
    user: CurrentUser,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> PackagesResponse:
    """Top risky packages across the org's latest scans, by max priority then finding count."""
    org, _ = await require_org(session, user, org_slug)
    latest = _latest_scan_ids(org.id)

    agg_rows = (
        await session.execute(
            select(
                Finding.package,
                func.max(Finding.priority),
                func.count(),
                func.count(func.distinct(Scan.repo_id)),
            )
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Finding.scan_id.in_(latest))
            .group_by(Finding.package)
            .order_by(func.max(Finding.priority).desc(), func.count().desc(), Finding.package)
            .limit(limit)
        )
    ).all()

    # Each package's top-priority finding: its band is read from the stored row rather than
    # re-deriving the engine's priority->band thresholds (the engine stays the authority), and
    # its scan id gives the dashboard a click-through target to the ranked finding list.
    rank = (
        func.row_number()
        .over(partition_by=Finding.package, order_by=(Finding.priority.desc(), Finding.id))
        .label("rank")
    )
    ranked = (
        select(Finding.package, Finding.band, Finding.scan_id, rank)
        .where(Finding.scan_id.in_(latest))
        .subquery()
    )
    top_rows = (
        await session.execute(
            select(ranked.c.package, ranked.c.band, ranked.c.scan_id).where(ranked.c.rank == 1)
        )
    ).all()
    top_by_package: dict[str, tuple[str, uuid.UUID | None]] = {
        package: (band, scan_id) for package, band, scan_id in top_rows
    }

    packages: list[PackageRisk] = []
    for package, max_priority, finding_count, repo_count in agg_rows:
        band, top_scan_id = top_by_package.get(package, (PriorityBand.INFO.value, None))
        packages.append(
            PackageRisk(
                package=package,
                max_priority=max_priority,
                band=band,
                finding_count=finding_count,
                repo_count=repo_count,
                top_scan_id=top_scan_id,
            )
        )
    return PackagesResponse(org_id=org.id, packages=packages)


@router.get("/v1/orgs/{org_slug}/analytics/resolution", response_model=ResolutionResponse)
async def analytics_resolution(
    org_slug: str, user: CurrentUser, session: SessionDep
) -> ResolutionResponse:
    """Median days from first-seen to fixed (per band), derived from per-(repo, ref) scan diffs."""
    org, _ = await require_org(session, user, org_slug)

    scan_rows = (
        await session.execute(
            select(Scan.id, Scan.repo_id, Scan.ref, Scan.created_at)
            .join(Repository, Repository.id == Scan.repo_id)
            .where(Repository.org_id == org.id)
            .order_by(Scan.created_at, Scan.id)
        )
    ).all()
    finding_rows = (
        await session.execute(
            select(Finding.scan_id, Finding.package, Finding.advisory_id, Finding.band)
            .join(Scan, Scan.id == Finding.scan_id)
            .join(Repository, Repository.id == Scan.repo_id)
            .where(Repository.org_id == org.id)
        )
    ).all()
    findings_by_scan: dict[uuid.UUID, dict[FindingKey, str]] = defaultdict(dict)
    for scan_id, package, advisory_id, band in finding_rows:
        findings_by_scan[scan_id][(package, advisory_id)] = band

    # One timeline per (repo, ref); scan_rows are already in ascending (created_at, id) order.
    timelines: dict[tuple[uuid.UUID, str | None], list[Any]] = defaultdict(list)
    for scan_id, repo_id, ref, created_at in scan_rows:
        timelines[(repo_id, ref)].append((created_at, findings_by_scan.get(scan_id, {})))

    episodes: list[ResolutionEpisode] = []
    for timeline in timelines.values():
        episodes.extend(resolution_episodes(timeline))

    by_band_days: dict[str, list[float]] = {band.value: [] for band in PriorityBand}
    for episode in episodes:
        by_band_days.setdefault(episode.band, []).append(episode.days)

    def _stats(days: list[float]) -> ResolutionStats:
        return ResolutionStats(
            resolved_count=len(days),
            median_days=median(days) if days else None,
        )

    return ResolutionResponse(
        org_id=org.id,
        overall=_stats([episode.days for episode in episodes]),
        bands={band: _stats(days) for band, days in by_band_days.items()},
    )
