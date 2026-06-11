"""Read API (Task 11.4): orgs, repos, scans, findings, diff, and the repo trend.

All endpoints are strictly org-scoped via :mod:`vulnadvisor_platform.access` — a user only ever sees
data for orgs they belong to. Findings are returned as the engine's JSON-report finding object
(stored ``payload``) so the dashboard and CLI never diverge. Scan lists use keyset pagination.
"""

import base64
import json
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.access import require_org, require_repo, require_scan
from vulnadvisor_platform.analytics import parse_window
from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.models import Finding, Membership, Org, Repository, Scan
from vulnadvisor_platform.schemas import (
    DiffResponse,
    FindingsResponse,
    OrgDetailOut,
    OrgOut,
    RepoOut,
    ScanDetailOut,
    ScanListItem,
    ScanPage,
    TrendPoint,
    TrendResponse,
)
from vulnadvisor_platform.security import CurrentUser
from vulnadvisor_platform.trends import summarize_tiers

router = APIRouter(tags=["read"])


# --- helpers ------------------------------------------------------------------------------------


async def _repo_out(session: AsyncSession, repo: Repository) -> RepoOut:
    scan_count = (
        await session.execute(select(func.count()).select_from(Scan).where(Scan.repo_id == repo.id))
    ).scalar_one()
    last_scan_at = (
        await session.execute(select(func.max(Scan.created_at)).where(Scan.repo_id == repo.id))
    ).scalar_one()
    return RepoOut(
        id=repo.id,
        name=repo.name,
        default_branch=repo.default_branch,
        is_private=repo.is_private,
        scan_count=scan_count,
        last_scan_at=last_scan_at,
    )


def _encode_cursor(scan: Scan) -> str:
    payload = {"ts": scan.created_at.isoformat(), "id": str(scan.id)}
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
        return datetime.fromisoformat(data["ts"]), uuid.UUID(data["id"])
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid cursor") from exc


async def _finding_payloads(
    session: AsyncSession, scan_id: uuid.UUID
) -> dict[tuple[str, str], dict[str, Any]]:
    rows = (
        await session.execute(
            select(Finding.package, Finding.advisory_id, Finding.payload).where(
                Finding.scan_id == scan_id
            )
        )
    ).all()
    return {(package, advisory_id): payload for package, advisory_id, payload in rows}


# --- orgs ---------------------------------------------------------------------------------------


@router.get("/v1/orgs", response_model=list[OrgOut])
async def list_orgs(user: CurrentUser, session: SessionDep) -> list[OrgOut]:
    """List the orgs the authenticated user belongs to."""
    rows = (
        await session.execute(
            select(Org, Membership.role)
            .join(Membership, Membership.org_id == Org.id)
            .where(Membership.user_id == user.id)
            .order_by(Org.slug)
        )
    ).all()
    return [
        OrgOut(id=org.id, slug=org.slug, name=org.name, plan=org.plan, role=role)
        for org, role in rows
    ]


@router.get("/v1/orgs/{org_slug}", response_model=OrgDetailOut)
async def get_org(org_slug: str, user: CurrentUser, session: SessionDep) -> OrgDetailOut:
    """Org detail with repo and member counts."""
    org, role = await require_org(session, user, org_slug)
    repo_count = (
        await session.execute(
            select(func.count()).select_from(Repository).where(Repository.org_id == org.id)
        )
    ).scalar_one()
    member_count = (
        await session.execute(
            select(func.count()).select_from(Membership).where(Membership.org_id == org.id)
        )
    ).scalar_one()
    return OrgDetailOut(
        id=org.id,
        slug=org.slug,
        name=org.name,
        plan=org.plan,
        role=role,
        repo_count=repo_count,
        member_count=member_count,
    )


# --- repositories -------------------------------------------------------------------------------


@router.get("/v1/orgs/{org_slug}/repos", response_model=list[RepoOut])
async def list_repos(org_slug: str, user: CurrentUser, session: SessionDep) -> list[RepoOut]:
    """List repositories in an org."""
    org, _ = await require_org(session, user, org_slug)
    repos = (
        (
            await session.execute(
                select(Repository).where(Repository.org_id == org.id).order_by(Repository.name)
            )
        )
        .scalars()
        .all()
    )
    return [await _repo_out(session, repo) for repo in repos]


@router.get("/v1/orgs/{org_slug}/repos/{repo_name}", response_model=RepoOut)
async def get_repo(
    org_slug: str, repo_name: str, user: CurrentUser, session: SessionDep
) -> RepoOut:
    """Repository detail."""
    org, _ = await require_org(session, user, org_slug)
    repo = await require_repo(session, org, repo_name)
    return await _repo_out(session, repo)


@router.get("/v1/orgs/{org_slug}/repos/{repo_name}/trend", response_model=TrendResponse)
async def repo_trend(
    org_slug: str,
    repo_name: str,
    user: CurrentUser,
    session: SessionDep,
    window: str = "90d",
) -> TrendResponse:
    """Per-day actionable/deprioritized/reachable-called counts from each day's latest scan."""
    org, _ = await require_org(session, user, org_slug)
    repo = await require_repo(session, org, repo_name)
    days = parse_window(window)
    cutoff = utcnow() - timedelta(days=days)

    scans = (
        (
            await session.execute(
                select(Scan)
                .where(Scan.repo_id == repo.id, Scan.created_at >= cutoff)
                .order_by(Scan.created_at)
            )
        )
        .scalars()
        .all()
    )
    latest_per_day: dict[str, Scan] = {}
    for scan in scans:
        day = scan.created_at.date().isoformat()
        current = latest_per_day.get(day)
        if current is None or scan.created_at >= current.created_at:
            latest_per_day[day] = scan

    points: list[TrendPoint] = []
    for day in sorted(latest_per_day):
        scan = latest_per_day[day]
        rows = (
            await session.execute(
                select(Finding.tier, func.count())
                .where(Finding.scan_id == scan.id)
                .group_by(Finding.tier)
            )
        ).all()
        totals = summarize_tiers({tier: count for tier, count in rows})
        points.append(
            TrendPoint(
                date=day,
                actionable=totals.actionable,
                deprioritized=totals.deprioritized,
                reachable_called=totals.reachable_called,
            )
        )
    return TrendResponse(repo_id=repo.id, window_days=days, points=points)


# --- scans & findings ---------------------------------------------------------------------------


@router.get("/v1/orgs/{org_slug}/repos/{repo_name}/scans", response_model=ScanPage)
async def list_scans(
    org_slug: str,
    repo_name: str,
    user: CurrentUser,
    session: SessionDep,
    ref: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
) -> ScanPage:
    """List a repo's scans (newest first), optionally filtered by ref, with keyset pagination."""
    org, _ = await require_org(session, user, org_slug)
    repo = await require_repo(session, org, repo_name)

    stmt = select(Scan).where(Scan.repo_id == repo.id)
    if ref is not None:
        stmt = stmt.where(Scan.ref == ref)
    if cursor is not None:
        ts, cid = _decode_cursor(cursor)
        stmt = stmt.where(tuple_(Scan.created_at, Scan.id) < (ts, cid))
    stmt = stmt.order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit + 1)

    scans = list((await session.execute(stmt)).scalars().all())
    next_cursor = None
    if len(scans) > limit:
        scans = scans[:limit]
        next_cursor = _encode_cursor(scans[-1])
    items = [ScanListItem.model_validate(scan) for scan in scans]
    return ScanPage(items=items, next_cursor=next_cursor)


@router.get("/v1/scans/{scan_id}", response_model=ScanDetailOut)
async def get_scan(scan_id: uuid.UUID, user: CurrentUser, session: SessionDep) -> ScanDetailOut:
    """Scan detail (summary, degraded sources, status)."""
    scan = await require_scan(session, user, scan_id)
    return ScanDetailOut.model_validate(scan)


@router.get("/v1/scans/{scan_id}/findings", response_model=FindingsResponse)
async def list_findings(
    scan_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    tier: str | None = None,
    band: str | None = None,
    min_priority: float | None = None,
) -> FindingsResponse:
    """A scan's findings (priority-desc), filterable by tier / band / minimum priority."""
    scan = await require_scan(session, user, scan_id)
    stmt = select(Finding).where(Finding.scan_id == scan.id)
    if tier is not None:
        stmt = stmt.where(Finding.tier == tier)
    if band is not None:
        stmt = stmt.where(Finding.band == band)
    if min_priority is not None:
        stmt = stmt.where(Finding.priority >= min_priority)
    stmt = stmt.order_by(Finding.priority.desc())
    findings = (await session.execute(stmt)).scalars().all()
    payloads = [finding.payload for finding in findings]
    return FindingsResponse(scan_id=scan.id, count=len(payloads), findings=payloads)


@router.get("/v1/scans/{from_id}/diff/{to_id}", response_model=DiffResponse)
async def diff_scans(
    from_id: uuid.UUID, to_id: uuid.UUID, user: CurrentUser, session: SessionDep
) -> DiffResponse:
    """Findings introduced/fixed between two scans the user can access, plus the unchanged count."""
    from_scan = await require_scan(session, user, from_id)
    to_scan = await require_scan(session, user, to_id)
    before = await _finding_payloads(session, from_scan.id)
    after = await _finding_payloads(session, to_scan.id)
    introduced = [payload for key, payload in after.items() if key not in before]
    fixed = [payload for key, payload in before.items() if key not in after]
    unchanged = len(before.keys() & after.keys())
    return DiffResponse(
        from_scan_id=from_scan.id,
        to_scan_id=to_scan.id,
        introduced=introduced,
        fixed=fixed,
        unchanged=unchanged,
    )
