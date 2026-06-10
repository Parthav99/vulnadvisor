"""Tenant-scoping helpers: resolve an org/repo/scan only if the user may see it.

Every read path goes through these. A user who is not a member of an org gets **404** for that org
and anything under it (we don't leak the existence of other tenants' orgs/repos/scans).
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.models import Membership, Org, Repository, Scan, User


def _not_found(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")


async def _role(session: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID) -> str | None:
    return (
        await session.execute(
            select(Membership.role).where(
                Membership.user_id == user_id, Membership.org_id == org_id
            )
        )
    ).scalar_one_or_none()


async def require_org(session: AsyncSession, user: User, org_slug: str) -> tuple[Org, str]:
    """Return ``(org, role)`` if the user is a member, else 404."""
    org = (await session.execute(select(Org).where(Org.slug == org_slug))).scalar_one_or_none()
    if org is None:
        raise _not_found("org")
    role = await _role(session, user.id, org.id)
    if role is None:
        raise _not_found("org")
    return org, role


async def require_repo(session: AsyncSession, org: Org, repo_name: str) -> Repository:
    """Return the named repo within ``org``, else 404."""
    repo = (
        await session.execute(
            select(Repository).where(Repository.org_id == org.id, Repository.name == repo_name)
        )
    ).scalar_one_or_none()
    if repo is None:
        raise _not_found("repository")
    return repo


async def require_scan(session: AsyncSession, user: User, scan_id: uuid.UUID) -> Scan:
    """Return the scan if the user belongs to its repo's org, else 404."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise _not_found("scan")
    repo = await session.get(Repository, scan.repo_id)
    if repo is None or await _role(session, user.id, repo.org_id) is None:
        raise _not_found("scan")
    return scan
