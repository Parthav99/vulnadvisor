"""GitHub App webhook + install entry point (Task 11.6).

``POST /v1/github/webhook`` is HMAC-verified, then dispatched: ``installation`` /
``installation_repositories`` sync orgs/installations/repos; ``pull_request`` (opened/synchronize)
posts or updates the reachability-triage comment built from the head vs base scan diff. Source code
is never touched — the comment is built from already-uploaded reports.
"""

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.config import SettingsDep, get_settings
from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.github_app import GitHubApp, GitHubAppDep
from vulnadvisor_platform.models import (
    Finding,
    Installation,
    Org,
    Repository,
    Scan,
    ScanStatus,
)
from vulnadvisor_platform.pr_comment import MARKER, render_pr_comment
from vulnadvisor_platform.webhooks import verify_signature

router = APIRouter(tags=["github"])

_PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


def _object(parent: dict[str, Any], key: str) -> dict[str, Any]:
    """Return ``parent[key]`` if it is a dict, else an empty dict (defensive payload access)."""
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


@router.get("/v1/github/install")
async def install() -> RedirectResponse:
    """Redirect to the GitHub App installation page."""
    slug = get_settings().github_app_slug or "vulnadvisor"
    return RedirectResponse(
        f"https://github.com/apps/{slug}/installations/new",
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.post("/v1/github/webhook")
async def webhook(
    request: Request, settings: SettingsDep, app: GitHubAppDep, session: SessionDep
) -> dict[str, Any]:
    """Verify and dispatch a GitHub webhook delivery."""
    body = await request.body()
    if not verify_signature(
        settings.github_webhook_secret, body, request.headers.get("X-Hub-Signature-256")
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid webhook signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "payload must be an object")

    event = request.headers.get("X-GitHub-Event", "")
    if event in {"installation", "installation_repositories"}:
        await _sync_installation(session, payload)
        return {"ok": True, "event": event}
    if event == "pull_request":
        commented = await _handle_pull_request(session, app, payload)
        return {"ok": True, "event": event, "commented": commented}
    return {"ok": True, "event": event, "ignored": True}


async def _sync_installation(session: AsyncSession, payload: dict[str, Any]) -> None:
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        return
    installation_id = installation.get("id")
    account = installation.get("account")
    account_login = account.get("login") if isinstance(account, dict) else None
    account_id = account.get("id") if isinstance(account, dict) else None
    if not isinstance(installation_id, int) or not isinstance(account_login, str):
        return

    org = await _upsert_org(session, account_login, account_id)
    record = (
        await session.execute(
            select(Installation).where(Installation.github_installation_id == installation_id)
        )
    ).scalar_one_or_none()
    if record is None:
        session.add(
            Installation(
                org_id=org.id,
                github_installation_id=installation_id,
                account_login=account_login,
            )
        )
    else:
        record.org_id = org.id
        record.account_login = account_login

    added = payload.get("repositories")
    if not isinstance(added, list):
        added = payload.get("repositories_added")
    for repo in added if isinstance(added, list) else []:
        if isinstance(repo, dict):
            await _upsert_repo(session, org, repo)

    removed = payload.get("repositories_removed")
    for repo in removed if isinstance(removed, list) else []:
        if isinstance(repo, dict) and isinstance(repo.get("id"), int):
            existing = (
                await session.execute(
                    select(Repository).where(Repository.github_repo_id == repo["id"])
                )
            ).scalar_one_or_none()
            if existing is not None:
                await session.delete(existing)

    await session.commit()


async def _upsert_org(session: AsyncSession, login: str, account_id: Any) -> Org:
    org = None
    if isinstance(account_id, int):
        org = (
            await session.execute(select(Org).where(Org.github_org_id == account_id))
        ).scalar_one_or_none()
    if org is None:
        org = (await session.execute(select(Org).where(Org.slug == login))).scalar_one_or_none()
    if org is None:
        org = Org(
            slug=login,
            name=login,
            github_org_id=account_id if isinstance(account_id, int) else None,
        )
        session.add(org)
        await session.flush()
    return org


async def _upsert_repo(session: AsyncSession, org: Org, repo: dict[str, Any]) -> None:
    repo_id = repo.get("id")
    name = repo.get("name")
    if not isinstance(name, str):
        return
    existing = None
    if isinstance(repo_id, int):
        existing = (
            await session.execute(select(Repository).where(Repository.github_repo_id == repo_id))
        ).scalar_one_or_none()
    if existing is None:
        session.add(
            Repository(
                org_id=org.id,
                name=name,
                github_repo_id=repo_id if isinstance(repo_id, int) else None,
                is_private=bool(repo.get("private", True)),
            )
        )
    else:
        existing.name = name
        existing.org_id = org.id


async def _latest_complete(
    session: AsyncSession,
    repo_id: uuid.UUID,
    *,
    commit_sha: str | None = None,
    ref: str | None = None,
) -> Scan | None:
    stmt = select(Scan).where(Scan.repo_id == repo_id, Scan.status == ScanStatus.COMPLETE.value)
    if commit_sha is not None:
        stmt = stmt.where(Scan.commit_sha == commit_sha)
    elif ref is not None:
        stmt = stmt.where(Scan.ref == ref)
    stmt = stmt.order_by(Scan.created_at.desc()).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _finding_map(
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


async def _handle_pull_request(
    session: AsyncSession, app: GitHubApp, payload: dict[str, Any]
) -> bool:
    if payload.get("action") not in _PR_ACTIONS:
        return False
    pull_request = payload.get("pull_request")
    repository = payload.get("repository")
    installation = payload.get("installation")
    number = payload.get("number")
    if not isinstance(pull_request, dict) or not isinstance(repository, dict):
        return False
    full_name = repository.get("full_name")
    repo_gid = repository.get("id")
    if (
        not isinstance(number, int)
        or not isinstance(full_name, str)
        or not isinstance(repo_gid, int)
    ):
        return False

    repo = (
        await session.execute(select(Repository).where(Repository.github_repo_id == repo_gid))
    ).scalar_one_or_none()
    if repo is None:
        return False  # repo not installed/synced

    head = _object(pull_request, "head")
    base = _object(pull_request, "base")
    head_sha = head.get("sha")
    head_ref = head.get("ref")
    base_ref = base.get("ref")

    head_scan = await _latest_complete(
        session,
        repo.id,
        commit_sha=head_sha if isinstance(head_sha, str) else None,
        ref=head_ref if isinstance(head_ref, str) else None,
    )
    if head_scan is None:
        body = (
            f"{MARKER}\n## VulnAdvisor — reachability triage\n\n"
            "Waiting for a scan report for this commit. Upload "
            "`vulnadvisor scan --format json` from CI to see the reachable-finding diff."
        )
    else:
        base_scan = await _latest_complete(
            session, repo.id, ref=base_ref if isinstance(base_ref, str) else None
        )
        after = await _finding_map(session, head_scan.id)
        before = await _finding_map(session, base_scan.id) if base_scan is not None else {}
        introduced = [payload_ for key, payload_ in after.items() if key not in before]
        fixed_count = sum(1 for key in before if key not in after)
        body = render_pr_comment(
            introduced=introduced, fixed_count=fixed_count, repo=full_name, pr_number=number
        )

    installation_id = installation.get("id") if isinstance(installation, dict) else None
    await app.post_or_update_comment(
        installation_id=installation_id if isinstance(installation_id, int) else None,
        repo_full_name=full_name,
        pr_number=number,
        body=body,
    )
    return True
