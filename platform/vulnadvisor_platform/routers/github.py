"""GitHub App webhook + install entry point (Task 11.6) and the setup PR (Task 14.2).

``POST /v1/github/webhook`` is HMAC-verified, then dispatched: ``installation`` /
``installation_repositories`` sync orgs/installations/repos; ``pull_request`` (opened/synchronize)
posts or updates the reachability-triage comment built from the head vs base scan diff. Source code
is never touched — the comment is built from already-uploaded reports.

``POST /v1/orgs/{org}/repos/{repo}/setup-pr`` (Task 14.2) has the App open — or idempotently
update — a PR adding the scan workflow to a synced repo; the same webhook tracks that PR's
open/merged lifecycle so the dashboard's setup chips stay honest.
"""

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.access import require_admin, require_org, require_repo
from vulnadvisor_platform.config import Settings, SettingsDep, get_settings
from vulnadvisor_platform.copilot import CopilotKeyError, decrypt_api_key
from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.github_app import GitHubApp, GitHubAppDep, GitHubAppError
from vulnadvisor_platform.github_oauth import has_setup_scopes
from vulnadvisor_platform.github_secrets import GitHubSecrets, GitHubSecretsDep, GitHubSecretsError
from vulnadvisor_platform.models import (
    ApiKey,
    Finding,
    Installation,
    Membership,
    Org,
    Repository,
    Role,
    Scan,
    ScanStatus,
    User,
)
from vulnadvisor_platform.pr_comment import MARKER, render_pr_comment
from vulnadvisor_platform.pr_suggestion import (
    ReviewComment,
    build_review_comments,
    count_suggestable_fixes,
)
from vulnadvisor_platform.schemas import SetupPrResponse
from vulnadvisor_platform.security import CurrentUser, generate_api_key
from vulnadvisor_platform.setup_pr import (
    API_KEY_SECRET_NAME,
    PR_STATE_MERGED,
    PR_STATE_OPEN,
    SETUP_BRANCH,
    SETUP_PR_TITLE,
    WORKFLOW_COMMIT_MESSAGE,
    WORKFLOW_PATH,
    api_url_problem,
    render_pr_body,
    render_workflow,
)
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


@router.post("/v1/orgs/{org_slug}/repos/{repo_name}/setup-pr", response_model=SetupPrResponse)
async def open_setup_pr(
    org_slug: str,
    repo_name: str,
    user: CurrentUser,
    session: SessionDep,
    app: GitHubAppDep,
    secrets: GitHubSecretsDep,
    settings: SettingsDep,
) -> SetupPrResponse:
    """Open the setup PR adding the scan workflow to a synced repo (idempotent: re-runs update).

    Requires owner/admin on the org and a GitHub-synced repo. Two credential paths share one
    renderer (Task 17.4 Part 3): if the org has a **GitHub App** installation we open the PR as the
    App (org-wide, bot identity); otherwise we fall back to the **logged-in user's OAuth token** if
    it carries ``repo``/``workflow`` scope — so "Sign in with GitHub → set up repo" needs no App. If
    neither credential is available, a 409 tells the user to install the App or grant repo access.
    The PR adds ``.github/workflows/vulnadvisor.yml`` on a fixed branch; clicking again updates the
    same branch and PR in place — it never opens a duplicate.

    Zero-config secret (Task B): when a write-capable user OAuth token is available we also mint an
    org API key and write it as the repo's ``VULNADVISOR_API_KEY`` secret, so the workflow runs with
    no manual step. ``secret_set`` in the response reports whether that happened.
    """
    org, role = await require_org(session, user, org_slug)
    require_admin(role)
    repo = await require_repo(session, org, repo_name)
    if repo.github_repo_id is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this repository is not linked to GitHub (it only receives CLI/CI uploads)",
        )
    # Refuse to ship a workflow baked with a URL CI can't reach (e.g. the dev localhost default).
    # This is a platform-config error, not the caller's fault -> 500 with an operator-facing detail.
    url_problem = api_url_problem(settings.public_api_url)
    if url_problem is not None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, url_problem)
    installation = (
        await session.execute(
            select(Installation)
            .where(Installation.org_id == org.id)
            .order_by(Installation.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # Resolve the no-App OAuth token up front (it can 409) so the try below only wraps GitHub calls.
    oauth_token = _user_setup_token(user, settings) if installation is None else None

    owner_login = installation.account_login if installation is not None else user.login
    repo_full_name = f"{owner_login}/{repo.name}"
    workflow = render_workflow(default_branch=repo.default_branch, api_url=settings.public_api_url)
    pr_body = render_pr_body(
        repo_full_name=repo_full_name, org_slug=org.slug, dashboard_url=settings.dashboard_url
    )
    common = {
        "repo_full_name": repo_full_name,
        "base_branch": repo.default_branch,
        "file_path": WORKFLOW_PATH,
        "file_content": workflow,
        "commit_message": WORKFLOW_COMMIT_MESSAGE,
        "pr_title": SETUP_PR_TITLE,
        "pr_body": pr_body,
    }
    try:
        if installation is not None:
            result = await app.open_setup_pr(
                installation_id=installation.github_installation_id, **common
            )
        else:
            assert oauth_token is not None  # guaranteed by _user_setup_token (raises otherwise)
            result = await app.open_setup_pr_with_token(token=oauth_token, **common)
    except GitHubAppError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"GitHub App error: {exc}") from exc

    repo.setup_pr_number = result.number
    repo.setup_pr_url = result.url or None
    repo.setup_pr_state = PR_STATE_OPEN
    await session.commit()

    # The PR now exists regardless of what happens next, so its state is committed first. Then write
    # the auth secret if we have a write-capable user token (the OAuth path always does; the App
    # path does only when the user separately granted repo access).
    secret_token = (
        oauth_token if oauth_token is not None else _optional_user_setup_token(user, settings)
    )
    secret_set = await _write_api_key_secret(
        session=session,
        secrets=secrets,
        org=org,
        user=user,
        repo_name=repo.name,
        repo_full_name=repo_full_name,
        token=secret_token,
    )
    return SetupPrResponse(
        pr_number=result.number,
        pr_url=result.url,
        created=result.created,
        secret_set=secret_set,
    )


def _optional_user_setup_token(user: User, settings: Settings) -> str | None:
    """The user's decrypted write-capable OAuth token, or ``None`` — the no-raise variant.

    Used for secret writing on the App path, where a missing/insufficient/unreadable token simply
    means we skip the auto-secret (the dashboard then offers to grant access), never an error.
    """
    scopes = (user.github_token_scopes or "").split()
    if user.github_token_ciphertext is None or not has_setup_scopes(scopes):
        return None
    try:
        return decrypt_api_key(settings.secret_key, user.github_token_ciphertext)
    except CopilotKeyError:
        return None


async def _write_api_key_secret(
    *,
    session: AsyncSession,
    secrets: GitHubSecrets,
    org: Org,
    user: User,
    repo_name: str,
    repo_full_name: str,
    token: str | None,
) -> bool:
    """Mint an org API key and write it as the repo's ``VULNADVISOR_API_KEY`` secret.

    Returns True when the secret was written; with no write-capable ``token`` we skip and return
    False (the dashboard then prompts for access). The fresh key is persisted only *after* GitHub
    accepts the secret, and any prior auto-minted setup key for this repo is revoked — so re-clicks
    never accumulate live keys. A GitHub rejection surfaces as a 502 (the PR is already open; the
    next click retries the secret idempotently).
    """
    if token is None:
        return False
    secret, prefix, digest = generate_api_key()
    try:
        await secrets.put_repo_secret(
            token=token,
            repo_full_name=repo_full_name,
            secret_name=API_KEY_SECRET_NAME,
            value=secret,
        )
    except GitHubSecretsError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"the setup PR opened but writing the {API_KEY_SECRET_NAME} secret failed: {exc}",
        ) from exc
    name = f"setup:{repo_name}"
    prior = (
        (
            await session.execute(
                select(ApiKey).where(
                    ApiKey.org_id == org.id,
                    ApiKey.name == name,
                    ApiKey.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for key in prior:
        key.revoked_at = utcnow()
    session.add(ApiKey(org_id=org.id, name=name, hash=digest, prefix=prefix, created_by=user.id))
    await session.commit()
    return True


def _user_setup_token(user: User, settings: Settings) -> str:
    """The user's decrypted, write-capable OAuth token, or a 409 asking them to (re-)authorize.

    The no-App fallback (Task 17.4 Part 3): we can only open the PR as the user if they signed in
    with the elevated ``repo``/``workflow`` scopes. A missing/insufficient/unreadable token is a
    409 directing them to install the App or re-authorize at ``/v1/auth/github/login?setup=1``.
    """
    scopes = (user.github_token_scopes or "").split()
    if user.github_token_ciphertext is None or not has_setup_scopes(scopes):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "no GitHub App is installed for this org; either install it, or sign in with GitHub "
            "and grant repository access (/v1/auth/github/login?setup=1) to open the setup PR",
        )
    try:
        return decrypt_api_key(settings.secret_key, user.github_token_ciphertext)
    except CopilotKeyError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "your stored GitHub authorization could not be read; sign in with GitHub again "
            "(/v1/auth/github/login?setup=1) to re-grant repository access",
        ) from exc


@router.post("/v1/github/webhook")
@router.post("/v1/webhooks/github", include_in_schema=False)
async def webhook(
    request: Request, settings: SettingsDep, app: GitHubAppDep, session: SessionDep
) -> dict[str, Any]:
    """Verify and dispatch a GitHub webhook delivery.

    Served at the canonical ``/v1/github/webhook`` and an alias ``/v1/webhooks/github`` (kept out
    of the OpenAPI schema) so a GitHub App configured with either path works identically.
    """
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

    # Link the installing user (the webhook ``sender``) to the org as owner, so they actually see
    # it in GET /v1/orgs after installing. Without this the org exists but belongs to no one.
    installer = await _upsert_installer(session, payload.get("sender"))
    if installer is not None:
        await _ensure_membership(session, installer.id, org.id, Role.OWNER.value)

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


async def _upsert_installer(session: AsyncSession, sender: Any) -> User | None:
    """Upsert the installing user from the webhook ``sender`` object; ``None`` if it's malformed.

    The user may not have logged in yet, so a minimal record (github id + login) is created; a later
    OAuth login fills in email/avatar by matching ``github_user_id``.
    """
    if not isinstance(sender, dict):
        return None
    gid = sender.get("id")
    login = sender.get("login")
    if not isinstance(gid, int) or not isinstance(login, str):
        return None
    user = (
        await session.execute(select(User).where(User.github_user_id == gid))
    ).scalar_one_or_none()
    if user is None:
        avatar = sender.get("avatar_url")
        user = User(
            github_user_id=gid,
            login=login,
            email=None,
            avatar_url=avatar if isinstance(avatar, str) else None,
        )
        session.add(user)
        await session.flush()
    return user


async def _ensure_membership(
    session: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID, role: str
) -> None:
    """Create a membership linking ``user_id`` to ``org_id`` if one doesn't already exist."""
    existing = (
        await session.execute(
            select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(Membership(user_id=user_id, org_id=org_id, role=role))


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


async def _sync_setup_pr_state(
    session: AsyncSession, repo: Repository, action: Any, pull_request: dict[str, Any]
) -> None:
    """Track the setup PR's lifecycle from its own webhook deliveries.

    Opened/reopened -> ``open`` (with number/url, in case the row predates the PR or the platform
    was redeployed); closed -> ``merged`` when GitHub says so, else cleared (back to "not set up",
    which is then the truth).
    """
    if action in {"opened", "reopened"}:
        repo.setup_pr_state = PR_STATE_OPEN
        number = pull_request.get("number")
        if isinstance(number, int):
            repo.setup_pr_number = number
        html_url = pull_request.get("html_url")
        if isinstance(html_url, str):
            repo.setup_pr_url = html_url
    elif action == "closed":
        if pull_request.get("merged") is True:
            repo.setup_pr_state = PR_STATE_MERGED
        else:
            repo.setup_pr_state = None
            repo.setup_pr_number = None
            repo.setup_pr_url = None
    await session.commit()


async def _handle_pull_request(
    session: AsyncSession, app: GitHubApp, payload: dict[str, Any]
) -> bool:
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

    # Our own setup PR: keep its lifecycle state in sync and never comment on it (a triage
    # comment on a one-file workflow PR would be noise).
    if head.get("ref") == SETUP_BRANCH:
        await _sync_setup_pr_state(session, repo, payload.get("action"), pull_request)
        return False

    if payload.get("action") not in _PR_ACTIONS:
        return False
    head_sha = head.get("sha")
    head_ref = head.get("ref")
    base_ref = base.get("ref")

    head_scan = await _latest_complete(
        session,
        repo.id,
        commit_sha=head_sha if isinstance(head_sha, str) else None,
        ref=head_ref if isinstance(head_ref, str) else None,
    )
    review_comments: list[ReviewComment] = []
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
        stored_fixes = head_scan.suggestions if isinstance(head_scan.suggestions, list) else []
        review_comments = build_review_comments(stored_fixes)
        body = render_pr_comment(
            introduced=introduced,
            fixed_count=fixed_count,
            repo=full_name,
            pr_number=number,
            validated_fixes=count_suggestable_fixes(stored_fixes),
        )

    installation_id = installation.get("id") if isinstance(installation, dict) else None
    installation_id = installation_id if isinstance(installation_id, int) else None
    await app.post_or_update_comment(
        installation_id=installation_id,
        repo_full_name=full_name,
        pr_number=number,
        body=body,
    )

    # In-line one-click suggestions for the validated fixes (Task 17.2). Posted as a COMMENT review
    # on the head commit; prunes our prior suggestions first so a synchronize updates them in place.
    # Requires the head sha to anchor against — without it the summary comment alone is posted.
    if isinstance(head_sha, str) and head_sha:
        await app.post_or_update_suggestions(
            installation_id=installation_id,
            repo_full_name=full_name,
            pr_number=number,
            head_sha=head_sha,
            comments=review_comments,
        )
    return True
