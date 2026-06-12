"""GitHub App: HMAC webhook verification, installation sync, and the PR diff comment.

The webhook secret is injected via a settings override and the GitHub client is faked, so the full
verify -> dispatch -> diff -> comment path runs without network or real credentials.
"""

import hashlib
import hmac
import json
from typing import Any

import yaml
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.github_app import GitHubAppError, SetupPr, get_github_app
from vulnadvisor_platform.models import (
    ApiKey,
    Finding,
    Installation,
    Membership,
    Org,
    Repository,
    Role,
    Scan,
    User,
)
from vulnadvisor_platform.security import generate_api_key

_SECRET = "whsec_test"


class _FakeApp:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.setup_calls: list[dict[str, Any]] = []
        self.fail_setup = False

    async def post_or_update_comment(
        self, *, installation_id: int | None, repo_full_name: str, pr_number: int, body: str
    ) -> None:
        self.calls.append(
            {
                "installation_id": installation_id,
                "repo": repo_full_name,
                "pr": pr_number,
                "body": body,
            }
        )

    async def open_setup_pr(self, **kwargs: Any) -> SetupPr:
        if self.fail_setup:
            raise GitHubAppError("github is down")
        self.setup_calls.append(kwargs)
        # Same fixed branch -> same PR forever: only the first call "creates".
        return SetupPr(
            number=7,
            url="https://github.com/acme/web/pull/7",
            created=len(self.setup_calls) == 1,
        )


def _overrides() -> _FakeApp:
    fake = _FakeApp()
    app.dependency_overrides[get_settings] = lambda: Settings(github_webhook_secret=_SECRET)
    app.dependency_overrides[get_github_app] = lambda: fake
    return fake


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(_SECRET.encode(), body, hashlib.sha256).hexdigest()


async def _post(
    client: AsyncClient, payload: dict[str, Any], event: str, *, valid: bool = True
) -> Any:
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(body) if valid else "sha256=deadbeef",
    }
    return await client.post("/v1/github/webhook", content=body, headers=headers)


def _finding(scan_id: Any, pkg: str, adv: str, *, tier: str = "imported") -> Finding:
    payload = {
        "dependency": {"name": pkg, "version": "1.0"},
        "advisory": {"id": adv},
        "score": {"value": 80.0, "band": "high"},
        "reachability": {"tier": tier},
        "fix": {"command": f"pip install -U {pkg}"},
    }
    return Finding(
        scan_id=scan_id,
        advisory_id=adv,
        package=pkg,
        version="1.0",
        tier=tier,
        band="high",
        priority=80.0,
        payload=payload,
    )


# --- signature verification ---------------------------------------------------------------------


async def test_webhook_rejects_bad_signature(client: AsyncClient) -> None:
    _overrides()
    resp = await _post(client, {"zen": "hi"}, "ping", valid=False)
    assert resp.status_code == 401


async def test_webhook_accepts_valid_ping(client: AsyncClient) -> None:
    _overrides()
    resp = await _post(client, {"zen": "hi"}, "ping")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


async def test_webhook_alias_path_works(client: AsyncClient) -> None:
    _overrides()
    body = json.dumps({"zen": "hi"}).encode()
    headers = {
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(body),
    }
    # The alias /v1/webhooks/github resolves to the same handler as /v1/github/webhook.
    resp = await client.post("/v1/webhooks/github", content=body, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# --- installation sync --------------------------------------------------------------------------


async def test_installation_event_syncs_org_and_repos(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    _overrides()
    payload = {
        "action": "created",
        "installation": {"id": 5001, "account": {"login": "acme", "id": 42}},
        "sender": {"login": "octo-admin", "id": 999, "avatar_url": "http://a/x.png"},
        "repositories": [
            {"id": 777, "name": "web", "full_name": "acme/web", "private": True},
        ],
    }
    resp = await _post(client, payload, "installation")
    assert resp.status_code == 200

    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        assert org.github_org_id == 42
        inst = (
            await session.execute(
                select(Installation).where(Installation.github_installation_id == 5001)
            )
        ).scalar_one()
        assert inst.org_id == org.id
        repo = (
            await session.execute(select(Repository).where(Repository.github_repo_id == 777))
        ).scalar_one()
        assert repo.name == "web" and repo.org_id == org.id


async def test_installation_links_installer_as_owner(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """The installing user (webhook ``sender``) becomes an owner member, so GET /v1/orgs sees it."""
    _overrides()
    payload = {
        "action": "created",
        "installation": {"id": 5050, "account": {"login": "acme", "id": 42}},
        "sender": {"login": "octo-admin", "id": 999, "avatar_url": "http://a/x.png"},
        "repositories": [],
    }
    resp = await _post(client, payload, "installation")
    assert resp.status_code == 200

    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        user = (await session.execute(select(User).where(User.github_user_id == 999))).scalar_one()
        membership = (
            await session.execute(
                select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id)
            )
        ).scalar_one()
        assert membership.role == "owner"


# --- pull_request comment -----------------------------------------------------------------------


async def _seed_repo(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    repo_gid: int,
    with_scans: bool,
) -> None:
    async with sessionmaker() as session:
        org = Org(slug="acme", name="Acme", github_org_id=1)
        session.add(org)
        await session.flush()
        repo = Repository(org_id=org.id, name="web", github_repo_id=repo_gid)
        session.add(repo)
        await session.flush()
        if with_scans:
            base = Scan(
                repo_id=repo.id,
                commit_sha="basesha",
                ref="refs/heads/main",
                tool_version="1",
                degraded_sources=[],
                summary={},
            )
            head = Scan(
                repo_id=repo.id,
                commit_sha="headsha",
                ref="refs/heads/feature",
                tool_version="1",
                degraded_sources=[],
                summary={},
            )
            session.add_all([base, head])
            await session.flush()
            session.add(_finding(base.id, "jinja2", "GHSA-1"))
            session.add_all(
                [_finding(head.id, "jinja2", "GHSA-1"), _finding(head.id, "requests", "GHSA-3")]
            )
        await session.commit()


def _pr_payload(repo_gid: int) -> dict[str, Any]:
    return {
        "action": "opened",
        "number": 7,
        "repository": {"id": repo_gid, "full_name": "acme/web"},
        "pull_request": {
            "head": {"sha": "headsha", "ref": "refs/heads/feature"},
            "base": {"ref": "refs/heads/main"},
        },
        "installation": {"id": 99},
    }


async def test_pull_request_posts_diff_comment(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    fake = _overrides()
    await _seed_repo(sessionmaker, repo_gid=777, with_scans=True)

    resp = await _post(client, _pr_payload(777), "pull_request")
    assert resp.status_code == 200
    assert resp.json()["commented"] is True

    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["repo"] == "acme/web" and call["pr"] == 7 and call["installation_id"] == 99
    # The introduced finding (requests) is surfaced; the unchanged one (jinja2) is not "new".
    assert "requests" in call["body"]
    assert "VulnAdvisor" in call["body"]
    assert "1 new reachable finding" in call["body"]


async def test_pull_request_without_report_posts_pending(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    fake = _overrides()
    await _seed_repo(sessionmaker, repo_gid=777, with_scans=False)

    resp = await _post(client, _pr_payload(777), "pull_request")
    assert resp.status_code == 200
    assert len(fake.calls) == 1
    assert "Waiting for a scan report" in fake.calls[0]["body"]


async def test_pull_request_unsynced_repo_is_noop(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    fake = _overrides()
    # No repo with this github id exists -> nothing to comment on.
    resp = await _post(client, _pr_payload(999), "pull_request")
    assert resp.status_code == 200
    assert resp.json()["commented"] is False
    assert fake.calls == []


async def test_install_redirects(client: AsyncClient) -> None:
    resp = await client.get("/v1/github/install")
    assert resp.status_code == 307
    assert "github.com/apps/" in resp.headers["location"]


# --- pure helpers -------------------------------------------------------------------------------


def test_verify_signature() -> None:
    from vulnadvisor_platform.webhooks import verify_signature

    body = b'{"a": 1}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert verify_signature("s3cret", body, good) is True
    assert verify_signature("s3cret", body, "sha256=wrong") is False
    assert verify_signature("s3cret", body, None) is False
    assert verify_signature("", body, good) is False  # no configured secret -> fail closed


def test_render_pr_comment_clean_pr() -> None:
    from vulnadvisor_platform.pr_comment import MARKER, render_pr_comment

    body = render_pr_comment(introduced=[], fixed_count=2, repo="acme/web", pr_number=3)
    assert MARKER in body
    assert "No new reachable" in body
    assert "2 finding(s) fixed" in body


def test_render_pr_comment_uses_cve_first_display_id() -> None:
    from vulnadvisor_platform.pr_comment import render_pr_comment

    finding = {
        "dependency": {"name": "jinja2", "version": "2.11.2"},
        "advisory": {"id": "PYSEC-2026-52", "aliases": ["CVE-2020-28493"]},
        "score": {"value": 80.0, "band": "high"},
        "reachability": {"tier": "imported"},
        "fix": {"command": 'pip install --upgrade "jinja2>=2.11.3"'},
    }
    body = render_pr_comment(introduced=[finding], fixed_count=0, repo="acme/web", pr_number=1)
    # CVE-first display id, computed from id + aliases for pre-1.1 payloads.
    assert "CVE-2020-28493" in body
    # No "==" in display contexts; the fix command keeps its own pinning syntax.
    assert "`jinja2 2.11.2`" in body
    assert "jinja2==2.11.2" not in body


def test_render_pr_comment_prefers_report_display_id() -> None:
    from vulnadvisor_platform.pr_comment import render_pr_comment

    finding = {
        "dependency": {"name": "jinja2", "version": "2.11.2"},
        "advisory": {"id": "GHSA-462w-v97r-4m45", "display_id": "CVE-2020-28493"},
        "score": {"value": 80.0, "band": "high"},
        "reachability": {"tier": "imported"},
        "fix": {"command": "pip install --upgrade jinja2"},
    }
    body = render_pr_comment(introduced=[finding], fixed_count=0, repo="acme/web", pr_number=1)
    assert "CVE-2020-28493" in body


# --- setup PR (Task 14.2): webhook -> sync -> setup-PR flow --------------------------------------


def _install_payload() -> dict[str, Any]:
    """An installation event matching the conftest-seeded acme org (github_org_id=10) and
    octocat (github_user_id=1), so the seeded API key authenticates the installer afterwards."""
    return {
        "action": "created",
        "installation": {"id": 5001, "account": {"login": "acme", "id": 10}},
        "sender": {"login": "octocat", "id": 1},
        "repositories": [{"id": 777, "name": "web", "full_name": "acme/web", "private": True}],
    }


def _setup_pr_payload(*, action: str, merged: bool = False) -> dict[str, Any]:
    """A pull_request event for the App's own setup PR (head = vulnadvisor/setup)."""
    return {
        "action": action,
        "number": 7,
        "repository": {"id": 777, "full_name": "acme/web"},
        "pull_request": {
            "number": 7,
            "merged": merged,
            "html_url": "https://github.com/acme/web/pull/7",
            "head": {"sha": "setupsha", "ref": "vulnadvisor/setup"},
            "base": {"ref": "main"},
        },
        "installation": {"id": 5001},
    }


async def _repo_listing(client: AsyncClient, seeded_key: str) -> dict[str, Any]:
    resp = await client.get(
        "/v1/orgs/acme/repos", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 200
    repos = {repo["name"]: repo for repo in resp.json()}
    return repos["web"]


async def test_setup_pr_full_flow(client: AsyncClient, seeded_key: str) -> None:
    """Webhook install -> repo synced -> setup PR opened -> status chip flips to pr-open."""
    fake = _overrides()
    assert (await _post(client, _install_payload(), "installation")).status_code == 200

    before = await _repo_listing(client, seeded_key)
    assert before["github_linked"] is True
    assert before["setup_status"] == "not-set-up"

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "pr_number": 7,
        "pr_url": "https://github.com/acme/web/pull/7",
        "created": True,
    }

    call = fake.setup_calls[0]
    assert call["installation_id"] == 5001
    assert call["repo_full_name"] == "acme/web"
    assert call["base_branch"] == "main"
    assert call["file_path"] == ".github/workflows/vulnadvisor.yml"
    # The proposed workflow is valid YAML and runs the upload scan.
    workflow = yaml.safe_load(call["file_content"])
    assert workflow["jobs"]["vulnadvisor"]["steps"][-1]["run"] == "vulnadvisor scan . --upload"
    assert "VULNADVISOR_API_KEY" in call["pr_body"]

    after = await _repo_listing(client, seeded_key)
    assert after["setup_status"] == "pr-open"
    assert after["setup_pr_url"] == "https://github.com/acme/web/pull/7"


async def test_setup_pr_reclick_updates_not_duplicates(
    client: AsyncClient, seeded_key: str
) -> None:
    fake = _overrides()
    await _post(client, _install_payload(), "installation")
    headers = {"Authorization": f"Bearer {seeded_key}"}

    first = await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)
    second = await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)

    assert first.json()["created"] is True
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["pr_number"] == first.json()["pr_number"]
    assert len(fake.setup_calls) == 2
    assert (await _repo_listing(client, seeded_key))["setup_status"] == "pr-open"


async def test_setup_pr_lifecycle_via_webhook(client: AsyncClient, seeded_key: str) -> None:
    """The webhook tracks the setup PR open -> merged (and close-without-merge resets)."""
    fake = _overrides()
    await _post(client, _install_payload(), "installation")
    headers = {"Authorization": f"Bearer {seeded_key}"}
    await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)

    # Opened event for our own setup PR: state stays open, and we never comment on it.
    resp = await _post(client, _setup_pr_payload(action="opened"), "pull_request")
    assert resp.status_code == 200 and resp.json()["commented"] is False
    assert fake.calls == []
    assert (await _repo_listing(client, seeded_key))["setup_status"] == "pr-open"

    # Merged -> the chip moves forward (awaiting the first scan), keeping the PR link.
    await _post(client, _setup_pr_payload(action="closed", merged=True), "pull_request")
    merged = await _repo_listing(client, seeded_key)
    assert merged["setup_status"] == "pr-merged"
    assert merged["setup_pr_url"] == "https://github.com/acme/web/pull/7"

    # Closed without merging -> honestly back to "not set up".
    await _post(client, _setup_pr_payload(action="opened"), "pull_request")
    await _post(client, _setup_pr_payload(action="closed", merged=False), "pull_request")
    closed = await _repo_listing(client, seeded_key)
    assert closed["setup_status"] == "not-set-up"
    assert closed["setup_pr_url"] is None


async def test_setup_pr_receiving_scans_wins(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    _overrides()
    await _post(client, _install_payload(), "installation")
    headers = {"Authorization": f"Bearer {seeded_key}"}
    await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)

    async with sessionmaker() as session:
        repo = (
            await session.execute(select(Repository).where(Repository.github_repo_id == 777))
        ).scalar_one()
        session.add(
            Scan(
                repo_id=repo.id,
                commit_sha="feedface",
                ref="refs/heads/main",
                tool_version="1",
                degraded_sources=[],
                summary={},
            )
        )
        await session.commit()

    assert (await _repo_listing(client, seeded_key))["setup_status"] == "receiving-scans"


async def test_setup_pr_requires_github_linked_repo(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A CLI-upload-only repo (no github_repo_id) can't receive a setup PR -> 409."""
    _overrides()
    await _post(client, _install_payload(), "installation")
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        session.add(Repository(org_id=org.id, name="local-only", github_repo_id=None))
        await session.commit()

    resp = await client.post(
        "/v1/orgs/acme/repos/local-only/setup-pr",
        headers={"Authorization": f"Bearer {seeded_key}"},
    )
    assert resp.status_code == 409
    assert "not linked to GitHub" in resp.json()["detail"]


async def test_setup_pr_requires_installation(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A GitHub-linked repo whose org has no App installation -> 409 telling them to install."""
    _overrides()
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        session.add(Repository(org_id=org.id, name="web", github_repo_id=777))
        await session.commit()

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 409
    assert "install" in resp.json()["detail"].lower()


async def test_setup_pr_requires_admin_role(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    _overrides()
    await _post(client, _install_payload(), "installation")

    member_secret, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        member = User(login="junior", github_user_id=2)
        session.add(member)
        await session.flush()
        session.add(Membership(user_id=member.id, org_id=org.id, role=Role.MEMBER.value))
        session.add(
            ApiKey(
                org_id=org.id,
                name="member-key",
                hash=digest,
                prefix=prefix,
                created_by=member.id,
            )
        )
        await session.commit()

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {member_secret}"}
    )
    assert resp.status_code == 403


async def test_setup_pr_cross_org_is_404(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A user from another org gets 404 (tenant isolation: existence is never leaked)."""
    fake = _overrides()
    await _post(client, _install_payload(), "installation")

    outsider_secret, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        outsider = User(login="outsider", github_user_id=3)
        other_org = Org(slug="other", name="Other Inc")
        session.add_all([outsider, other_org])
        await session.flush()
        session.add(Membership(user_id=outsider.id, org_id=other_org.id, role=Role.OWNER.value))
        session.add(
            ApiKey(
                org_id=other_org.id,
                name="outsider-key",
                hash=digest,
                prefix=prefix,
                created_by=outsider.id,
            )
        )
        await session.commit()

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr",
        headers={"Authorization": f"Bearer {outsider_secret}"},
    )
    assert resp.status_code == 404
    assert fake.setup_calls == []


async def test_setup_pr_github_error_maps_to_502(client: AsyncClient, seeded_key: str) -> None:
    fake = _overrides()
    fake.fail_setup = True
    await _post(client, _install_payload(), "installation")

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 502
    assert "github is down" in resp.json()["detail"]
    # The failure left no half-recorded state behind.
    assert (await _repo_listing(client, seeded_key))["setup_status"] == "not-set-up"


# --- installation token (RS256 JWT) -------------------------------------------------------------


def _rsa_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


def test_app_jwt_is_valid_rs256() -> None:
    import jwt

    from vulnadvisor_platform.config import Settings
    from vulnadvisor_platform.github_app import GitHubApp

    private_pem, public_pem = _rsa_keypair()
    app_client = GitHubApp(Settings(github_app_id="12345", github_app_private_key=private_pem))
    claims = jwt.decode(app_client._app_jwt(), public_pem, algorithms=["RS256"])
    assert claims["iss"] == "12345"
    assert claims["exp"] > claims["iat"]


async def test_installation_token_exchange(monkeypatch: Any) -> None:
    import httpx
    import jwt

    from vulnadvisor_platform import github_app as ga
    from vulnadvisor_platform.config import Settings

    private_pem, public_pem = _rsa_keypair()
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(201, json={"token": "ghs_live", "expires_at": "2026-01-01T00:00:00Z"})

    real_async_client = httpx.AsyncClient  # capture before patching to avoid self-recursion
    monkeypatch.setattr(
        ga.httpx,
        "AsyncClient",
        lambda **kw: real_async_client(transport=httpx.MockTransport(handler)),
    )
    app_client = ga.GitHubApp(Settings(github_app_id="12345", github_app_private_key=private_pem))

    token = await app_client._installation_token(987)
    assert token == "ghs_live"
    assert seen["url"].endswith("/app/installations/987/access_tokens")
    # The JWT we sent GitHub is a valid RS256 token signed by our key.
    sent_jwt = seen["auth"].removeprefix("Bearer ")
    assert jwt.decode(sent_jwt, public_pem, algorithms=["RS256"])["iss"] == "12345"


async def test_installation_token_requires_config() -> None:
    import pytest

    from vulnadvisor_platform.config import Settings
    from vulnadvisor_platform.github_app import GitHubApp, GitHubAppError

    app_client = GitHubApp(Settings())  # no app credentials configured
    with pytest.raises(GitHubAppError):
        await app_client._installation_token(1)
