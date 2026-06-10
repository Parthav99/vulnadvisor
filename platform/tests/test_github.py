"""GitHub App: HMAC webhook verification, installation sync, and the PR diff comment.

The webhook secret is injected via a settings override and the GitHub client is faked, so the full
verify -> dispatch -> diff -> comment path runs without network or real credentials.
"""

import hashlib
import hmac
import json
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.github_app import get_github_app
from vulnadvisor_platform.models import Finding, Installation, Org, Repository, Scan

_SECRET = "whsec_test"


class _FakeApp:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

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


# --- installation sync --------------------------------------------------------------------------


async def test_installation_event_syncs_org_and_repos(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    _overrides()
    payload = {
        "action": "created",
        "installation": {"id": 5001, "account": {"login": "acme", "id": 42}},
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
