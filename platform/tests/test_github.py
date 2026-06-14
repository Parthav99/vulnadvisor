"""GitHub App: HMAC webhook verification, installation sync, and the PR diff comment.

The webhook secret is injected via a settings override and the GitHub client is faked, so the full
verify -> dispatch -> diff -> comment path runs without network or real credentials.
"""

import hashlib
import hmac
import json
from typing import Any

import pytest
import yaml
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.copilot import encrypt_api_key
from vulnadvisor_platform.github_app import GitHubAppError, SetupPr, get_github_app
from vulnadvisor_platform.github_secrets import GitHubSecretsError, SecretResult, get_github_secrets
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


class _FakeSecrets:
    """Records repo-secret writes; can be made to fail to exercise the 502 path."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = False

    async def put_repo_secret(
        self, *, token: str, repo_full_name: str, secret_name: str, value: str
    ) -> SecretResult:
        self.calls.append(
            {
                "token": token,
                "repo_full_name": repo_full_name,
                "secret_name": secret_name,
                "value": value,
            }
        )
        if self.fail:
            raise GitHubSecretsError("Resource not accessible by integration")
        return SecretResult(secret_name=secret_name, created=True)


class _FakeApp:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.setup_calls: list[dict[str, Any]] = []
        self.suggestion_calls: list[dict[str, Any]] = []
        self.default_branch_calls: list[dict[str, Any]] = []
        # What GitHub reports as the repo's default branch. None = "couldn't determine" -> the route
        # keeps the stored value; a string self-heals it (e.g. a repo whose real default is master).
        self.default_branch_value: str | None = None
        self.fail_setup = False
        # The paired secrets fake, registered alongside in _overrides() and reachable from tests.
        self.secrets = _FakeSecrets()

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

    async def post_or_update_suggestions(
        self,
        *,
        installation_id: int | None,
        repo_full_name: str,
        pr_number: int,
        head_sha: str,
        comments: Any,
    ) -> int:
        self.suggestion_calls.append(
            {
                "installation_id": installation_id,
                "repo": repo_full_name,
                "pr": pr_number,
                "head_sha": head_sha,
                "comments": list(comments),
            }
        )
        return len(comments)

    async def default_branch(
        self, *, installation_id: int | None, repo_full_name: str
    ) -> str | None:
        self.default_branch_calls.append(
            {"installation_id": installation_id, "repo": repo_full_name}
        )
        return self.default_branch_value

    async def default_branch_with_token(self, *, token: str, repo_full_name: str) -> str | None:
        self.default_branch_calls.append({"token": token, "repo": repo_full_name})
        return self.default_branch_value

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

    async def open_setup_pr_with_token(self, **kwargs: Any) -> SetupPr:
        if self.fail_setup:
            raise GitHubAppError("github is down")
        self.setup_calls.append(kwargs)
        return SetupPr(
            number=8,
            url=f"https://github.com/{kwargs['repo_full_name']}/pull/8",
            created=len(self.setup_calls) == 1,
        )


def _overrides() -> _FakeApp:
    fake = _FakeApp()
    # A publicly-reachable api URL so the setup-PR url guard (Task C) passes; the localhost default
    # would be rejected. A dedicated test overrides this back to localhost to exercise the guard.
    app.dependency_overrides[get_settings] = lambda: Settings(
        github_webhook_secret=_SECRET, public_api_url="https://api.vulnadvisor.example"
    )
    app.dependency_overrides[get_github_app] = lambda: fake
    app.dependency_overrides[get_github_secrets] = lambda: fake.secrets
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


_SQLI_DIFF = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -10,3 +10,3 @@ def get(uid):\n"
    "     cur = conn.cursor()\n"
    '-    cur.execute("SELECT * FROM u WHERE id = %s" % uid)\n'
    '+    cur.execute("SELECT * FROM u WHERE id = %s", (uid,))\n'
    "     return cur.fetchone()\n"
)


def _stored_fix(diff: str = _SQLI_DIFF) -> dict[str, Any]:
    return {
        "finding_id": "app/db.py:11:sql-injection",
        "file": "app/db.py",
        "line": 11,
        "cwe": "CWE-89",
        "kind": "sql-injection",
        "title": "SQL injection",
        "tier": "CONFIRMED-FLOW",
        "flow": "get -> cursor.execute (app/db.py:11)",
        "rationale": "Parameterize the query.",
        "confidence": "high",
        "diff": diff,
    }


async def _seed_repo_with_suggestions(
    sessionmaker: async_sessionmaker[AsyncSession], *, fixes: list[dict[str, Any]]
) -> None:
    async with sessionmaker() as session:
        org = Org(slug="acme", name="Acme", github_org_id=1)
        session.add(org)
        await session.flush()
        repo = Repository(org_id=org.id, name="web", github_repo_id=777)
        session.add(repo)
        await session.flush()
        head = Scan(
            repo_id=repo.id,
            commit_sha="headsha",
            ref="refs/heads/feature",
            tool_version="1",
            degraded_sources=[],
            summary={},
            suggestions=fixes,
        )
        session.add(head)
        await session.flush()
        session.add(_finding(head.id, "requests", "GHSA-3"))
        await session.commit()


async def test_pull_request_posts_inline_suggestions(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    fake = _overrides()
    await _seed_repo_with_suggestions(sessionmaker, fixes=[_stored_fix()])

    resp = await _post(client, _pr_payload(777), "pull_request")
    assert resp.status_code == 200 and resp.json()["commented"] is True

    # A summary comment that points at the validated fix...
    assert len(fake.calls) == 1
    assert "1 validated fix" in fake.calls[0]["body"]
    # ...and an in-line suggestion anchored to the exact sink line on the head commit.
    assert len(fake.suggestion_calls) == 1
    call = fake.suggestion_calls[0]
    assert call["head_sha"] == "headsha" and call["pr"] == 7
    assert len(call["comments"]) == 1
    comment = call["comments"][0]
    assert comment.path == "app/db.py" and comment.line == 11
    assert "```suggestion" in comment.body


async def test_pull_request_unsuggestable_fix_posts_no_inline(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A fix whose patch only adds a new file cannot be a one-click suggestion -> none posted."""
    fake = _overrides()
    file_add = _stored_fix("--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+print('x')\n")
    await _seed_repo_with_suggestions(sessionmaker, fixes=[file_add])

    resp = await _post(client, _pr_payload(777), "pull_request")
    assert resp.status_code == 200
    # The suggestions call still fires (to prune any stale comments) but carries nothing.
    assert len(fake.suggestion_calls) == 1
    assert fake.suggestion_calls[0]["comments"] == []
    assert "validated fix" not in fake.calls[0]["body"]


async def test_pull_request_synchronize_reposts_suggestions(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A second delivery (synchronize) updates in place: the App is asked to repost each time."""
    fake = _overrides()
    await _seed_repo_with_suggestions(sessionmaker, fixes=[_stored_fix()])

    await _post(client, _pr_payload(777), "pull_request")
    sync = _pr_payload(777)
    sync["action"] = "synchronize"
    await _post(client, sync, "pull_request")

    assert len(fake.suggestion_calls) == 2
    assert all(len(call["comments"]) == 1 for call in fake.suggestion_calls)


async def test_install_redirects(client: AsyncClient) -> None:
    resp = await client.get("/v1/github/install")
    assert resp.status_code == 307
    assert "github.com/apps/" in resp.headers["location"]


async def test_post_or_update_suggestions_prunes_then_reposts(monkeypatch: Any) -> None:
    """The client deletes its own prior in-line comments (by marker) before posting a new review."""
    import httpx

    from vulnadvisor_platform import github_app as ga
    from vulnadvisor_platform.config import Settings
    from vulnadvisor_platform.pr_suggestion import SUGGESTION_MARKER, ReviewComment

    seen: dict[str, Any] = {"deleted": [], "posted": None}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_live"})
        if path.endswith(f"/pulls/{42}/comments") and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {"id": 1, "body": f"{SUGGESTION_MARKER}\nold fix"},
                    {"id": 2, "body": "a human comment"},
                ],
            )
        if "/pulls/comments/" in path and request.method == "DELETE":
            seen["deleted"].append(int(path.rsplit("/", 1)[1]))
            return httpx.Response(204)
        if path.endswith(f"/pulls/{42}/reviews") and request.method == "POST":
            import json as _json

            seen["posted"] = _json.loads(request.content)
            return httpx.Response(200, json={"id": 99})
        return httpx.Response(404)  # pragma: no cover - defensive

    private_pem, _ = _rsa_keypair()
    real = httpx.AsyncClient
    monkeypatch.setattr(
        ga.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler))
    )
    app_client = ga.GitHubApp(Settings(github_app_id="1", github_app_private_key=private_pem))

    comment = ReviewComment(
        path="app/db.py", start_line=None, line=11, side="RIGHT", body=f"{SUGGESTION_MARKER}\nnew"
    )
    posted = await app_client.post_or_update_suggestions(
        installation_id=5,
        repo_full_name="acme/web",
        pr_number=42,
        head_sha="abc",
        comments=[comment],
    )
    assert posted == 1
    assert seen["deleted"] == [1]  # only our marked comment is pruned, not the human one
    assert seen["posted"]["event"] == "COMMENT"  # never REQUEST_CHANGES
    assert seen["posted"]["commit_id"] == "abc"
    assert seen["posted"]["comments"][0]["line"] == 11


async def test_open_setup_pr_surfaces_github_error_message(monkeypatch: Any) -> None:
    """A workflows-permission rejection on the file commit propagates GitHub's reason, not just 403.

    This is the live failure behind the opaque "GitHub rejected the request" 502: a GitHub App
    without the ``workflows`` permission can't commit a file under ``.github/workflows/``. The error
    must name that so the operator knows to grant the permission rather than guess.
    """
    import httpx

    from vulnadvisor_platform import github_app as ga
    from vulnadvisor_platform.config import Settings

    workflow_reason = (
        "refusing to allow a GitHub App to create or update workflow "
        "`.github/workflows/vulnadvisor.yml` without `workflows` permission"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_live"})
        if path.endswith("/git/ref/heads/main") and request.method == "GET":
            return httpx.Response(200, json={"object": {"sha": "basesha"}})
        if path.endswith("/git/ref/heads/vulnadvisor/setup") and request.method == "GET":
            return httpx.Response(404)
        if path.endswith("/git/refs") and request.method == "POST":
            return httpx.Response(201, json={})
        if path.endswith("/contents/.github/workflows/vulnadvisor.yml"):
            if request.method == "GET":
                return httpx.Response(404)
            return httpx.Response(403, json={"message": workflow_reason})  # PUT (the commit)
        return httpx.Response(404)  # pragma: no cover - defensive

    private_pem, _ = _rsa_keypair()
    real = httpx.AsyncClient
    monkeypatch.setattr(
        ga.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler))
    )
    app_client = ga.GitHubApp(Settings(github_app_id="1", github_app_private_key=private_pem))

    with pytest.raises(GitHubAppError) as excinfo:
        await app_client.open_setup_pr(
            installation_id=5,
            repo_full_name="acme/web",
            base_branch="main",
            file_path=".github/workflows/vulnadvisor.yml",
            file_content="name: VulnAdvisor\n",
            commit_message="Add workflow",
            pr_title="Add VulnAdvisor",
            pr_body="body",
        )
    message = str(excinfo.value)
    assert "committing the workflow file" in message  # which step failed
    assert "403" in message
    assert "workflows` permission" in message  # GitHub's own reason, surfaced


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
    # App path with no user OAuth token: the PR opens but no secret is auto-written (the App is not
    # granted secrets:write), so secret_set is False and the dashboard will offer to grant access.
    assert data == {
        "pr_number": 7,
        "pr_url": "https://github.com/acme/web/pull/7",
        "created": True,
        "secret_set": False,
    }
    assert fake.secrets.calls == []

    call = fake.setup_calls[0]
    assert call["installation_id"] == 5001
    assert call["repo_full_name"] == "acme/web"
    assert call["base_branch"] == "main"
    assert call["file_path"] == ".github/workflows/vulnadvisor.yml"
    # The proposed workflow is valid YAML, runs the upload scan, and posts PR fix suggestions.
    workflow = yaml.safe_load(call["file_content"])
    steps = workflow["jobs"]["vulnadvisor"]["steps"]
    assert steps[-2]["run"] == "vulnadvisor scan . --upload"
    assert steps[-1]["run"] == "vulnadvisor suggest"
    assert "VULNADVISOR_API_KEY" in call["pr_body"]

    after = await _repo_listing(client, seeded_key)
    assert after["setup_status"] == "pr-open"
    assert after["setup_pr_url"] == "https://github.com/acme/web/pull/7"


async def test_setup_pr_self_heals_wrong_default_branch(
    client: AsyncClient, seeded_key: str
) -> None:
    """A repo whose real default is 'master' (stored as the 'main' default) is resolved from GitHub.

    The installation_repositories webhook carries no default_branch, so the row sits at 'main'.
    Left uncorrected the PR would branch off a non-existent base and the workflow would only run on
    a dead 'main' push trigger. The setup-PR endpoint asks GitHub for the real branch and uses it.
    """
    fake = _overrides()
    fake.default_branch_value = "master"  # GitHub reports the repo's real default branch
    assert (await _post(client, _install_payload(), "installation")).status_code == 200
    # Sanity: the row was synced with the stale 'main' default before setup runs.
    assert (await _repo_listing(client, seeded_key))["default_branch"] == "main"

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 200

    # The PR is branched off 'master', and the workflow's push trigger targets 'master', not 'main'.
    # (Assert on the rendered text: PyYAML parses the bare `on:` key as the boolean True.)
    call = fake.setup_calls[0]
    assert call["base_branch"] == "master"
    assert 'branches: ["master"]' in call["file_content"]
    # The stored value is self-healed so the dashboard and future scans stay correct.
    assert (await _repo_listing(client, seeded_key))["default_branch"] == "master"


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


async def _seed_oauth_token(
    sessionmaker: async_sessionmaker[AsyncSession], *, token: str, scopes: str
) -> None:
    """Give the seeded owner (octocat) a stored GitHub OAuth token + scopes, and a GitHub repo."""
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        session.add(Repository(org_id=org.id, name="web", github_repo_id=777))
        owner = (await session.execute(select(User).where(User.github_user_id == 1))).scalar_one()
        owner.github_token_ciphertext = encrypt_api_key(Settings().secret_key, token)
        owner.github_token_scopes = scopes
        await session.commit()


async def test_setup_pr_via_oauth_token_when_no_app(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """No App installed, but the user signed in with repo/workflow scope -> PR opens via OAuth."""
    fake = _overrides()
    await _seed_oauth_token(
        sessionmaker, token="gho_writetoken", scopes="read:user user:email repo workflow"
    )

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "pr_number": 8,
        "pr_url": "https://github.com/octocat/web/pull/8",
        "created": True,
        "secret_set": True,
    }
    # Opened as the user via their OAuth token — not the App installation-token path.
    call = fake.setup_calls[0]
    assert "installation_id" not in call
    assert call["token"] == "gho_writetoken"
    assert call["repo_full_name"] == "octocat/web"
    # The same OAuth token wrote VULNADVISOR_API_KEY to the repo, with a freshly minted key value.
    secret_call = fake.secrets.calls[0]
    assert secret_call["token"] == "gho_writetoken"
    assert secret_call["repo_full_name"] == "octocat/web"
    assert secret_call["secret_name"] == "VULNADVISOR_API_KEY"
    assert secret_call["value"]  # a non-empty minted key
    assert (await _repo_listing(client, seeded_key))["setup_status"] == "pr-open"

    # The minted key was persisted (so it's listable/revocable), named for the repo.
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        keys = (
            (
                await session.execute(
                    select(ApiKey).where(ApiKey.org_id == org.id, ApiKey.name == "setup:web")
                )
            )
            .scalars()
            .all()
        )
        assert len(keys) == 1
        assert keys[0].revoked_at is None


async def test_setup_pr_oauth_reclick_rotates_key(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """Re-clicking writes a fresh secret each time but never leaves more than one live setup key."""
    fake = _overrides()
    await _seed_oauth_token(
        sessionmaker, token="gho_writetoken", scopes="read:user user:email repo workflow"
    )
    headers = {"Authorization": f"Bearer {seeded_key}"}

    await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)
    await client.post("/v1/orgs/acme/repos/web/setup-pr", headers=headers)

    # A new key value was pushed on each click...
    assert len(fake.secrets.calls) == 2
    assert fake.secrets.calls[0]["value"] != fake.secrets.calls[1]["value"]
    # ...but only one live setup:web key remains; the first was revoked (no live-key sprawl).
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        keys = (
            (
                await session.execute(
                    select(ApiKey).where(ApiKey.org_id == org.id, ApiKey.name == "setup:web")
                )
            )
            .scalars()
            .all()
        )
        active = [k for k in keys if k.revoked_at is None]
        assert len(keys) == 2
        assert len(active) == 1


async def test_setup_pr_secret_write_failure_maps_to_502(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """If GitHub rejects the secret write, the endpoint 502s; the open PR stays honest."""
    fake = _overrides()
    fake.secrets.fail = True
    await _seed_oauth_token(
        sessionmaker, token="gho_writetoken", scopes="read:user user:email repo workflow"
    )

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 502
    assert "VULNADVISOR_API_KEY" in resp.json()["detail"]
    # The PR did open (its state is committed before the secret step); only the secret failed.
    assert (await _repo_listing(client, seeded_key))["setup_status"] == "pr-open"
    # No key is persisted on failure (it's added only after GitHub accepts the secret).
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        keys = (
            (
                await session.execute(
                    select(ApiKey).where(ApiKey.org_id == org.id, ApiKey.name == "setup:web")
                )
            )
            .scalars()
            .all()
        )
        assert keys == []


async def test_setup_pr_oauth_insufficient_scope_409(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A read-only OAuth token (no repo/workflow) -> 409 directing the user to (re-)authorize."""
    fake = _overrides()
    await _seed_oauth_token(sessionmaker, token="gho_readonly", scopes="read:user user:email")

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 409
    assert "grant repository access" in resp.json()["detail"]
    assert fake.setup_calls == []


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


async def test_setup_pr_localhost_config_falls_back_to_request_host(
    client: AsyncClient, seeded_key: str
) -> None:
    """An unset PUBLIC_API_URL falls back to the public URL the request arrived on.

    A correctly-deployed platform that simply never set PUBLIC_API_URL still opens a working PR:
    the request reaches the platform over its public ingress (here the test client's https host),
    so the workflow bakes that URL instead of erroring.
    """
    fake = _overrides()
    # Leave PUBLIC_API_URL at the unreachable dev default; the request host should win instead.
    app.dependency_overrides[get_settings] = lambda: Settings(
        github_webhook_secret=_SECRET, public_api_url="http://localhost:8000"
    )
    await _post(client, _install_payload(), "installation")

    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr", headers={"Authorization": f"Bearer {seeded_key}"}
    )
    assert resp.status_code == 200
    # The PR was opened; the workflow baked the request's public URL (https://test), not localhost.
    assert len(fake.setup_calls) == 1
    workflow = fake.setup_calls[0]["file_content"]
    assert "https://test" in workflow
    assert "localhost" not in workflow


async def test_setup_pr_no_reachable_api_url_blocked(client: AsyncClient, seeded_key: str) -> None:
    """When neither config nor the request host is reachable (pure local dev), setup is refused."""
    fake = _overrides()
    app.dependency_overrides[get_settings] = lambda: Settings(
        github_webhook_secret=_SECRET, public_api_url="http://localhost:8000"
    )
    await _post(client, _install_payload(), "installation")

    # Force the request itself to arrive on a loopback host so the fallback can't rescue it.
    resp = await client.post(
        "/v1/orgs/acme/repos/web/setup-pr",
        headers={"Authorization": f"Bearer {seeded_key}", "host": "localhost"},
    )
    assert resp.status_code == 500
    assert "PUBLIC_API_URL" in resp.json()["detail"]
    # Nothing was attempted on GitHub, and no setup state was recorded.
    assert fake.setup_calls == []
    assert fake.secrets.calls == []


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
