"""GitHub OAuth login flow with a mocked GitHub client (no network).

Proves the round-trip: login redirects with CSRF state, the callback upserts the user and sets a
session cookie that then authenticates ``/v1/me``, and logout clears it.
"""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.github_oauth import GitHubUser, get_oauth
from vulnadvisor_platform.models import Org

_GH_USER = GitHubUser(id=4242, login="octonaut", email="o@example.com", avatar_url="http://a/x.png")


class _FakeOAuth:
    def __init__(self, user: GitHubUser) -> None:
        self._user = user

    def authorize_url(self, state: str) -> str:
        return f"https://github.com/login/oauth/authorize?client_id=test&state={state}"

    async def exchange_code(self, code: str) -> str:
        return f"token-{code}"

    async def fetch_user(self, token: str) -> GitHubUser:
        return self._user


def _use_fake_oauth(user: GitHubUser = _GH_USER) -> None:
    app.dependency_overrides[get_oauth] = lambda: _FakeOAuth(user)


async def test_login_redirects_to_github(client: AsyncClient) -> None:
    _use_fake_oauth()
    resp = await client.get("/v1/auth/github/login")
    assert resp.status_code == 307
    assert "github.com/login/oauth/authorize" in resp.headers["location"]
    assert "va_oauth_state" in resp.cookies  # CSRF state stored for the callback


async def test_callback_logs_in_and_session_authenticates(client: AsyncClient) -> None:
    _use_fake_oauth()
    login = await client.get("/v1/auth/github/login")
    state = login.cookies["va_oauth_state"]

    callback = await client.get(f"/v1/auth/github/callback?code=abc&state={state}")
    assert callback.status_code == 307  # redirect to the dashboard

    # The session cookie now authenticates the dashboard.
    me = await client.get("/v1/me")
    assert me.status_code == 200
    assert me.json()["login"] == "octonaut"


async def test_callback_backfills_personal_org_membership(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A GitHub App installed on the user's own account before first login is linked at login."""
    _use_fake_oauth()  # _GH_USER.id == 4242
    async with sessionmaker() as session:
        # Personal-account org (github_org_id == the user's github id), no membership yet.
        session.add(Org(slug="octonaut", name="octonaut", github_org_id=4242))
        await session.commit()

    login = await client.get("/v1/auth/github/login")
    state = login.cookies["va_oauth_state"]
    await client.get(f"/v1/auth/github/callback?code=abc&state={state}")

    orgs = await client.get("/v1/orgs")
    assert orgs.status_code == 200
    assert any(o["slug"] == "octonaut" for o in orgs.json())


async def test_callback_rejects_bad_state(client: AsyncClient) -> None:
    _use_fake_oauth()
    # No matching state cookie -> CSRF check fails.
    resp = await client.get("/v1/auth/github/callback?code=abc&state=wrong")
    assert resp.status_code == 400


async def test_logout_clears_session(client: AsyncClient) -> None:
    _use_fake_oauth()
    login = await client.get("/v1/auth/github/login")
    state = login.cookies["va_oauth_state"]
    await client.get(f"/v1/auth/github/callback?code=abc&state={state}")
    assert (await client.get("/v1/me")).status_code == 200

    logout = await client.post("/v1/auth/logout")
    assert logout.status_code == 204
    assert (await client.get("/v1/me")).status_code == 401
