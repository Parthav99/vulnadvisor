"""GitHub OAuth login flow with a mocked GitHub client (no network).

Proves the round-trip: login redirects with CSRF state, the callback upserts the user and sets a
session cookie that then authenticates ``/v1/me``, and logout clears it.
"""

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings
from vulnadvisor_platform.copilot import decrypt_api_key
from vulnadvisor_platform.github_oauth import GitHubUser, OAuthToken, get_oauth
from vulnadvisor_platform.models import Org, User

_GH_USER = GitHubUser(id=4242, login="octonaut", email="o@example.com", avatar_url="http://a/x.png")
_LOGIN_SCOPES = ("read:user", "user:email")
_SETUP_SCOPES = ("read:user", "user:email", "repo", "workflow")


class _FakeOAuth:
    def __init__(self, user: GitHubUser, scopes: tuple[str, ...]) -> None:
        self._user = user
        self._scopes = scopes

    def authorize_url(self, state: str, *, write_access: bool = False) -> str:
        scope = "repo+workflow" if write_access else "read:user+user:email"
        return f"https://github.com/login/oauth/authorize?scope={scope}&state={state}"

    async def exchange_code(self, code: str) -> OAuthToken:
        return OAuthToken(access_token=f"token-{code}", scopes=self._scopes)

    async def fetch_user(self, token: str) -> GitHubUser:
        return self._user


def _use_fake_oauth(user: GitHubUser = _GH_USER, scopes: tuple[str, ...] = _LOGIN_SCOPES) -> None:
    app.dependency_overrides[get_oauth] = lambda: _FakeOAuth(user, scopes)


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


async def test_login_setup_requests_write_scope(client: AsyncClient) -> None:
    """``?setup=1`` asks GitHub for the elevated repo/workflow scopes; plain login does not."""
    _use_fake_oauth()
    plain = await client.get("/v1/auth/github/login")
    setup = await client.get("/v1/auth/github/login?setup=1")
    assert "repo" not in plain.headers["location"]
    assert "repo+workflow" in setup.headers["location"]


async def test_callback_persists_token_encrypted(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """The OAuth token is stored encrypted (not plaintext) with its granted scopes."""
    _use_fake_oauth()
    login = await client.get("/v1/auth/github/login")
    state = login.cookies["va_oauth_state"]
    await client.get(f"/v1/auth/github/callback?code=abc&state={state}")

    async with sessionmaker() as session:
        user = (await session.execute(select(User).where(User.github_user_id == 4242))).scalar_one()
    assert user.github_token_ciphertext is not None
    assert "token-abc" not in user.github_token_ciphertext  # encrypted at rest, not plaintext
    assert decrypt_api_key(Settings().secret_key, user.github_token_ciphertext) == "token-abc"
    assert user.github_token_scopes == "read:user user:email"  # read-only login, no write scope


async def test_callback_setup_persists_write_scopes(
    client: AsyncClient, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A setup re-authorization upgrades the stored token's scopes to include repo/workflow."""
    _use_fake_oauth(scopes=_SETUP_SCOPES)
    login = await client.get("/v1/auth/github/login?setup=1")
    state = login.cookies["va_oauth_state"]
    await client.get(f"/v1/auth/github/callback?code=xyz&state={state}")

    async with sessionmaker() as session:
        user = (await session.execute(select(User).where(User.github_user_id == 4242))).scalar_one()
    assert user.github_token_scopes == "read:user user:email repo workflow"


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
