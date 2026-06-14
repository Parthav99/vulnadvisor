"""GitHub OAuth client for dashboard login (Task 11.5) + setup-PR authorization (Task 17.4).

Thin, defensive wrapper over GitHub's OAuth web flow. Exposed as a FastAPI dependency
(:func:`get_oauth`) so tests can substitute a fake without any network access.

Login requests only ``read:user user:email``. The elevated ``repo``/``workflow`` scopes needed to
open the zero-App setup PR (Task 17.4 Part 3) are requested **incrementally** — only when the user
asks to set up a repo (``authorize_url(..., write_access=True)``) — so an ordinary login never
grants write access. :func:`has_setup_scopes` answers "is this token write-capable?" from the
granted scopes recorded at exchange time.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import Depends

from vulnadvisor_platform.config import Settings, get_settings

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"

# The minimal login scopes, and the elevated scopes the setup PR needs: ``repo`` to create the
# branch/PR (private repos included) and ``workflow`` to commit a ``.github/workflows/*.yml`` file
# (GitHub rejects workflow-file writes without it).
_LOGIN_SCOPE = "read:user user:email"
_SETUP_SCOPE = "read:user user:email repo workflow"
SETUP_SCOPES: tuple[str, ...] = ("repo", "workflow")


class OAuthError(RuntimeError):
    """Raised when GitHub returns an unexpected or malformed OAuth response."""


@dataclass(frozen=True)
class OAuthToken:
    """An exchanged OAuth access token plus the scopes GitHub actually granted it."""

    access_token: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class GitHubUser:
    """The subset of a GitHub user profile we persist."""

    id: int
    login: str
    email: str | None
    avatar_url: str | None


def has_setup_scopes(scopes: Iterable[str]) -> bool:
    """True if ``scopes`` includes every scope the setup PR needs (``repo`` and ``workflow``)."""
    granted = set(scopes)
    return all(scope in granted for scope in SETUP_SCOPES)


class GitHubOAuth:
    """Performs the GitHub OAuth code exchange and user lookup."""

    def __init__(self, settings: Settings) -> None:
        """Bind the client to the app ``settings`` (client id/secret/redirect)."""
        self._settings = settings

    def authorize_url(self, state: str, *, write_access: bool = False) -> str:
        """The URL to redirect the browser to in order to start the OAuth flow.

        ``write_access`` requests the elevated ``repo``/``workflow`` scopes for the setup PR; the
        default keeps login least-privilege (read-only). Re-authorizing with the wider scope
        upgrades the same grant, so the persisted token gains write access without a second account.
        """
        query = urlencode(
            {
                "client_id": self._settings.github_client_id,
                "redirect_uri": self._settings.github_redirect_uri,
                "scope": _SETUP_SCOPE if write_access else _LOGIN_SCOPE,
                "state": state,
                "allow_signup": "true",
            }
        )
        return f"{_AUTHORIZE_URL}?{query}"

    async def exchange_code(self, code: str) -> OAuthToken:
        """Exchange an authorization ``code`` for an access token and its granted scopes."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                _TOKEN_URL,
                headers={"Accept": "application/json"},
                json={
                    "client_id": self._settings.github_client_id,
                    "client_secret": self._settings.github_client_secret,
                    "code": code,
                    "redirect_uri": self._settings.github_redirect_uri,
                },
            )
        response.raise_for_status()
        data = response.json()
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise OAuthError("GitHub did not return an access token")
        return OAuthToken(access_token=token, scopes=_parse_scopes(data.get("scope")))

    async def fetch_user(self, token: str) -> GitHubUser:
        """Fetch the authenticated user's profile with an access token."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                _USER_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        response.raise_for_status()
        data = response.json()
        user_id = data.get("id")
        login = data.get("login")
        if not isinstance(user_id, int) or not isinstance(login, str):
            raise OAuthError("GitHub returned a malformed user profile")
        email = data.get("email")
        avatar_url = data.get("avatar_url")
        return GitHubUser(
            id=user_id,
            login=login,
            email=email if isinstance(email, str) else None,
            avatar_url=avatar_url if isinstance(avatar_url, str) else None,
        )


def _parse_scopes(raw: object) -> tuple[str, ...]:
    """Parse GitHub's comma-separated ``scope`` field defensively into a tuple (empty if absent)."""
    if not isinstance(raw, str):
        return ()
    return tuple(scope.strip() for scope in raw.split(",") if scope.strip())


def get_oauth() -> GitHubOAuth:
    """FastAPI dependency providing the GitHub OAuth client (override in tests)."""
    return GitHubOAuth(get_settings())


OAuthDep = Annotated[GitHubOAuth, Depends(get_oauth)]
