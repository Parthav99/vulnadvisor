"""GitHub OAuth client for dashboard login (Task 11.5).

Thin, defensive wrapper over GitHub's OAuth web flow. Exposed as a FastAPI dependency
(:func:`get_oauth`) so tests can substitute a fake without any network access.
"""

from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import Depends

from vulnadvisor_platform.config import Settings, get_settings

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"


class OAuthError(RuntimeError):
    """Raised when GitHub returns an unexpected or malformed OAuth response."""


@dataclass(frozen=True)
class GitHubUser:
    """The subset of a GitHub user profile we persist."""

    id: int
    login: str
    email: str | None
    avatar_url: str | None


class GitHubOAuth:
    """Performs the GitHub OAuth code exchange and user lookup."""

    def __init__(self, settings: Settings) -> None:
        """Bind the client to the app ``settings`` (client id/secret/redirect)."""
        self._settings = settings

    def authorize_url(self, state: str) -> str:
        """The URL to redirect the browser to in order to start the OAuth flow."""
        query = urlencode(
            {
                "client_id": self._settings.github_client_id,
                "redirect_uri": self._settings.github_redirect_uri,
                "scope": "read:user user:email",
                "state": state,
                "allow_signup": "true",
            }
        )
        return f"{_AUTHORIZE_URL}?{query}"

    async def exchange_code(self, code: str) -> str:
        """Exchange an authorization ``code`` for an access token."""
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
        token = response.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise OAuthError("GitHub did not return an access token")
        return token

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


def get_oauth() -> GitHubOAuth:
    """FastAPI dependency providing the GitHub OAuth client (override in tests)."""
    return GitHubOAuth(get_settings())


OAuthDep = Annotated[GitHubOAuth, Depends(get_oauth)]
