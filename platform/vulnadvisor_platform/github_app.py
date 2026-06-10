"""GitHub App client for posting PR comments (Task 11.6).

Exposed as a dependency so the webhook orchestration is testable with a fake. The comment upsert
(find-our-comment-or-create) is implemented against the REST API given an installation token, which
is minted by signing a short-lived RS256 JWT with the App private key and exchanging it. If the App
credentials are not configured, token minting raises a clear error. Tests inject a fake client, so
the webhook -> diff -> comment path is exercised without network or credentials.
"""

import time
from typing import Annotated

import httpx
import jwt
from fastapi import Depends

from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.pr_comment import MARKER

_API = "https://api.github.com"
# A GitHub App JWT may live at most 10 minutes; we use a shorter window plus backdated iat for skew.
_JWT_TTL_SECONDS = 540
_JWT_SKEW_SECONDS = 60


class GitHubAppError(RuntimeError):
    """Raised when the GitHub App is not configured or the API rejects a request."""


class GitHubApp:
    """Posts or updates the single VulnAdvisor comment on a pull request."""

    def __init__(self, settings: Settings) -> None:
        """Bind to app settings (app id / private key / slug)."""
        self._settings = settings

    async def post_or_update_comment(
        self, *, installation_id: int | None, repo_full_name: str, pr_number: int, body: str
    ) -> None:
        """Create the VulnAdvisor PR comment, or update it in place if one already exists."""
        token = await self._installation_token(installation_id)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            listed = await client.get(
                f"{_API}/repos/{repo_full_name}/issues/{pr_number}/comments", headers=headers
            )
            listed.raise_for_status()
            existing_id = None
            for comment in listed.json():
                text = comment.get("body") if isinstance(comment, dict) else None
                if isinstance(text, str) and MARKER in text:
                    existing_id = comment.get("id")
                    break
            if existing_id is not None:
                response = await client.patch(
                    f"{_API}/repos/{repo_full_name}/issues/comments/{existing_id}",
                    headers=headers,
                    json={"body": body},
                )
            else:
                response = await client.post(
                    f"{_API}/repos/{repo_full_name}/issues/{pr_number}/comments",
                    headers=headers,
                    json={"body": body},
                )
            response.raise_for_status()

    def _app_jwt(self) -> str:
        """Sign a short-lived RS256 JWT with the App private key (issuer = App id)."""
        now = int(time.time())
        payload = {
            "iat": now - _JWT_SKEW_SECONDS,
            "exp": now + _JWT_TTL_SECONDS,
            "iss": self._settings.github_app_id,
        }
        try:
            return jwt.encode(payload, self._settings.github_app_private_key, algorithm="RS256")
        except (ValueError, TypeError) as exc:  # malformed/invalid private key
            raise GitHubAppError(f"could not sign GitHub App JWT: {exc}") from exc

    async def _installation_token(self, installation_id: int | None) -> str:
        """Mint an installation access token via the App JWT (RS256), or raise."""
        if not self._settings.github_app_id or not self._settings.github_app_private_key:
            raise GitHubAppError(
                "GitHub App credentials are not configured "
                "(set github_app_id and github_app_private_key)"
            )
        if installation_id is None:
            raise GitHubAppError("missing installation id for token exchange")

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{_API}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {self._app_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
        response.raise_for_status()
        token = response.json().get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub did not return an installation token")
        return token


def get_github_app() -> GitHubApp:
    """FastAPI dependency providing the GitHub App client (override in tests)."""
    return GitHubApp(get_settings())


GitHubAppDep = Annotated[GitHubApp, Depends(get_github_app)]
