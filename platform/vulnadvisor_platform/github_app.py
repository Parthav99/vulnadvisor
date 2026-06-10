"""GitHub App client for posting PR comments (Task 11.6).

Exposed as a dependency so the webhook orchestration is testable with a fake. The comment upsert
(find-our-comment-or-create) is implemented against the REST API given an installation token;
minting that token requires signing a short-lived RS256 JWT with the App private key (a crypto
dependency we have not added yet), so :meth:`_installation_token` raises until the App is
provisioned. Tests inject a fake client, so the webhook -> diff -> comment path is fully exercised.
"""

from typing import Annotated

import httpx
from fastapi import Depends

from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.pr_comment import MARKER

_API = "https://api.github.com"


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

    async def _installation_token(self, installation_id: int | None) -> str:
        if not self._settings.github_app_id or not self._settings.github_app_private_key:
            raise GitHubAppError(
                "GitHub App credentials are not configured "
                "(set github_app_id and github_app_private_key)"
            )
        # Minting an installation access token requires signing an RS256 JWT with the App private
        # key, then exchanging it at /app/installations/{id}/access_tokens. RS256 needs a crypto
        # dependency we have not added; deferred until the App is provisioned.
        raise GitHubAppError("installation token minting is not yet implemented")


def get_github_app() -> GitHubApp:
    """FastAPI dependency providing the GitHub App client (override in tests)."""
    return GitHubApp(get_settings())


GitHubAppDep = Annotated[GitHubApp, Depends(get_github_app)]
