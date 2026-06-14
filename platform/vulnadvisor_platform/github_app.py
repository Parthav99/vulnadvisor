"""GitHub App client for posting PR comments (Task 11.6) and opening setup PRs (Task 14.2).

Exposed as a dependency so the webhook orchestration is testable with a fake. The comment upsert
(find-our-comment-or-create) is implemented against the REST API given an installation token, which
is minted by signing a short-lived RS256 JWT with the App private key and exchanging it. If the App
credentials are not configured, token minting raises a clear error. Tests inject a fake client, so
the webhook -> diff -> comment path is exercised without network or credentials.
"""

import base64
import time
from dataclasses import dataclass
from typing import Annotated, Any

import httpx
import jwt
from fastapi import Depends

from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.pr_comment import MARKER
from vulnadvisor_platform.pr_suggestion import SUGGESTION_MARKER, ReviewComment
from vulnadvisor_platform.setup_pr import SETUP_BRANCH

_API = "https://api.github.com"
# A GitHub App JWT may live at most 10 minutes; we use a shorter window plus backdated iat for skew.
_JWT_TTL_SECONDS = 540
_JWT_SKEW_SECONDS = 60


class GitHubAppError(RuntimeError):
    """Raised when the GitHub App is not configured or the API rejects a request."""


@dataclass(frozen=True)
class SetupPr:
    """The setup PR that now exists for a repo — freshly created or updated in place."""

    number: int
    url: str
    created: bool


def _ok(response: httpx.Response, context: str) -> Any:
    """Return the parsed JSON body, or raise a contextual :class:`GitHubAppError` on >= 400."""
    if response.status_code >= 400:
        raise GitHubAppError(
            f"{context}: GitHub returned {response.status_code}{_github_message(response)}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise GitHubAppError(f"{context}: GitHub returned a non-JSON body") from exc


def _github_message(response: httpx.Response) -> str:
    """GitHub's human-readable error ``message`` in parens, or ``""`` — defensive, never raises.

    GitHub puts the real reason here (e.g. "refusing to allow a GitHub App to create or update
    workflow `.github/workflows/...` without `workflows` permission"); surfacing it turns an opaque
    502 into an actionable one.
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str) and message:
            return f" ({message})"
    return ""


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

    async def post_or_update_suggestions(
        self,
        *,
        installation_id: int | None,
        repo_full_name: str,
        pr_number: int,
        head_sha: str,
        comments: list[ReviewComment],
    ) -> int:
        """Post validated fixes as in-line ``suggestion`` review comments, idempotently.

        On every push we first delete our own previous fix comments (found by
        :data:`SUGGESTION_MARKER`) so stale suggestions on moved lines never linger, then post a
        single review carrying the current ones. The review event is always ``COMMENT`` — we never
        request changes and never auto-commit; the developer clicks "Commit suggestion". Returns the
        number of in-line suggestions posted (0 when there are none, after pruning stale ones).
        """
        token = await self._installation_token(installation_id)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            listed = await client.get(
                f"{_API}/repos/{repo_full_name}/pulls/{pr_number}/comments",
                headers=headers,
                params={"per_page": "100"},
            )
            listed.raise_for_status()
            for comment in listed.json():
                if not isinstance(comment, dict):
                    continue
                text = comment.get("body")
                comment_id = comment.get("id")
                is_ours = isinstance(text, str) and SUGGESTION_MARKER in text
                if is_ours and isinstance(comment_id, int):
                    deleted = await client.delete(
                        f"{_API}/repos/{repo_full_name}/pulls/comments/{comment_id}",
                        headers=headers,
                    )
                    # A 404 means it is already gone — tolerate it; anything else is a real error.
                    if deleted.status_code not in (200, 204, 404):
                        deleted.raise_for_status()

            if not comments:
                return 0

            response = await client.post(
                f"{_API}/repos/{repo_full_name}/pulls/{pr_number}/reviews",
                headers=headers,
                json={
                    "commit_id": head_sha,
                    "event": "COMMENT",
                    "comments": [comment.to_api() for comment in comments],
                },
            )
            response.raise_for_status()
        return len(comments)

    async def open_setup_pr(
        self,
        *,
        installation_id: int | None,
        repo_full_name: str,
        base_branch: str,
        file_path: str,
        file_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
    ) -> SetupPr:
        """Open the setup PR as the GitHub App (installation token) — the org-wide bot path.

        Idempotency comes from the fixed branch name (:data:`SETUP_BRANCH`): the branch is created
        once from the base branch's head, the file commit is skipped when the branch already holds
        identical content, and an already-open PR from that branch is updated in place instead of
        opening a second one.
        """
        token = await self._installation_token(installation_id)
        return await self._open_setup_pr(
            token=token,
            repo_full_name=repo_full_name,
            base_branch=base_branch,
            file_path=file_path,
            file_content=file_content,
            commit_message=commit_message,
            pr_title=pr_title,
            pr_body=pr_body,
        )

    async def open_setup_pr_with_token(
        self,
        *,
        token: str,
        repo_full_name: str,
        base_branch: str,
        file_path: str,
        file_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
    ) -> SetupPr:
        """Open the setup PR as the logged-in user via their OAuth ``token`` — no App needed.

        The zero-App onboarding path (Task 17.4 Part 3): "Sign in with GitHub → set up repo" opens
        the PR under the user's own identity. Same idempotent branch/commit/PR logic as the App
        path; only the credential differs (a ``repo``/``workflow``-scoped OAuth token instead of an
        installation token).
        """
        return await self._open_setup_pr(
            token=token,
            repo_full_name=repo_full_name,
            base_branch=base_branch,
            file_path=file_path,
            file_content=file_content,
            commit_message=commit_message,
            pr_title=pr_title,
            pr_body=pr_body,
        )

    async def default_branch(
        self, *, installation_id: int | None, repo_full_name: str
    ) -> str | None:
        """The repo's current default branch as GitHub reports it (App path), or ``None``."""
        token = await self._installation_token(installation_id)
        return await self._default_branch(token=token, repo_full_name=repo_full_name)

    async def default_branch_with_token(self, *, token: str, repo_full_name: str) -> str | None:
        """The repo's current default branch via the user's OAuth ``token``, or ``None``."""
        return await self._default_branch(token=token, repo_full_name=repo_full_name)

    async def _default_branch(self, *, token: str, repo_full_name: str) -> str | None:
        """GET the repo and return its ``default_branch`` (defensively); ``None`` on any failure.

        The stored value can be stale or simply wrong: the ``installation_repositories`` webhook
        payload carries no ``default_branch``, so a freshly-synced repo sits at the model's
        ``"main"`` default even when its real default is ``"master"``. Resolving it from GitHub
        keeps both the workflow's push trigger and the PR base correct. A failure (network/
        permission/non-JSON) is non-fatal — it returns ``None`` so the caller uses the stored value.
        """
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{_API}/repos/{repo_full_name}", headers=headers)
        if response.status_code >= 400:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        branch = data.get("default_branch") if isinstance(data, dict) else None
        return branch if isinstance(branch, str) and branch else None

    async def _open_setup_pr(
        self,
        *,
        token: str,
        repo_full_name: str,
        base_branch: str,
        file_path: str,
        file_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
    ) -> SetupPr:
        """Open or idempotently update the setup PR using an already-minted ``token``."""
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        owner = repo_full_name.split("/", 1)[0]
        async with httpx.AsyncClient(timeout=10.0) as client:
            base = await client.get(
                f"{_API}/repos/{repo_full_name}/git/ref/heads/{base_branch}", headers=headers
            )
            if base.status_code == 404:
                raise GitHubAppError(f"base branch {base_branch!r} not found in {repo_full_name}")
            base_data = _ok(base, "resolving the base branch")
            base_object = base_data.get("object") if isinstance(base_data, dict) else None
            base_sha = base_object.get("sha") if isinstance(base_object, dict) else None
            if not isinstance(base_sha, str) or not base_sha:
                raise GitHubAppError("GitHub did not return the base branch sha")

            branch_ref = await client.get(
                f"{_API}/repos/{repo_full_name}/git/ref/heads/{SETUP_BRANCH}", headers=headers
            )
            if branch_ref.status_code == 404:
                created_ref = await client.post(
                    f"{_API}/repos/{repo_full_name}/git/refs",
                    headers=headers,
                    json={"ref": f"refs/heads/{SETUP_BRANCH}", "sha": base_sha},
                )
                _ok(created_ref, "creating the setup branch")
            else:
                _ok(branch_ref, "resolving the setup branch")

            encoded = base64.b64encode(file_content.encode("utf-8")).decode("ascii")
            existing_file = await client.get(
                f"{_API}/repos/{repo_full_name}/contents/{file_path}",
                params={"ref": SETUP_BRANCH},
                headers=headers,
            )
            file_payload: dict[str, str] = {
                "message": commit_message,
                "content": encoded,
                "branch": SETUP_BRANCH,
            }
            needs_commit = True
            if existing_file.status_code == 200:
                file_data = _ok(existing_file, "reading the existing workflow file")
                if isinstance(file_data, dict):
                    current = file_data.get("content")
                    # GitHub wraps base64 with newlines; compare whitespace-stripped.
                    if isinstance(current, str) and "".join(current.split()) == encoded:
                        needs_commit = False
                    sha = file_data.get("sha")
                    if isinstance(sha, str):
                        file_payload["sha"] = sha
            elif existing_file.status_code != 404:
                _ok(existing_file, "reading the existing workflow file")
            if needs_commit:
                put = await client.put(
                    f"{_API}/repos/{repo_full_name}/contents/{file_path}",
                    headers=headers,
                    json=file_payload,
                )
                _ok(put, "committing the workflow file")

            pulls = await client.get(
                f"{_API}/repos/{repo_full_name}/pulls",
                params={"head": f"{owner}:{SETUP_BRANCH}", "state": "open", "per_page": "1"},
                headers=headers,
            )
            listing = _ok(pulls, "listing open setup PRs")
            existing_pr = None
            if isinstance(listing, list) and listing and isinstance(listing[0], dict):
                existing_pr = listing[0]
            if existing_pr is not None:
                number = existing_pr.get("number")
                if not isinstance(number, int):
                    raise GitHubAppError("GitHub returned an open PR without a number")
                patched = await client.patch(
                    f"{_API}/repos/{repo_full_name}/pulls/{number}",
                    headers=headers,
                    json={"title": pr_title, "body": pr_body},
                )
                patched_data = _ok(patched, "updating the existing setup PR")
                return SetupPr(
                    number=number, url=self._html_url(patched_data, existing_pr), created=False
                )

            opened = await client.post(
                f"{_API}/repos/{repo_full_name}/pulls",
                headers=headers,
                json={
                    "title": pr_title,
                    "body": pr_body,
                    "head": SETUP_BRANCH,
                    "base": base_branch,
                },
            )
            opened_data = _ok(opened, "opening the setup PR")
            number = opened_data.get("number") if isinstance(opened_data, dict) else None
            if not isinstance(number, int):
                raise GitHubAppError("GitHub did not return the new PR's number")
            return SetupPr(number=number, url=self._html_url(opened_data), created=True)

    @staticmethod
    def _html_url(*candidates: Any) -> str:
        """The first ``html_url`` found in the candidate PR objects ("" when GitHub omits it)."""
        for candidate in candidates:
            if isinstance(candidate, dict):
                url = candidate.get("html_url")
                if isinstance(url, str) and url:
                    return url
        return ""

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
