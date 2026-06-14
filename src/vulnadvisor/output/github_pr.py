"""Post validated fixes as in-line GitHub ``suggestion`` review comments from CI (Task 17.4).

The **zero-setup** path: a GitHub Actions workflow running ``vulnadvisor suggest`` posts one-click
``suggestion`` review comments using the built-in ``GITHUB_TOKEN`` — **no App, no webhook, no
platform**. The pull-request number and head sha are read from the Actions event payload
(``GITHUB_EVENT_PATH``) with ``GITHUB_SHA``/``GITHUB_REPOSITORY`` as fallbacks.

Stdlib-only (``urllib``) so the published wheel gains no runtime dependency (it mirrors
:mod:`vulnadvisor.output.upload`). The diff -> suggestion rendering is the *shared* pure renderer in
:mod:`vulnadvisor.output.pr_suggestion`, so this CI path and the GitHub App path (17.2) post the
identical comments.

Soundness carries over verbatim: the review event is always ``COMMENT`` (never ``REQUEST_CHANGES``,
never an auto-commit), and on every run we prune our own prior fix comments (found by
:data:`SUGGESTION_MARKER`) before reposting, so a fixed or moved line never strands a stale
suggestion. Defensive throughout: a malformed event payload yields ``None`` (a clean no-op), and any
network/HTTP failure raises a typed :class:`GitHubPostError` with context rather than a traceback.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from vulnadvisor.output.pr_suggestion import SUGGESTION_MARKER, ReviewComment

__all__ = [
    "GitHubHttp",
    "GitHubPostError",
    "GitHubResponse",
    "PullContext",
    "UrllibGitHubHttp",
    "parse_pr_event",
    "post_review_suggestions",
    "read_pr_context",
]

_API = "https://api.github.com"
_API_VERSION = "2022-11-28"
_PER_PAGE = 100
_MAX_PAGES = 20  # a PR with >2000 review comments is pathological; bound the prune scan.
_MAX_ERROR_BODY = 500


class GitHubPostError(RuntimeError):
    """Raised when posting in-line suggestions fails (network, auth, or a rejected request)."""


@dataclass(frozen=True)
class PullContext:
    """The pull request to comment on, resolved from the Actions environment."""

    repo_full_name: str
    pr_number: int
    head_sha: str


@dataclass(frozen=True)
class GitHubResponse:
    """A GitHub REST response: the HTTP status and raw body (HTTP errors are returned, not raised).

    Returning 4xx/5xx as a value (rather than raising) lets the caller tolerate an expected 404 when
    deleting an already-gone comment while still surfacing a genuine failure.
    """

    status: int
    body: bytes


class GitHubHttp(Protocol):
    """Minimal HTTP surface for the GitHub REST API (a fake is injected in tests)."""

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> GitHubResponse:
        """Perform a request, returning the response (incl. 4xx/5xx) or raising on network error."""
        ...


class UrllibGitHubHttp:
    """A :class:`GitHubHttp` backed by the standard library ``urllib`` (no added dependency)."""

    def __init__(self, timeout: float = 15.0) -> None:
        """Create a transport whose requests time out after ``timeout`` seconds."""
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> GitHubResponse:
        """Perform the request; an HTTP error status becomes a response, a network error a raise."""
        request = urllib.request.Request(  # noqa: S310 - fixed api.github.com host
            url, data=body, method=method, headers=dict(headers or {})
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                return GitHubResponse(status=response.status, body=response.read())
        except urllib.error.HTTPError as exc:
            return GitHubResponse(status=exc.code, body=exc.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise GitHubPostError(f"{method} {url} failed: {exc}") from exc


def _str(value: Any) -> str | None:
    """``value`` if it is a non-empty string, else ``None`` (defensive payload access)."""
    return value if isinstance(value, str) and value else None


def parse_pr_event(
    payload: object, *, github_sha: str | None = None, repository: str | None = None
) -> PullContext | None:
    """Resolve the :class:`PullContext` from a parsed Actions event payload, or ``None``.

    Reads ``pull_request.number``/``pull_request.head.sha``/``repository.full_name`` from the
    ``pull_request`` (or ``pull_request_target``) event, falling back to the top-level ``number``,
    the ``GITHUB_SHA`` env, and ``GITHUB_REPOSITORY`` (``owner/repo``). Returns ``None`` when there
    is no pull-request context (e.g. a push event) or the payload is malformed — the caller treats
    that as a clean no-op rather than an error.
    """
    payload = payload if isinstance(payload, dict) else {}
    pull_request = payload.get("pull_request")
    pull_request = pull_request if isinstance(pull_request, dict) else {}
    repo_obj = payload.get("repository")
    repo_obj = repo_obj if isinstance(repo_obj, dict) else {}
    head = pull_request.get("head")
    head = head if isinstance(head, dict) else {}

    number = pull_request.get("number")
    if not isinstance(number, int) or isinstance(number, bool):
        top = payload.get("number")
        number = top if isinstance(top, int) and not isinstance(top, bool) else None
    if number is None:
        return None

    repo_full_name = _str(repo_obj.get("full_name")) or _str(repository)
    if repo_full_name is None or "/" not in repo_full_name:
        return None

    head_sha = _str(head.get("sha")) or _str(github_sha)
    if head_sha is None:
        return None

    return PullContext(repo_full_name=repo_full_name, pr_number=number, head_sha=head_sha)


def read_pr_context(env: Mapping[str, str]) -> PullContext | None:
    """Read + parse the Actions event file named by ``GITHUB_EVENT_PATH``, or ``None``.

    Defensive: a missing/unreadable file or non-JSON content yields ``None`` (a no-op), never a
    traceback. ``GITHUB_SHA`` and ``GITHUB_REPOSITORY`` provide fallbacks for the head sha and the
    ``owner/repo`` name when the payload omits them.
    """
    event_path = env.get("GITHUB_EVENT_PATH")
    payload: object = {}
    if event_path:
        try:
            with open(event_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            payload = {}
    return parse_pr_event(
        payload, github_sha=env.get("GITHUB_SHA"), repository=env.get("GITHUB_REPOSITORY")
    )


def _auth_headers(token: str) -> dict[str, str]:
    """Standard authenticated GitHub REST headers for a token (App installation or GITHUB_TOKEN)."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }


def _list_review_comments(
    http: GitHubHttp, ctx: PullContext, headers: Mapping[str, str]
) -> list[dict[str, Any]]:
    """List a PR's review comments across pages, returning only well-formed comment objects."""
    out: list[dict[str, Any]] = []
    base = f"{_API}/repos/{ctx.repo_full_name}/pulls/{ctx.pr_number}/comments"
    for page in range(1, _MAX_PAGES + 1):
        response = http.request("GET", f"{base}?per_page={_PER_PAGE}&page={page}", headers=headers)
        if response.status >= 400:
            raise GitHubPostError(_http_error("listing PR review comments", response))
        try:
            data = json.loads(response.body)
        except (ValueError, TypeError) as exc:
            raise GitHubPostError("GitHub returned a non-JSON comment list") from exc
        if not isinstance(data, list):
            break
        out.extend(item for item in data if isinstance(item, dict))
        if len(data) < _PER_PAGE:
            break
    return out


def _prune_our_comments(http: GitHubHttp, ctx: PullContext, headers: Mapping[str, str]) -> None:
    """Delete our own prior fix comments (by :data:`SUGGESTION_MARKER`); tolerate a gone 404."""
    for comment in _list_review_comments(http, ctx, headers):
        text = comment.get("body")
        comment_id = comment.get("id")
        if isinstance(text, str) and SUGGESTION_MARKER in text and isinstance(comment_id, int):
            response = http.request(
                "DELETE",
                f"{_API}/repos/{ctx.repo_full_name}/pulls/comments/{comment_id}",
                headers=headers,
            )
            if response.status not in (200, 204, 404):
                raise GitHubPostError(_http_error("deleting a stale suggestion", response))


def post_review_suggestions(
    http: GitHubHttp, *, token: str, ctx: PullContext, comments: list[ReviewComment]
) -> int:
    """Post ``comments`` as a single in-line ``COMMENT`` review, idempotently. Returns the count.

    Always prunes our own prior fix comments first (so a re-run on a synchronized PR updates them in
    place and a now-fixed finding's suggestion disappears), then — if any remain — posts one review
    whose event is ``COMMENT``. We never request changes and never auto-commit; the developer clicks
    "Commit suggestion". With no comments, pruning still runs and the function returns 0.
    """
    headers = _auth_headers(token)
    _prune_our_comments(http, ctx, headers)
    if not comments:
        return 0

    payload = {
        "commit_id": ctx.head_sha,
        "event": "COMMENT",
        "comments": [comment.to_api() for comment in comments],
    }
    response = http.request(
        "POST",
        f"{_API}/repos/{ctx.repo_full_name}/pulls/{ctx.pr_number}/reviews",
        body=json.dumps(payload).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"},
    )
    if response.status >= 400:
        raise GitHubPostError(_http_error("posting the suggestion review", response))
    return len(comments)


def _http_error(context: str, response: GitHubResponse) -> str:
    """A contextual error message including GitHub's status and a snippet of its body."""
    detail = response.body.decode("utf-8", "replace")[:_MAX_ERROR_BODY].strip()
    hint = f": {detail}" if detail else ""
    return f"{context}: GitHub returned HTTP {response.status}{hint}"
