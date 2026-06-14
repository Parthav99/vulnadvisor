"""Tests for the zero-setup CI PR-suggestion poster (Task 17.4).

The poster turns validated fixes into in-line GitHub ``suggestion`` review comments posted directly
from GitHub Actions with the built-in ``GITHUB_TOKEN`` — no App, no platform. These tests prove the
event-payload parsing (defensively, from a fixture payload) and the REST choreography (list -> prune
our own -> post one ``COMMENT`` review) against a fake GitHub, with no network.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from vulnadvisor.output.github_pr import (
    GitHubPostError,
    GitHubResponse,
    PullContext,
    UrllibGitHubHttp,
    parse_pr_event,
    post_review_suggestions,
    read_pr_context,
)
from vulnadvisor.output.pr_suggestion import SUGGESTION_MARKER, ReviewComment

# --- event payload parsing ----------------------------------------------------------------------


def _event(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "number": 7,
        "pull_request": {"number": 7, "head": {"sha": "headsha123"}},
        "repository": {"full_name": "acme/web"},
    }
    base.update(over)
    return base


def test_parse_pr_event_reads_number_sha_and_repo() -> None:
    ctx = parse_pr_event(_event())
    assert ctx == PullContext(repo_full_name="acme/web", pr_number=7, head_sha="headsha123")


def test_parse_pr_event_falls_back_to_top_level_number() -> None:
    payload = _event(pull_request={"head": {"sha": "deadbeef"}})
    ctx = parse_pr_event(payload)
    assert ctx is not None and ctx.pr_number == 7 and ctx.head_sha == "deadbeef"


def test_parse_pr_event_falls_back_to_env_repo_and_sha() -> None:
    payload = {"number": 3, "pull_request": {"number": 3}}
    ctx = parse_pr_event(payload, github_sha="abc123", repository="octo/repo")
    assert ctx == PullContext(repo_full_name="octo/repo", pr_number=3, head_sha="abc123")


@pytest.mark.parametrize(
    "payload",
    [
        {},  # no PR context (e.g. a push event)
        {"pull_request": {"head": {"sha": "x"}}, "repository": {"full_name": "a/b"}},  # no number
        {"number": 1, "repository": {"full_name": "a/b"}},  # no head sha anywhere
        {"number": 1, "pull_request": {"head": {"sha": "x"}}},  # no repo name anywhere
        {"number": 1, "pull_request": {"head": {"sha": "x"}}, "repository": {"full_name": "bad"}},
        "not-a-dict",
        None,
        {"number": True, "pull_request": {}},  # bool is not a valid PR number
    ],
)
def test_parse_pr_event_returns_none_on_no_context_or_malformed(payload: object) -> None:
    assert parse_pr_event(payload, github_sha=None, repository=None) is None


def test_read_pr_context_reads_the_event_file(tmp_path: Path) -> None:
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(_event()), encoding="utf-8")
    ctx = read_pr_context({"GITHUB_EVENT_PATH": str(event_file)})
    assert ctx is not None and ctx.pr_number == 7


def test_read_pr_context_missing_or_bad_file_is_none(tmp_path: Path) -> None:
    assert read_pr_context({}) is None
    assert read_pr_context({"GITHUB_EVENT_PATH": str(tmp_path / "nope.json")}) is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert read_pr_context({"GITHUB_EVENT_PATH": str(bad)}) is None


# --- posting against a fake GitHub --------------------------------------------------------------


class _FakeHttp:
    """A minimal fake of the GitHub REST endpoints the poster touches."""

    def __init__(
        self,
        *,
        pages: list[list[dict[str, Any]]] | None = None,
        delete_status: int = 204,
        review_status: int = 201,
    ) -> None:
        self.pages = pages if pages is not None else [[]]
        self.delete_status = delete_status
        self.review_status = review_status
        self.deleted: list[int] = []
        self.reviews: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str, Mapping[str, str]]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> GitHubResponse:
        self.requests.append((method, url, dict(headers or {})))
        if method == "GET":
            page = int(url.rsplit("page=", 1)[1])
            data = self.pages[page - 1] if page - 1 < len(self.pages) else []
            return GitHubResponse(200, json.dumps(data).encode())
        if method == "DELETE":
            self.deleted.append(int(url.rsplit("/", 1)[1]))
            return GitHubResponse(self.delete_status, b"")
        if method == "POST":
            assert body is not None
            self.reviews.append(json.loads(body))
            return GitHubResponse(self.review_status, b"{}")
        return GitHubResponse(500, b"unhandled")


_CTX = PullContext(repo_full_name="acme/web", pr_number=7, head_sha="headsha123")


def _comment(line: int = 11) -> ReviewComment:
    return ReviewComment(
        path="app/db.py",
        start_line=None,
        line=line,
        side="RIGHT",
        body=f"{SUGGESTION_MARKER}\n```suggestion\nfixed\n```",
    )


def test_post_review_suggestions_posts_a_comment_review() -> None:
    http = _FakeHttp()
    posted = post_review_suggestions(http, token="ghs_x", ctx=_CTX, comments=[_comment()])
    assert posted == 1
    assert len(http.reviews) == 1
    review = http.reviews[0]
    # Soundness: always a COMMENT review on the head sha, never REQUEST_CHANGES, never auto-commit.
    assert review["event"] == "COMMENT"
    assert review["commit_id"] == "headsha123"
    assert review["comments"][0]["path"] == "app/db.py"
    assert review["comments"][0]["line"] == 11
    assert review["comments"][0]["side"] == "RIGHT"


def test_post_review_sends_bearer_token_and_api_version() -> None:
    http = _FakeHttp()
    post_review_suggestions(http, token="ghs_secret", ctx=_CTX, comments=[_comment()])
    _, url, headers = http.requests[-1]
    assert url.endswith("/repos/acme/web/pulls/7/reviews")
    assert headers["Authorization"] == "Bearer ghs_secret"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_post_review_prunes_only_our_own_prior_comments() -> None:
    existing = [
        {"id": 1, "body": f"{SUGGESTION_MARKER}\nold suggestion"},
        {"id": 2, "body": "a human's review comment"},
        {"id": 3, "body": f"{SUGGESTION_MARKER}\nanother of ours"},
    ]
    http = _FakeHttp(pages=[existing])
    post_review_suggestions(http, token="t", ctx=_CTX, comments=[_comment()])
    # Only our marked comments are deleted; the human comment is untouched.
    assert http.deleted == [1, 3]
    assert len(http.reviews) == 1


def test_post_review_with_no_comments_still_prunes_and_posts_nothing() -> None:
    existing = [{"id": 9, "body": f"{SUGGESTION_MARKER}\nstale"}]
    http = _FakeHttp(pages=[existing])
    posted = post_review_suggestions(http, token="t", ctx=_CTX, comments=[])
    assert posted == 0
    assert http.deleted == [9]  # a now-fixed finding's suggestion is removed in place
    assert http.reviews == []  # no empty review posted


def test_post_review_tolerates_404_on_delete() -> None:
    existing = [{"id": 5, "body": f"{SUGGESTION_MARKER}\ngone already"}]
    http = _FakeHttp(pages=[existing], delete_status=404)
    posted = post_review_suggestions(http, token="t", ctx=_CTX, comments=[_comment()])
    assert posted == 1  # a 404 (already deleted) is not an error


def test_post_review_raises_on_delete_failure() -> None:
    existing = [{"id": 5, "body": f"{SUGGESTION_MARKER}\nx"}]
    http = _FakeHttp(pages=[existing], delete_status=500)
    with pytest.raises(GitHubPostError, match="deleting a stale suggestion"):
        post_review_suggestions(http, token="t", ctx=_CTX, comments=[_comment()])


def test_post_review_raises_on_review_post_failure() -> None:
    http = _FakeHttp(review_status=422)
    with pytest.raises(GitHubPostError, match="posting the suggestion review"):
        post_review_suggestions(http, token="t", ctx=_CTX, comments=[_comment()])


def test_post_review_paginates_the_comment_list() -> None:
    page1 = [{"id": i, "body": "human"} for i in range(100)]  # full page -> fetch the next
    page2 = [{"id": 999, "body": f"{SUGGESTION_MARKER}\nours on page 2"}]
    http = _FakeHttp(pages=[page1, page2])
    post_review_suggestions(http, token="t", ctx=_CTX, comments=[_comment()])
    assert http.deleted == [999]


# --- the urllib-backed transport (HTTP status mapping, no real network) -------------------------


def test_urllib_http_maps_http_error_status_to_response(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error
    import urllib.request

    def boom(*_a: object, **_k: object) -> object:
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, _Body(b'{"message":"x"}'))  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    response = UrllibGitHubHttp().request("DELETE", "https://api.github.com/x")
    assert response.status == 404 and b"x" in response.body


def test_urllib_http_raises_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error
    import urllib.request

    def boom(*_a: object, **_k: object) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(GitHubPostError, match="failed"):
        UrllibGitHubHttp().request("GET", "https://api.github.com/x")


class _Body:
    """A minimal stand-in for an ``HTTPError`` file object exposing ``read()``."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        """No-op; present so ``HTTPError``'s finalizer does not warn about a missing ``close``."""
