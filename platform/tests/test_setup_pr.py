"""Task 14.2 — setup-PR content (snapshot + valid YAML) and the idempotent REST orchestration.

The workflow/PR-body renderers are pure, so they're snapshot- and structure-tested directly
(PyYAML proves the workflow parses). ``GitHubApp.open_setup_pr`` runs against a small stateful
fake of GitHub's REST API via ``httpx.MockTransport``, proving the branch/file/PR choreography:
create once, update in place forever, never a duplicate PR.
"""

import base64
import json
import re
from typing import Any

import httpx
import pytest
import yaml

from vulnadvisor_platform import github_app as ga
from vulnadvisor_platform.config import Settings
from vulnadvisor_platform.github_app import GitHubApp, GitHubAppError
from vulnadvisor_platform.setup_pr import (
    PR_STATE_MERGED,
    PR_STATE_OPEN,
    SETUP_BRANCH,
    SETUP_PR_TITLE,
    STATUS_NOT_SET_UP,
    STATUS_PR_MERGED,
    STATUS_PR_OPEN,
    STATUS_RECEIVING_SCANS,
    WORKFLOW_COMMIT_MESSAGE,
    WORKFLOW_PATH,
    api_url_problem,
    render_pr_body,
    render_workflow,
    setup_status,
)

_API_URL = "https://api.vulnadvisor.example"
_DASH_URL = "https://vulnadvisor.example"


# --- workflow rendering ---------------------------------------------------------------------------


EXPECTED_WORKFLOW = """\
# VulnAdvisor — reachability-aware dependency triage for Python.
#
# Scans on every push to main and on every pull request, then uploads the
# JSON report to your VulnAdvisor dashboard. On pull requests it also posts one-click,
# machine-validated fix suggestions in-line using the built-in GITHUB_TOKEN (no GitHub
# App needed). Only the report leaves CI — never your source code. The setup PR body
# explains the repository secrets.
name: VulnAdvisor

on:
  push:
    branches: ["main"]
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  vulnadvisor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install VulnAdvisor
        run: pip install vulnadvisor
      - name: Scan and upload the report
        env:
          VULNADVISOR_API_KEY: ${{ secrets.VULNADVISOR_API_KEY }}
          API_URL: "https://api.vulnadvisor.example"
        run: vulnadvisor scan . --upload
      - name: Suggest validated fixes on the pull request
        if: github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: vulnadvisor suggest
"""


def test_workflow_snapshot() -> None:
    assert render_workflow(default_branch="main", api_url=_API_URL) == EXPECTED_WORKFLOW


def test_workflow_is_valid_yaml_with_expected_structure() -> None:
    doc = yaml.safe_load(render_workflow(default_branch="main", api_url=_API_URL))
    # YAML 1.1 parses the bare `on` key as boolean True — that's what GitHub receives too.
    triggers = doc[True]
    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    # The suggest step needs pull-requests: write; the App is not required.
    assert doc["permissions"] == {"contents": "read", "pull-requests": "write"}
    job = doc["jobs"]["vulnadvisor"]
    assert job["runs-on"] == "ubuntu-latest"
    steps = job["steps"]
    assert steps[0]["uses"] == "actions/checkout@v4"
    assert steps[1]["uses"] == "actions/setup-python@v5"
    scan = steps[-2]
    assert scan["run"] == "vulnadvisor scan . --upload"
    assert scan["env"]["VULNADVISOR_API_KEY"] == "${{ secrets.VULNADVISOR_API_KEY }}"
    assert scan["env"]["API_URL"] == _API_URL
    # The zero-setup PR-suggestion step: GITHUB_TOKEN only, gated to pull requests.
    suggest = steps[-1]
    assert suggest["run"] == "vulnadvisor suggest"
    assert suggest["if"] == "github.event_name == 'pull_request'"
    assert suggest["env"]["GITHUB_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"
    assert suggest["env"]["OPENROUTER_API_KEY"] == "${{ secrets.OPENROUTER_API_KEY }}"


@pytest.mark.parametrize("branch", ["main", "master", "release/v1.0", "dev-2026"])
def test_workflow_branch_names_stay_valid_yaml(branch: str) -> None:
    doc = yaml.safe_load(render_workflow(default_branch=branch, api_url=_API_URL))
    assert doc[True]["push"]["branches"] == [branch]


# --- PR body --------------------------------------------------------------------------------------


def test_pr_body_explains_the_one_manual_step() -> None:
    body = render_pr_body(repo_full_name="acme/web", org_slug="acme", dashboard_url=_DASH_URL + "/")
    assert WORKFLOW_PATH in body
    assert "VULNADVISOR_API_KEY" in body
    # Direct link to where the key is minted (trailing slash on dashboard_url normalized away).
    assert f"{_DASH_URL}/orgs/acme/settings/api-keys" in body
    assert "acme/web" in body
    # The privacy posture and the device-flow alternative are both stated.
    assert "never leaves CI" in body
    assert "vulnadvisor login" in body
    # Idempotency is promised to the user in writing.
    assert "updates this PR in place" in body


# --- api-url guard --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.vulnadvisor.io",
        "https://vulnadvisor.example/api",
        "http://api.internal.acme.com:8000",  # a real DNS host (not an IP) — we don't resolve it
        "https://8.8.8.8",  # a public IP literal
    ],
)
def test_api_url_problem_accepts_public_urls(url: str) -> None:
    assert api_url_problem(url) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://LOCALHOST:8000",
        "https://app.localhost",
        "http://127.0.0.1:8000",
        "http://127.5.5.5",
        "http://[::1]:8000",
        "http://10.0.0.5",
        "http://192.168.1.10:8000",
        "http://172.16.4.4",
        "http://169.254.1.1",  # link-local
        "http://0.0.0.0:8000",  # unspecified
        "ftp://example.com",  # bad scheme
        "not-a-url",  # no scheme/host
        "https://",  # no host
    ],
)
def test_api_url_problem_rejects_unreachable_urls(url: str) -> None:
    problem = api_url_problem(url)
    assert problem is not None
    assert "PUBLIC_API_URL" in problem


# --- setup status ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scan_count", "state", "expected"),
    [
        (0, None, STATUS_NOT_SET_UP),
        (0, PR_STATE_OPEN, STATUS_PR_OPEN),
        (0, PR_STATE_MERGED, STATUS_PR_MERGED),
        (1, None, STATUS_RECEIVING_SCANS),
        # Received scans always win, whatever the PR state says.
        (3, PR_STATE_OPEN, STATUS_RECEIVING_SCANS),
        (3, PR_STATE_MERGED, STATUS_RECEIVING_SCANS),
        # Unknown stored state degrades to "not set up", never to a positive claim.
        (0, "weird", STATUS_NOT_SET_UP),
    ],
)
def test_setup_status(scan_count: int, state: str | None, expected: str) -> None:
    assert setup_status(scan_count=scan_count, setup_pr_state=state) == expected


# --- open_setup_pr against a stateful fake GitHub -------------------------------------------------


class _FakeGitHub:
    """A minimal stateful double for the GitHub REST endpoints ``open_setup_pr`` touches."""

    def __init__(self, *, base_branch: str = "main", base_sha: str = "abc123") -> None:
        self.refs: dict[str, str] = {f"heads/{base_branch}": base_sha}
        self.files: dict[tuple[str, str], dict[str, str]] = {}  # (branch, path) -> content/sha
        self.pulls: list[dict[str, Any]] = []
        self.commits = 0
        self.last_put_body: dict[str, Any] | None = None
        self._next_pr = 1
        self._next_sha = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method

        if method == "GET" and (m := re.match(r"^/repos/[^/]+/[^/]+/git/ref/(.+)$", path)):
            ref = m.group(1)
            if ref in self.refs:
                return httpx.Response(200, json={"object": {"sha": self.refs[ref]}})
            return httpx.Response(404, json={"message": "Not Found"})

        if method == "POST" and path.endswith("/git/refs"):
            body = json.loads(request.content)
            self.refs[body["ref"].removeprefix("refs/")] = body["sha"]
            return httpx.Response(201, json={"ref": body["ref"]})

        if m := re.match(r"^/repos/[^/]+/[^/]+/contents/(.+)$", path):
            file_path = m.group(1)
            if method == "GET":
                entry = self.files.get((request.url.params.get("ref", ""), file_path))
                if entry is None:
                    return httpx.Response(404, json={"message": "Not Found"})
                return httpx.Response(200, json=dict(entry))
            if method == "PUT":
                body = json.loads(request.content)
                self.last_put_body = body
                self.commits += 1
                self._next_sha += 1
                self.files[(body["branch"], file_path)] = {
                    "content": body["content"],
                    "sha": f"filesha{self._next_sha}",
                }
                return httpx.Response(201, json={"content": {"sha": f"filesha{self._next_sha}"}})

        if re.match(r"^/repos/[^/]+/[^/]+/pulls$", path):
            if method == "GET":
                head = request.url.params.get("head", "")
                branch = head.split(":", 1)[1] if ":" in head else head
                open_prs = [
                    {"number": p["number"], "html_url": p["html_url"]}
                    for p in self.pulls
                    if p["state"] == "open" and p["head"] == branch
                ]
                return httpx.Response(200, json=open_prs)
            if method == "POST":
                body = json.loads(request.content)
                pr = {
                    "number": self._next_pr,
                    "state": "open",
                    "head": body["head"],
                    "title": body["title"],
                    "body": body["body"],
                    "html_url": f"https://github.example/acme/web/pull/{self._next_pr}",
                }
                self._next_pr += 1
                self.pulls.append(pr)
                return httpx.Response(
                    201, json={"number": pr["number"], "html_url": pr["html_url"]}
                )

        if method == "PATCH" and (m := re.match(r"^/repos/[^/]+/[^/]+/pulls/(\d+)$", path)):
            number = int(m.group(1))
            for pr in self.pulls:
                if pr["number"] == number:
                    body = json.loads(request.content)
                    pr["title"], pr["body"] = body["title"], body["body"]
                    return httpx.Response(200, json={"number": number, "html_url": pr["html_url"]})
            return httpx.Response(404, json={"message": "Not Found"})

        return httpx.Response(500, json={"unhandled": f"{method} {path}"})


def _patched_app(monkeypatch: Any, fake: _FakeGitHub) -> GitHubApp:
    async def fake_token(self: GitHubApp, installation_id: int | None) -> str:
        return "ghs_test"

    monkeypatch.setattr(GitHubApp, "_installation_token", fake_token)
    real_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        ga.httpx,
        "AsyncClient",
        lambda **kw: real_async_client(transport=httpx.MockTransport(fake.handler)),
    )
    return GitHubApp(Settings())


async def _open(app: GitHubApp, *, content: str | None = None) -> Any:
    return await app.open_setup_pr(
        installation_id=5001,
        repo_full_name="acme/web",
        base_branch="main",
        file_path=WORKFLOW_PATH,
        file_content=content
        if content is not None
        else render_workflow(default_branch="main", api_url=_API_URL),
        commit_message=WORKFLOW_COMMIT_MESSAGE,
        pr_title=SETUP_PR_TITLE,
        pr_body=render_pr_body(repo_full_name="acme/web", org_slug="acme", dashboard_url=_DASH_URL),
    )


async def test_open_setup_pr_creates_branch_file_and_pr(monkeypatch: Any) -> None:
    fake = _FakeGitHub()
    app = _patched_app(monkeypatch, fake)

    result = await _open(app)

    assert result.created is True
    assert result.number == 1
    assert result.url == "https://github.example/acme/web/pull/1"
    # The branch was cut from the base branch's head.
    assert fake.refs[f"heads/{SETUP_BRANCH}"] == "abc123"
    # The committed file decodes to the rendered workflow — and parses as YAML.
    stored = fake.files[(SETUP_BRANCH, WORKFLOW_PATH)]["content"]
    decoded = base64.b64decode(stored).decode("utf-8")
    assert decoded == render_workflow(default_branch="main", api_url=_API_URL)
    assert yaml.safe_load(decoded)["name"] == "VulnAdvisor"
    # Exactly one PR, with our title and an explanatory body.
    assert len(fake.pulls) == 1
    assert fake.pulls[0]["title"] == SETUP_PR_TITLE
    assert "VULNADVISOR_API_KEY" in fake.pulls[0]["body"]


async def test_open_setup_pr_reclick_updates_never_duplicates(monkeypatch: Any) -> None:
    fake = _FakeGitHub()
    app = _patched_app(monkeypatch, fake)

    first = await _open(app)
    second = await _open(app)

    assert first.created is True and second.created is False
    assert second.number == first.number
    assert len(fake.pulls) == 1  # never a duplicate PR
    assert fake.commits == 1  # identical content -> no pointless second commit


async def test_open_setup_pr_changed_content_recommits_with_sha(monkeypatch: Any) -> None:
    fake = _FakeGitHub()
    app = _patched_app(monkeypatch, fake)

    await _open(app)
    changed = render_workflow(default_branch="main", api_url="https://api.other.example")
    result = await _open(app, content=changed)

    assert result.created is False
    assert fake.commits == 2
    # The update commit referenced the existing file's sha (GitHub requires it).
    assert fake.last_put_body is not None and fake.last_put_body.get("sha") == "filesha1"
    stored = fake.files[(SETUP_BRANCH, WORKFLOW_PATH)]["content"]
    assert base64.b64decode(stored).decode("utf-8") == changed
    assert len(fake.pulls) == 1


async def test_open_setup_pr_missing_base_branch_raises(monkeypatch: Any) -> None:
    fake = _FakeGitHub(base_branch="other")
    app = _patched_app(monkeypatch, fake)

    with pytest.raises(GitHubAppError, match="base branch"):
        await _open(app)
    assert fake.pulls == []
