"""Setup-PR content + per-repo setup status (Task 14.2).

Pure functions only: the GitHub Actions workflow the App proposes, the PR body that explains it,
and the setup-status chip shown per repo in the dashboard. The REST orchestration that actually
opens the PR lives in :mod:`vulnadvisor_platform.github_app`.
"""

import json

# Where the workflow lands in the user's repo, and the branch the App commits it to. Re-running
# setup re-uses the same branch, which is what makes the whole flow idempotent (one branch ->
# at most one open PR).
WORKFLOW_PATH = ".github/workflows/vulnadvisor.yml"
SETUP_BRANCH = "vulnadvisor/setup"
SETUP_PR_TITLE = "Add VulnAdvisor reachability scanning"
WORKFLOW_COMMIT_MESSAGE = "Add VulnAdvisor scan workflow"

# The setup PR's last known lifecycle state, stored on the repository row (synced via webhook).
PR_STATE_OPEN = "open"
PR_STATE_MERGED = "merged"

# Setup-status chips, derived (never stored) in :func:`setup_status`.
STATUS_NOT_SET_UP = "not-set-up"
STATUS_PR_OPEN = "pr-open"
STATUS_PR_MERGED = "pr-merged"
STATUS_RECEIVING_SCANS = "receiving-scans"


def render_workflow(*, default_branch: str, api_url: str) -> str:
    """The GitHub Actions workflow the setup PR adds.

    ``default_branch`` and ``api_url`` are interpolated as JSON strings — a strict subset of YAML
    double-quoted scalars — so any legal git branch name or URL stays valid YAML.

    On pull requests the workflow also runs ``vulnadvisor suggest``, which posts machine-validated
    one-click fix suggestions in-line using the built-in ``GITHUB_TOKEN`` — **no GitHub App
    required** (Task 17.4). That step needs ``pull-requests: write`` and one model-key secret; an
    unset key simply means no suggestions, never a failed build.
    """
    branch = json.dumps(default_branch)
    url = json.dumps(api_url)
    return f"""\
# VulnAdvisor — reachability-aware dependency triage for Python.
#
# Scans on every push to {default_branch} and on every pull request, then uploads the
# JSON report to your VulnAdvisor dashboard. On pull requests it also posts one-click,
# machine-validated fix suggestions in-line using the built-in GITHUB_TOKEN (no GitHub
# App needed). Only the report leaves CI — never your source code. The setup PR body
# explains the repository secrets.
name: VulnAdvisor

on:
  push:
    branches: [{branch}]
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
          VULNADVISOR_API_KEY: ${{{{ secrets.VULNADVISOR_API_KEY }}}}
          API_URL: {url}
        run: vulnadvisor scan . --upload
      - name: Suggest validated fixes on the pull request
        if: github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          OPENROUTER_API_KEY: ${{{{ secrets.OPENROUTER_API_KEY }}}}
          OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
        run: vulnadvisor suggest
"""


def render_pr_body(*, repo_full_name: str, org_slug: str, dashboard_url: str) -> str:
    """The setup PR's body: what the workflow does, the one secret to add, and the privacy facts."""
    dash = dashboard_url.rstrip("/")
    org_url = f"{dash}/orgs/{org_slug}"
    keys_url = f"{org_url}/settings/api-keys"
    return f"""\
## VulnAdvisor — automatic reachability scanning

This PR adds `{WORKFLOW_PATH}`: every push to the default branch and every pull request runs \
`vulnadvisor scan . --upload`, so the dependency vulnerabilities that are *actually reachable \
from your code* show up in your [dashboard]({org_url}), ranked and explained.

### One step before merging

The workflow authenticates with a repository secret named `VULNADVISOR_API_KEY`:

1. Generate an org API key at [{org_slug} → Settings → API keys]({keys_url}) — or run \
`vulnadvisor login` on your machine and mint one from that same page.
2. In **{repo_full_name} → Settings → Secrets and variables → Actions**, add a repository \
secret named `VULNADVISOR_API_KEY` with that value.

### One-click fix suggestions on your pull requests (optional)

On every pull request the workflow also runs `vulnadvisor suggest`: it machine-validates a patch \
for each finding and posts it as an in-line GitHub **suggestion** you can commit with one click — \
using the built-in `GITHUB_TOKEN`, **no GitHub App required**. To enable it, add **one** model-key \
repository secret (any works — a free OpenRouter key is enough): `OPENROUTER_API_KEY`, \
`OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`. Without a model key this step posts nothing and never \
fails your build.

### What gets uploaded

Only the JSON scan report (package names, advisory ids, reachability evidence). Your source \
code never leaves CI — the scan and the fix validation both run entirely inside your own runner; \
the only outbound calls are the report upload, your own model key, and GitHub.

By default the scan never fails your build; add `--fail-on <tier|score>` to the scan step \
when you're ready to gate merges.

---
*Opened by the VulnAdvisor GitHub App. Re-running setup updates this PR in place — it never \
opens a duplicate.*
"""


def setup_status(*, scan_count: int, setup_pr_state: str | None) -> str:
    """Derive the per-repo setup chip: received scans win, then the setup PR's known state.

    A merged PR without scans yet stays distinct from "not set up" — merging is progress, and
    showing "Not set up" right after a merge would be dishonest.
    """
    if scan_count > 0:
        return STATUS_RECEIVING_SCANS
    if setup_pr_state == PR_STATE_OPEN:
        return STATUS_PR_OPEN
    if setup_pr_state == PR_STATE_MERGED:
        return STATUS_PR_MERGED
    return STATUS_NOT_SET_UP
