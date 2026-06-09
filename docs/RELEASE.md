# Release runbook (maintainer only)

Publishing is **irreversible** and outward-facing, so only a maintainer runs the tagging and
posting steps below. Everything above the line "MAINTAINER: irreversible steps" is reversible prep
that lives in the repo. The release is driven by
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which builds the sdist + wheel
and publishes to PyPI via **Trusted Publishing (OIDC)** on any `v*` tag push.

## Heads-up: the stale `v1.0` tag

A `v1.0` tag already exists locally and on the remote, but it points to an **old commit**
(`f555caa`, Task 9.1) that predates `release.yml`. It therefore never triggered a publish, and
PyPI has no `vulnadvisor` project yet. **Do not reuse `v1.0`.** Release as **`v1.0.0`** (matches the
`pyproject.toml` version and the `v*` trigger) so you never have to force-move a published ref.

Optionally delete the stale tag afterward (non-essential):

```bash
git tag -d v1.0 && git push origin :refs/tags/v1.0
```

## One-time PyPI setup (before the first release)

1. Reserve the name and configure Trusted Publishing **before** pushing the tag, at
   <https://pypi.org/manage/account/publishing/>. Create a *pending* publisher with:
   - PyPI project name: `vulnadvisor`
   - Owner / repository: `Parthav99` / `vulnadvisor_v2`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
2. In the GitHub repo settings, create an **Environment** named `pypi` (Settings → Environments).
   Optionally add a required reviewer so the publish job waits for approval.

No API token secret is needed — OIDC handles auth.

## Pre-flight (reversible — run these locally first)

```bash
# 1. The full gate must be green.
uv run ruff check && uv run ruff format --check && uv run mypy --strict src && uv run pytest

# 2. The release artifact builds and the entrypoint runs in a clean venv (mirrors release.yml).
rm -rf dist && uv build
python -m venv /tmp/relcheck && /tmp/relcheck/bin/pip install dist/*.whl
/tmp/relcheck/bin/vulnadvisor --version   # must print: vulnadvisor 1.0.0

# 3. The live benchmark still shows real noise reduction with ZERO false negatives
#    (launch-blocking — see benchmarks/REPORT.live.md).
```

Confirm the launch post (`docs/launch-post.md`) leads with the real live numbers, then only the
hermetic figure. Confirm `pyproject.toml` URLs point to the final repo slug
(`Parthav99/vulnadvisor_v2`).

---

## MAINTAINER: irreversible steps

```bash
# Tag the release commit on main and push it. This triggers release.yml -> PyPI.
git checkout main && git pull origin main
git tag -a v1.0.0 -m "VulnAdvisor 1.0.0"
git push origin v1.0.0
```

Then:

1. Watch the **Release** workflow in the Actions tab. If you set a required reviewer on the `pypi`
   environment, approve it. Confirm it publishes the wheel + sdist.
2. Verify install from PyPI on a clean machine:
   ```bash
   uvx vulnadvisor --version
   pipx install vulnadvisor && vulnadvisor --version
   ```
3. Create the GitHub Release for `v1.0.0` (paste the `CHANGELOG.md` 1.0.0 section).
4. Enable **Discussions** (Settings → Features) for the feedback path, and create a `feedback`
   label and a `false-negative` label (used by the issue templates).
5. Post the launch (lead with the live numbers, link the repo and `benchmarks/REPORT.live.md`):
   - r/Python
   - Hacker News (Show HN)

## Post-launch

- Publishing the same version twice will fail — bump `pyproject.toml` and `CHANGELOG.md` for any
  follow-up release, then tag `v1.0.1` / `v1.1.0` etc.
