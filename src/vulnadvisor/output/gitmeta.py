# File: src/vulnadvisor/output/gitmeta.py
"""Detect the scanned project's git commit/ref for honest upload metadata.

``scan --upload`` attaches the commit SHA and ref of the scanned directory so the dashboard shows
real provenance. Detection is strictly best-effort and defensive: when git is not installed, the
directory is not a repository, or the output looks wrong, the field is ``None`` — **never a
placeholder** like forty zeros. CI values (``GITHUB_SHA``/``GITHUB_REF``) take precedence over
local detection so PR diffs line up with what GitHub reports.
"""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ScanMetadata", "detect_scan_metadata"]

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_GIT_TIMEOUT = 5.0


@dataclass(frozen=True)
class ScanMetadata:
    """The commit/ref a scan ran against; either field is ``None`` when honestly unknown."""

    commit_sha: str | None
    ref: str | None


def _run_git(args: list[str], cwd: Path) -> str | None:
    """Run a git command in ``cwd``; return its stripped stdout, or ``None`` on any failure."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, never shell, never user-controlled
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        # git missing/not executable, cwd vanished, or git hung — metadata is simply unknown.
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def _valid_sha(value: str | None) -> str | None:
    """Return a normalized 40-hex commit SHA, or ``None`` for anything else (incl. all zeros)."""
    if not value:
        return None
    sha = value.strip().lower()
    if not _SHA_RE.fullmatch(sha) or set(sha) == {"0"}:
        return None
    return sha


def detect_scan_metadata(path: Path) -> ScanMetadata:
    """Detect commit/ref for ``path``: CI env first, then git, else ``None`` — never placeholders.

    ``GITHUB_SHA``/``GITHUB_REF`` win when set (CI checkouts are detached, so the symbolic ref is
    unavailable there anyway). Locally, ``git rev-parse HEAD`` and ``git symbolic-ref --short
    HEAD`` are asked; a detached HEAD yields a SHA with no ref, and a non-repo or a machine
    without git yields ``None`` for both. Never raises.
    """
    directory = path if path.is_dir() else path.parent
    commit = _valid_sha(os.environ.get("GITHUB_SHA"))
    if commit is None:
        commit = _valid_sha(_run_git(["rev-parse", "HEAD"], directory))
    ref = (os.environ.get("GITHUB_REF") or "").strip() or None
    if ref is None:
        ref = _run_git(["symbolic-ref", "--short", "HEAD"], directory)
    return ScanMetadata(commit_sha=commit, ref=ref)
