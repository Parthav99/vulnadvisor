# File: tests/test_gitmeta.py
"""Tests for scan git-metadata detection (Task 12.2): real values or null, never zeros."""

import subprocess
from pathlib import Path

import pytest

from vulnadvisor.output import gitmeta
from vulnadvisor.output.gitmeta import detect_scan_metadata

_ZEROS = "0" * 40


@pytest.fixture(autouse=True)
def _no_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip CI variables so tests are deterministic when the suite itself runs in Actions."""
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.delenv("GITHUB_REF", raising=False)


def _git(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


requires_git = pytest.mark.skipif(not _git_available(), reason="git not installed")


def _init_repo_with_commit(path: Path) -> str:
    _git(["init", "-b", "main"], path)
    _git(
        [
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ],
        path,
    )
    return _git(["rev-parse", "HEAD"], path)


@requires_git
def test_git_repo_yields_real_sha_and_branch(tmp_path: Path) -> None:
    sha = _init_repo_with_commit(tmp_path)
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha == sha.lower()
    assert meta.ref == "main"


@requires_git
def test_detached_head_yields_sha_without_ref(tmp_path: Path) -> None:
    sha = _init_repo_with_commit(tmp_path)
    _git(["checkout", "--detach", sha], tmp_path)
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha == sha.lower()
    assert meta.ref is None


@requires_git
def test_file_path_uses_parent_directory(tmp_path: Path) -> None:
    sha = _init_repo_with_commit(tmp_path)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("pyyaml==5.3\n")
    meta = detect_scan_metadata(manifest)
    assert meta.commit_sha == sha.lower()


def test_non_repo_directory_yields_nulls(tmp_path: Path) -> None:
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha is None
    assert meta.ref is None


def test_git_absent_yields_nulls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_git(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(gitmeta.subprocess, "run", no_git)
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha is None
    assert meta.ref is None


def test_ci_env_wins_without_invoking_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sha = "a" * 40
    monkeypatch.setenv("GITHUB_SHA", sha)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/feature")

    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("git must not be invoked when CI env is set")

    monkeypatch.setattr(gitmeta, "_run_git", boom)
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha == sha
    assert meta.ref == "refs/heads/feature"


@pytest.mark.parametrize("bad_sha", [_ZEROS, "not-a-sha", "abc123", "", "  "])
def test_invalid_env_sha_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_sha: str
) -> None:
    monkeypatch.setenv("GITHUB_SHA", bad_sha)
    # Outside a repo the fallback finds nothing — the bad value must become null, never zeros.
    monkeypatch.setattr(gitmeta, "_run_git", lambda args, cwd: None)
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha is None


def test_zero_sha_from_git_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gitmeta, "_run_git", lambda args, cwd: _ZEROS if args[0] == "rev-parse" else None
    )
    meta = detect_scan_metadata(tmp_path)
    assert meta.commit_sha is None
