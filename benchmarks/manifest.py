"""Pinned public repositories for the live benchmark, plus the live runner.

The manifest pins each repo to a commit so the artifact is reproducible. The live runner clones at
that commit, runs ``pip-audit`` (the naive baseline) and VulnAdvisor (triage) over the repo's
requirements, and records the per-advisory tier. It is intentionally not exercised in CI (it needs
network, ``pip-audit``, and real clones); the hermetic corpus is the tested path. Every step is
defensive — a clone/audit/scan failure degrades that repo to an empty result rather than crashing
the run.

For live repos we cannot label every advisory's reachability, so ``reachable_truth`` is left
unknown; the live report shows the noise reduction and reachable-called counts, while the
soundness guarantee (a reachable finding is never NOT_IMPORTED) is proven by the hermetic corpus.
"""

import json
import subprocess  # noqa: S404 - invokes git/pip-audit with fixed argv, never shell=True
from dataclasses import dataclass
from pathlib import Path

from benchmarks.metrics import AdvisoryOutcome, RepoResult
from vulnadvisor.advisories.clients import EpssClient, KevClient, OSVClient
from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.advisories.transport import UrllibTransport
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.model.reachability import ReachabilityTier
from vulnadvisor.store.cache import SqliteCache, default_cache_path

__all__ = ["MANIFEST", "RepoSpec", "run_live"]


@dataclass(frozen=True)
class RepoSpec:
    """A pinned public repo to benchmark: clone ``url`` at ``commit`` and audit ``requirements``."""

    name: str
    url: str
    commit: str
    requirements: str = "requirements.txt"


# Popular, dependency-heavy public Python projects, pinned for reproducibility (commits are real,
# HEAD as of 2026-06-09). Advisory data still reflects the day the audit is run. Requirements paths
# are best-effort and must be confirmed per repo before a published live run -- several of these
# projects also ship dependencies via pyproject.toml rather than a requirements file.
MANIFEST: tuple[RepoSpec, ...] = (
    RepoSpec(
        "sentry-python",
        "https://github.com/getsentry/sentry-python",
        "035826318933d3e99d0ec3c40e34cbf25c298f7e",
        "requirements-testing.txt",
    ),
    RepoSpec(
        "httpie",
        "https://github.com/httpie/httpie",
        "5b604c37c6c67e18e7c3e9aee6c88a8c22b98345",
        "requirements-dev.txt",
    ),
    RepoSpec(
        "flask",
        "https://github.com/pallets/flask",
        "36e4a824f340fdee7ed50937ba8e7f6bc7d17f81",
        "requirements/dev.txt",
    ),
    RepoSpec(
        "requests",
        "https://github.com/psf/requests",
        "6f205ff422bccd5e4c4fc0b64c5f3e7df5181db6",
        "requirements-dev.txt",
    ),
    RepoSpec(
        "rich",
        "https://github.com/Textualize/rich",
        "46cebbb032f920eb096efbaf23cdc6fe9dd541f7",
        "requirements.txt",
    ),
    RepoSpec(
        "scrapy",
        "https://github.com/scrapy/scrapy",
        "4e956bd2de5e319bebad2d603a2f5ee34d9d2ffb",
        "requirements.txt",
    ),
    RepoSpec(
        "celery",
        "https://github.com/celery/celery",
        "1cc9ecf430717b371892573ecad252929213e75e",
        "requirements/default.txt",
    ),
    RepoSpec(
        "pandas",
        "https://github.com/pandas-dev/pandas",
        "e1198e6b3648fbaeee8850922b10161d0541c971",
        "requirements-dev.txt",
    ),
    RepoSpec(
        "fastapi",
        "https://github.com/fastapi/fastapi",
        "5cdf820c8046edaf83c306ebd7435f038fc4a75a",
        "requirements.txt",
    ),
    RepoSpec(
        "django-cms",
        "https://github.com/django-cms/django-cms",
        "8758714b865ffa79c6bcd0e5c503958ea48885aa",
        "requirements.txt",
    ),
    RepoSpec(
        "airflow",
        "https://github.com/apache/airflow",
        "cd5509fc701cd18f32ae5b9625fa34a151c12f9e",
        "requirements.txt",
    ),
    RepoSpec(
        "poetry",
        "https://github.com/python-poetry/poetry",
        "298068d32cc16e7d2a086c3bdf219daa30a85a8b",
        "requirements.txt",
    ),
)


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run a fixed-argv command, capturing output; never uses a shell."""
    return subprocess.run(  # noqa: S603 - fixed argv list, no shell
        args, cwd=cwd, capture_output=True, text=True, timeout=600, check=False
    )


def _pip_audit_ids(requirements: Path) -> dict[str, set[str]]:
    """Return ``{package: {advisory_id, ...}}`` from ``pip-audit`` on a requirements file."""
    result = _run(
        ["pip-audit", "--format", "json", "--requirement", str(requirements), "--no-deps"]
    )
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError):
        return {}
    out: dict[str, set[str]] = {}
    for dep in payload.get("dependencies", []) if isinstance(payload, dict) else []:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", "")).lower()
        ids = {
            str(v.get("id")) for v in dep.get("vulns", []) if isinstance(v, dict) and v.get("id")
        }
        if name and ids:
            out.setdefault(name, set()).update(ids)
    return out


def _live_matcher() -> AdvisoryMatcher:
    """Build a live advisory matcher (OSV/EPSS/KEV) sharing the local cache."""
    cache = SqliteCache(default_cache_path())
    transport = UrllibTransport()
    return AdvisoryMatcher(
        OSVClient(transport, cache), EpssClient(transport, cache), KevClient(transport, cache)
    )


def run_live(spec: RepoSpec, workdir: Path) -> RepoResult:
    """Clone ``spec`` at its commit, run pip-audit + VulnAdvisor, and record per-advisory tiers.

    Defensive: any failed step returns an empty :class:`RepoResult` rather than raising.
    """
    checkout = workdir / spec.name
    if _run(["git", "clone", "--filter=blob:none", spec.url, str(checkout)]).returncode != 0:
        return RepoResult(repo=spec.name, commit=spec.commit, outcomes=())
    _run(["git", "checkout", spec.commit], cwd=checkout)

    requirements = checkout / spec.requirements
    if not requirements.is_file():
        return RepoResult(repo=spec.name, commit=spec.commit, outcomes=())
    baseline = _pip_audit_ids(requirements)

    report = scan_project(checkout, _live_matcher())
    tier_by_package: dict[str, ReachabilityTier] = {}
    for finding in report.findings:
        if finding.reachability is not None:
            tier_by_package[finding.matched.dependency.name.lower()] = finding.reachability.tier

    outcomes: list[AdvisoryOutcome] = []
    for package, ids in sorted(baseline.items()):
        tier = tier_by_package.get(package, ReachabilityTier.DYNAMIC_UNKNOWN)
        for advisory_id in sorted(ids):
            outcomes.append(AdvisoryOutcome(advisory_id=advisory_id, package=package, tier=tier))
    return RepoResult(repo=spec.name, commit=spec.commit, outcomes=tuple(outcomes))
