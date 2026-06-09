"""Live benchmark over pinned real public repos: OSV (naive baseline) vs VulnAdvisor triage.

Each repo is pinned to an **older tag** whose committed, pinned requirements contain real, known
vulnerabilities (current HEADs of maintained projects are patched, so they show nothing to triage).

The comparison is anchored on the *naive baseline*: every advisory OSV reports for a declared,
pinned dependency -- exactly what a conventional scanner (pip-audit, Dependabot, GitHub alerts)
surfaces, since they all draw from the OSV / PyPI advisory database. We query OSV directly from the
pinned ``name==version`` lines: this is the same database pip-audit uses, but it does not have to
build a wheel for every (often decade-old, unbuildable) dependency just to read its metadata, so it
works on precisely the old, vulnerable corpus that defeats pip-audit on a modern interpreter.

For each flagged package we then ask the **real** VulnAdvisor reachability engine which tier it
falls in. Reachability is computed *locally* from the import graph and the package->import mapping,
so it needs no advisory network calls of its own. To map a distribution to its import name with
confidence, the engine reads installed package metadata; so for each repo we create a throwaway
venv, install the flagged packages (best-effort, no transitive deps) plus VulnAdvisor, and compute
reachability *inside* that venv. Unmappable or uninstallable packages fall back to the cautious
DYNAMIC-UNKNOWN tier (never a false "safe").

This module runs on demand (``python -m benchmarks --live``); it is not part of CI (needs network
and real clones). Every step is defensive -- a failed repo is skipped, never fatal.
"""

import json
import shutil
import subprocess  # noqa: S404 - fixed argv, never shell=True; invokes git/uv only
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name

from benchmarks.metrics import AdvisoryOutcome, RepoResult
from vulnadvisor.advisories.clients import OSVClient
from vulnadvisor.advisories.transport import TransportError, UrllibTransport
from vulnadvisor.deps.parsers import parse_requirements_txt
from vulnadvisor.model.reachability import ReachabilityTier
from vulnadvisor.store.cache import SqliteCache

__all__ = ["MANIFEST", "RepoSpec", "run_live"]

_TIER_BY_VALUE = {tier.value: tier for tier in ReachabilityTier}

# Persisted OSV response cache so re-runs of the benchmark hit zero network.
_OSV_CACHE_PATH = Path(__file__).resolve().parent / ".osv-cache.sqlite"


@dataclass(frozen=True)
class RepoSpec:
    """A pinned public repo: clone ``url`` at ``ref`` (tag) and audit ``requirements``."""

    name: str
    url: str
    ref: str
    requirements: str


# Real public applications pinned to older tags whose committed requirements carry known-vulnerable,
# pinned dependencies (so there is real noise to triage). Tags are reproducible references.
MANIFEST: tuple[RepoSpec, ...] = (
    RepoSpec("redash", "https://github.com/getredash/redash", "v10.0.0", "requirements.txt"),
    RepoSpec("superset", "https://github.com/apache/superset", "1.3.2", "requirements/base.txt"),
    RepoSpec("netbox", "https://github.com/netbox-community/netbox", "v3.0.0", "requirements.txt"),
    RepoSpec("saleor", "https://github.com/saleor/saleor", "2.11.1", "requirements.txt"),
    RepoSpec(
        "intelowl",
        "https://github.com/intelowlproject/IntelOwl",
        "v4.0.0",
        "requirements/project-requirements.txt",
    ),
    RepoSpec("django-nv", "https://github.com/nVisium/django.nV", "master", "requirements.txt"),
    RepoSpec("ctfd", "https://github.com/CTFd/CTFd", "3.4.0", "requirements.txt"),
    RepoSpec(
        "healthchecks",
        "https://github.com/healthchecks/healthchecks",
        "v1.25.0",
        "requirements.txt",
    ),
    RepoSpec("frappe", "https://github.com/frappe/frappe", "v13.0.0", "requirements.txt"),
    RepoSpec("awx", "https://github.com/ansible/awx", "19.2.0", "requirements/requirements.txt"),
)

# Run inside each repo's venv: build the import graph, compute reachability for the flagged
# packages, and report each one's tier (plus a soundness flag if a NOT-IMPORTED package's import
# name nonetheless appears in the graph -- that would be a false negative).
_REACHABILITY_SNIPPET = """
import json, sys
from pathlib import Path
from packaging.utils import canonicalize_name
from vulnadvisor.callgraph.import_graph import build_import_graph
from vulnadvisor.deps.import_mapping import resolve_import_names
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.reachability import compute_reachability

spec = json.loads(Path(sys.argv[1]).read_text())
graph = build_import_graph(Path(spec["repo"]))
roots = set(graph.import_roots())
out = {}
for name, version in spec["packages"]:
    dep = Dependency(name=canonicalize_name(name), raw_name=name, version=version,
                     source=DependencySource.REQUIREMENTS_TXT)
    tier = compute_reachability(dep, graph).tier
    mapping = resolve_import_names(name)
    imported = any(n.split(".")[0] in roots for n in mapping.import_names)
    suspect_fn = tier.value == "not-imported" and imported
    out[canonicalize_name(name)] = {"tier": tier.value, "suspect_fn": suspect_fn}
Path(sys.argv[2]).write_text(json.dumps(out))
"""


def _run(
    args: list[str], cwd: Path | None = None, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    """Run a fixed-argv command, capturing output; never uses a shell."""
    return subprocess.run(  # noqa: S603 - fixed argv list, no shell
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def _venv_python(venv: Path) -> Path:
    """Return the interpreter path inside ``venv`` for the current OS."""
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _osv_baseline(requirements: Path) -> list[tuple[str, str, list[str]]]:
    """Return ``[(package, version, [advisory_id, ...]), ...]`` from OSV for pinned deps.

    The naive baseline: every advisory OSV reports for a declared, pinned dependency -- the same
    set a conventional scanner shows. Only ``==`` pinned dependencies are queried (an unpinned
    range cannot be matched to a concrete vulnerable version, and including every historical
    advisory would inflate the baseline unfairly). Network failures skip that package, never crash.
    """
    try:
        deps = parse_requirements_txt(requirements.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    client = OSVClient(UrllibTransport(timeout=30.0), SqliteCache(_OSV_CACHE_PATH))
    out: list[tuple[str, str, list[str]]] = []
    for dep in deps:
        if dep.version is None:
            continue
        try:
            advisories = client.query(dep)
        except TransportError:
            continue
        ids = sorted({adv.id for adv in advisories if adv.id})
        if ids:
            out.append((dep.raw_name or dep.name, dep.version, ids))
    return out


def _wheel_path() -> Path | None:
    """Return the built VulnAdvisor wheel, building it if necessary."""
    root = Path(__file__).resolve().parent.parent
    wheels = sorted((root / "dist").glob("vulnadvisor-*.whl"))
    if not wheels:
        _run(["uv", "build", "--wheel"], cwd=root, timeout=300)
        wheels = sorted((root / "dist").glob("vulnadvisor-*.whl"))
    return wheels[-1] if wheels else None


def _reachability_tiers(
    repo: Path, flagged: list[tuple[str, str, list[str]]], wheel: Path
) -> dict[str, dict[str, object]]:
    """Compute each flagged package's reachability tier in a venv that has them installed."""
    with tempfile.TemporaryDirectory(prefix="vulnadvisor-bench-venv-") as tmp:
        venv = Path(tmp) / "venv"
        if _run(["uv", "venv", str(venv)], timeout=120).returncode != 0:
            return {}
        python = _venv_python(venv)
        # VulnAdvisor (with its runtime deps) so the snippet can import it.
        if (
            _run(
                ["uv", "pip", "install", "--python", str(python), str(wheel)], timeout=300
            ).returncode
            != 0
        ):
            return {}
        # Install each flagged package for confident import-name mapping. We install the *latest*
        # version, not the pinned-vulnerable one: the import name is version-stable, latest has
        # prebuilt wheels (the decade-old vulnerable versions usually fail to build on modern
        # Python), and reachability depends only on the import name, never the installed version.
        for name, _version, _ids in flagged:
            _run(
                ["uv", "pip", "install", "--python", str(python), "--no-deps", name],
                timeout=180,
            )
        spec_file = Path(tmp) / "spec.json"
        out_file = Path(tmp) / "out.json"
        spec_file.write_text(
            json.dumps({"repo": str(repo), "packages": [[n, v] for n, v, _ in flagged]}),
            encoding="utf-8",
        )
        snippet = Path(tmp) / "snippet.py"
        snippet.write_text(_REACHABILITY_SNIPPET, encoding="utf-8")
        if (
            _run([str(python), str(snippet), str(spec_file), str(out_file)], timeout=600).returncode
            != 0
        ):
            return {}
        try:
            parsed = json.loads(out_file.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}
        return parsed if isinstance(parsed, dict) else {}


def run_live(spec: RepoSpec, workdir: Path, wheel: Path | None = None) -> RepoResult:
    """Clone ``spec`` at its tag, query OSV, compute reachability tiers, and record outcomes.

    Defensive: any failed step yields an empty :class:`RepoResult` (the repo is skipped).
    """
    wheel = wheel or _wheel_path()
    if wheel is None:
        return RepoResult(repo=spec.name, commit=spec.ref, outcomes=())

    checkout = workdir / spec.name
    clone = _run(
        ["git", "clone", "--depth", "1", "--branch", spec.ref, spec.url, str(checkout)], timeout=600
    )
    if clone.returncode != 0:
        return RepoResult(repo=spec.name, commit=spec.ref, outcomes=())

    requirements = checkout / spec.requirements
    if not requirements.is_file():
        return RepoResult(repo=spec.name, commit=spec.ref, outcomes=())

    flagged = _osv_baseline(requirements)
    if not flagged:
        return RepoResult(repo=spec.name, commit=spec.ref, outcomes=())

    tiers = _reachability_tiers(checkout, flagged, wheel)

    outcomes: list[AdvisoryOutcome] = []
    for name, _version, ids in flagged:
        info = tiers.get(canonicalize_name(name), {})
        tier_value = str(info.get("tier", "dynamic-unknown"))
        # A NOT-IMPORTED whose import name is nonetheless present is a (suspect) false negative:
        # mark it reachable_truth=True so the metrics' false-negative tally catches it.
        truth = True if info.get("suspect_fn") else None
        for advisory_id in ids:
            outcomes.append(
                AdvisoryOutcome(
                    advisory_id=advisory_id,
                    package=canonicalize_name(name),
                    tier=_TIER_BY_VALUE.get(tier_value, ReachabilityTier.DYNAMIC_UNKNOWN),
                    reachable_truth=truth,
                )
            )
    shutil.rmtree(checkout, ignore_errors=True)  # free disk between large repos
    return RepoResult(repo=spec.name, commit=spec.ref, outcomes=tuple(outcomes))
