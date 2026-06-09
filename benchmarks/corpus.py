"""A deterministic synthetic corpus, exercised through the real VulnAdvisor reachability engine.

Each corpus repo declares a set of dependencies in three roles:

* ``called``   — imported and the vulnerable symbol is actually called (expect IMPORTED_AND_CALLED),
* ``imported`` — imported but the vulnerable symbol is not called (expect IMPORTED),
* ``unused``   — declared but never imported (noise a naive scanner raises; expect NOT_IMPORTED).

We synthesize real source files and run them through ``build_import_graph`` + the reachability
engine (the same path the CLI uses), so the benchmark measures the actual product, not a mock. As we
own the roles, ``reachable_truth`` is exact — which makes the false-negative check trustworthy.

Only packages with a confident package→import mapping are used, so ``unused`` deps resolve to
NOT_IMPORTED rather than the cautious DYNAMIC_UNKNOWN; import statements are generated from the
resolver so names like ``pyyaml``→``yaml`` stay correct regardless of what is installed.
"""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from benchmarks.metrics import AdvisoryOutcome, BenchmarkReport, RepoResult, build_report
from vulnadvisor.callgraph import DEFAULT_PLUGINS, collect_entry_points, entry_point_names
from vulnadvisor.callgraph.import_graph import build_import_graph
from vulnadvisor.deps.import_mapping import resolve_import_names
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.reachability import compute_reachability, refine_reachability

__all__ = ["CORPUS", "CorpusRepo", "Dep", "run_corpus"]


@dataclass(frozen=True)
class Dep:
    """A dependency in a corpus repo, with the role that fixes its expected reachability."""

    package: str
    role: str  # "called" | "imported" | "unused"
    symbol: str = "run"
    critical: bool = False


@dataclass(frozen=True)
class CorpusRepo:
    """A synthetic repository: a name and its dependencies (source is generated from the roles)."""

    name: str
    deps: tuple[Dep, ...] = field(default_factory=tuple)


# Twelve repos (>= 10), each mixing reachable and unused dependencies so the aggregate shows a
# realistic noise reduction with several genuinely reachable (and critical) findings preserved.
CORPUS: tuple[CorpusRepo, ...] = (
    CorpusRepo(
        "api-gateway",
        (
            Dep("requests", "called", "get", True),
            Dep("urllib3", "unused", critical=True),
            Dep("certifi", "unused"),
        ),
    ),
    CorpusRepo(
        "data-pipeline",
        (Dep("pyyaml", "called", "load", True), Dep("requests", "imported"), Dep("idna", "unused")),
    ),
    CorpusRepo(
        "cli-tool",
        (
            Dep("rich", "called", "print"),
            Dep("typer", "imported"),
            Dep("packaging", "unused"),
            Dep("pygments", "unused"),
        ),
    ),
    CorpusRepo(
        "web-scraper",
        (
            Dep("requests", "called", "get", True),
            Dep("charset-normalizer", "imported"),
            Dep("certifi", "unused"),
        ),
    ),
    CorpusRepo(
        "config-loader",
        (Dep("pyyaml", "called", "load", True), Dep("packaging", "unused"), Dep("idna", "unused")),
    ),
    CorpusRepo(
        "auth-service",
        (
            Dep("pydantic", "imported"),
            Dep("requests", "unused", critical=True),
            Dep("urllib3", "unused"),
        ),
    ),
    CorpusRepo(
        "report-builder",
        (
            Dep("rich", "called", "print"),
            Dep("markupsafe", "called", "escape"),
            Dep("pygments", "unused"),
        ),
    ),
    CorpusRepo(
        "cache-layer",
        (
            Dep("msgpack", "called", "packb"),
            Dep("cachecontrol", "imported"),
            Dep("certifi", "unused"),
        ),
    ),
    CorpusRepo(
        "ingest-worker",
        (
            Dep("pyyaml", "imported"),
            Dep("requests", "unused"),
            Dep("idna", "unused"),
            Dep("packaging", "unused"),
        ),
    ),
    CorpusRepo(
        "notify-bot",
        (
            Dep("requests", "called", "post", True),
            Dep("urllib3", "unused"),
            Dep("certifi", "unused"),
            Dep("idna", "unused"),
        ),
    ),
    CorpusRepo(
        "schema-tool",
        (
            Dep("pydantic", "called", "validate"),
            Dep("packaging", "imported"),
            Dep("rich", "unused"),
        ),
    ),
    CorpusRepo(
        "static-site",
        (Dep("markupsafe", "imported"), Dep("pygments", "unused"), Dep("packaging", "unused")),
    ),
)


def _import_name(package: str) -> str:
    """Return the top-level import name for ``package`` (e.g. ``pyyaml`` -> ``yaml``)."""
    names = resolve_import_names(package).import_names
    return names[0] if names else canonicalize_name(package).replace("-", "_")


def _synthesize(repo: CorpusRepo) -> dict[str, str]:
    """Generate the repo's source files from its dependency roles."""
    imports: list[str] = []
    calls: list[tuple[str, str]] = []
    for dep in repo.deps:
        if dep.role in {"called", "imported"}:
            imports.append(f"import {_import_name(dep.package)}")
        if dep.role == "called":
            calls.append((_import_name(dep.package), dep.symbol))

    body = [f'"""Synthetic benchmark app for {repo.name}."""', ""]
    body.extend(dict.fromkeys(imports))  # de-duplicate while preserving order
    body.append("")
    for imp, symbol in calls:
        body.append(f"def use_{imp}(data):")
        body.append(f"    return {imp}.{symbol}(data)")
        body.append("")
    for imp, _symbol in calls:
        body.append(f'use_{imp}(b"x")')

    requirements = "".join(f"{dep.package}==1.0.0\n" for dep in repo.deps)
    return {"app.py": "\n".join(body) + "\n", "requirements.txt": requirements}


def _evaluate(repo: CorpusRepo, root: Path) -> RepoResult:
    """Run the reachability engine over a materialized repo and record each advisory's outcome."""
    graph = build_import_graph(root)
    entry_points = entry_point_names(collect_entry_points(root, DEFAULT_PLUGINS))
    outcomes: list[AdvisoryOutcome] = []
    for index, dep in enumerate(repo.deps):
        dependency = Dependency(
            name=canonicalize_name(dep.package),
            raw_name=dep.package,
            version="1.0.0",
            source=DependencySource.REQUIREMENTS_TXT,
        )
        base = compute_reachability(dependency, graph)
        reach = refine_reachability(
            dependency,
            base,
            graph,
            root,
            frozenset({dep.symbol}),
            entry_points=entry_points,
        )
        outcomes.append(
            AdvisoryOutcome(
                advisory_id=f"BENCH-{repo.name}-{index:02d}",
                package=canonicalize_name(dep.package),
                tier=reach.tier,
                is_critical=dep.critical,
                reachable_truth=dep.role in {"called", "imported"},
            )
        )
    return RepoResult(repo=repo.name, commit="synthetic", outcomes=tuple(outcomes))


def run_corpus(corpus: Sequence[CorpusRepo] = CORPUS) -> BenchmarkReport:
    """Materialize and evaluate every corpus repo, returning the aggregated report."""
    rows: list[RepoResult] = []
    for repo in corpus:
        with tempfile.TemporaryDirectory(prefix=f"vulnadvisor-bench-{repo.name}-") as tmp:
            root = Path(tmp)
            for rel, content in _synthesize(repo).items():
                (root / rel).write_text(content, encoding="utf-8")
            rows.append(_evaluate(repo, root))
    return build_report(rows)
