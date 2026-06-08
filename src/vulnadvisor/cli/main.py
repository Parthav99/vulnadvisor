"""VulnAdvisor command-line entrypoint (Typer app)."""

from collections.abc import Callable
from enum import Enum
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vulnadvisor.advisories.clients import EpssClient, KevClient, OSVClient
from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.advisories.transport import UrllibTransport
from vulnadvisor.callgraph.frameworks import FrameworkPlugin
from vulnadvisor.callgraph.type_resolver import PyrightResolver, TypeResolver
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.cli.render import render_report
from vulnadvisor.model.advisory import Advisory
from vulnadvisor.output.gating import parse_fail_on, should_fail
from vulnadvisor.output.json_report import to_json
from vulnadvisor.output.sarif import to_sarif_json
from vulnadvisor.store.analysis_cache import AnalysisCache, default_analysis_cache_path
from vulnadvisor.store.cache import SqliteCache, default_cache_path
from vulnadvisor.store.dataset import SymbolDataset, default_dataset_path
from vulnadvisor.symbols.backfill import TOP_PYPI_PACKAGES, backfill
from vulnadvisor.symbols.extractor import SymbolExtractor


class OutputFormat(str, Enum):
    """Supported output formats for ``scan``."""

    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


app = typer.Typer(
    name="vulnadvisor",
    help="Stop scanning, start triaging — reachability-first vuln triage for Python.",
    no_args_is_help=True,
    add_completion=False,
)


def build_matcher() -> AdvisoryMatcher:
    """Build the production advisory matcher (live transport + local SQLite cache).

    Defined as a module-level function so tests can substitute an offline matcher.
    """
    cache = SqliteCache(default_cache_path())
    transport = UrllibTransport()
    return AdvisoryMatcher(
        OSVClient(transport, cache),
        EpssClient(transport, cache),
        KevClient(transport, cache),
    )


def build_osv_client() -> OSVClient:
    """Build the production OSV client (live transport + local cache); test-substitutable."""
    return OSVClient(UrllibTransport(), SqliteCache(default_cache_path()))


def build_symbol_extractor() -> SymbolExtractor:
    """Build the production symbol extractor (live transport); test-substitutable."""
    return SymbolExtractor(UrllibTransport())


def build_type_resolver() -> TypeResolver:
    """Build the optional Pyright resolver; it self-reports unavailable if pyright is absent."""
    return PyrightResolver()


def build_symbol_names_for() -> Callable[[Advisory], frozenset[str]] | None:
    """Return an advisory->vulnerable-symbol-names lookup from the local dataset, if it exists.

    Returns ``None`` when no dataset has been built (backfilled), so scans simply skip
    function-level reachability rather than doing any work.
    """
    path = default_dataset_path()
    if not path.exists():
        return None
    dataset = SymbolDataset(path)

    def lookup(advisory: Advisory) -> frozenset[str]:
        names: set[str] = set()
        for advisory_id in (advisory.id, *advisory.aliases):
            extraction = dataset.get(advisory_id)
            if extraction is not None:
                names.update(symbol.name for symbol in extraction.symbols)
        return frozenset(names)

    return lookup


def _resolve_version() -> str:
    """Return the installed package version, or a dev fallback if unresolved."""
    try:
        return _pkg_version("vulnadvisor")
    except PackageNotFoundError:
        return "0.0.0+dev"


def _version_callback(value: bool) -> None:
    """Print the version and exit when ``--version`` is passed."""
    if value:
        typer.echo(f"vulnadvisor {_resolve_version()}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the VulnAdvisor version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """VulnAdvisor: which dependency vulnerabilities are actually reachable from your code."""


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=True,
            readable=True,
            help="Path to the Python project to scan.",
        ),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format for results."),
    ] = OutputFormat.TERMINAL,
    public: Annotated[
        bool,
        typer.Option(
            "--public/--internal",
            help="Project is a public package (--public) or an internal app (--internal).",
        ),
    ] = True,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero when any finding meets/exceeds this band or score (0-100).",
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Disable the incremental per-file analysis cache (always re-parse every file).",
        ),
    ] = False,
    no_types: Annotated[
        bool,
        typer.Option(
            "--no-types",
            help="Disable Pyright type-informed resolution of reflective dispatch.",
        ),
    ] = False,
    no_frameworks: Annotated[
        bool,
        typer.Option(
            "--no-frameworks",
            help="Disable framework plugins (FastAPI/Django route + signal entry points).",
        ),
    ] = False,
) -> None:
    """Scan PATH for vulnerable dependencies and emit ranked, prioritized results.

    Matches declared/locked dependencies against OSV, enriches with EPSS and CISA KEV, and ranks
    by the deterministic priority score. ``--format`` selects the terminal three-card view, JSON,
    or SARIF 2.1.0 (for GitHub code scanning). ``--fail-on`` gates the exit code.
    ``--public/--internal`` is reserved for reachability (M4+).
    """
    _ = public  # reserved for later milestones; accepted now for a stable CLI surface

    # Validate --fail-on before doing any work so bad input fails fast.
    threshold = None
    if fail_on is not None:
        try:
            threshold = parse_fail_on(fail_on)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--fail-on") from exc

    analysis_cache = None if no_cache else AnalysisCache(default_analysis_cache_path())
    resolver = None if no_types else build_type_resolver()
    frameworks: list[FrameworkPlugin] | None = [] if no_frameworks else None
    try:
        report = scan_project(
            path,
            build_matcher(),
            symbol_names_for=build_symbol_names_for(),
            analysis_cache=analysis_cache,
            resolver=resolver,
            frameworks=frameworks,
        )
    finally:
        if analysis_cache is not None:
            analysis_cache.close()

    if output_format is OutputFormat.JSON:
        print(to_json(report.findings, report.degraded_sources, tool_version=_resolve_version()))
    elif output_format is OutputFormat.SARIF:
        print(
            to_sarif_json(report.findings, report.degraded_sources, tool_version=_resolve_version())
        )
    else:
        render_report(report.findings, report.degraded_sources, Console())

    if threshold is not None and should_fail(report.findings, threshold):
        raise typer.Exit(code=1)


@app.command(name="backfill")
def backfill_command(
    packages: Annotated[
        list[str] | None,
        typer.Argument(help="Package names to backfill (in addition to --top)."),
    ] = None,
    top: Annotated[
        int,
        typer.Option("--top", help="Also backfill the first N built-in top PyPI packages."),
    ] = 0,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Re-extract advisories already in the dataset."),
    ] = False,
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Dataset database path (defaults to the per-user location)."),
    ] = None,
) -> None:
    """Build/grow the advisory -> vulnerable-symbol dataset for the given packages.

    Queries OSV for each package's advisories, extracts vulnerable symbols from their fix commits,
    and stores them. Re-runs are idempotent; ``--refresh`` re-extracts existing advisories.
    """
    names = list(packages or [])
    if top > 0:
        names.extend(name for name in TOP_PYPI_PACKAGES[:top] if name not in names)
    if not names:
        raise typer.BadParameter("provide package names or use --top N")

    dataset = SymbolDataset(db if db is not None else default_dataset_path())
    try:
        result = backfill(
            dataset,
            names,
            osv=build_osv_client(),
            extractor=build_symbol_extractor(),
            refresh=refresh,
        )
    finally:
        total = dataset.count()
        dataset.close()

    typer.echo(
        f"Backfill: {result.packages} package(s), {result.advisories_seen} advisory hit(s), "
        f"{result.written} written, {result.skipped} skipped. Dataset now holds {total} advisories."
    )
    if result.degraded_packages:
        typer.echo(f"Degraded (OSV unreachable): {', '.join(result.degraded_packages)}")
