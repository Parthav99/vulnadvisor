"""VulnAdvisor command-line entrypoint (Typer app)."""

import os
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
from vulnadvisor.cli.pipeline import ScanReport, scan_project
from vulnadvisor.cli.render import render_report
from vulnadvisor.llm.client import build_anthropic_client
from vulnadvisor.llm.explainer import Explainer
from vulnadvisor.model.advisory import Advisory
from vulnadvisor.output.gating import parse_fail_on, should_fail
from vulnadvisor.output.json_report import build_report, to_json
from vulnadvisor.output.sarif import to_sarif_json
from vulnadvisor.output.upload import UploadError, upload_report
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


def build_explainer() -> Explainer:
    """Build the explainer: LLM-backed when ANTHROPIC_API_KEY is set, else template-only.

    Explanations are cached in the local SQLite cache and never influence the deterministic score.
    """
    client = build_anthropic_client()
    return Explainer(client=client, cache=SqliteCache(default_cache_path()))


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
    top: Annotated[
        int | None,
        typer.Option(
            "--top",
            min=1,
            help="Limit output to the top N findings by priority score (default: no limit).",
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
    no_explain: Annotated[
        bool,
        typer.Option(
            "--no-explain",
            help="Disable the plain-English Card A attack story (terminal output only).",
        ),
    ] = False,
    upload: Annotated[
        bool,
        typer.Option(
            "--upload",
            help="After scanning, upload the JSON report to a VulnAdvisor platform instance.",
        ),
    ] = False,
    api_url: Annotated[
        str | None,
        typer.Option(
            "--api-url",
            envvar="API_URL",
            help="Platform base URL for --upload (default: the API_URL env var).",
        ),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            envvar="VULNADVISOR_API_KEY",
            help="Org-scoped API key for --upload (default: the VULNADVISOR_API_KEY env var).",
        ),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo",
            help="Repository name to upload under (default: the scanned directory's name).",
        ),
    ] = None,
    dashboard_url: Annotated[
        str | None,
        typer.Option(
            "--dashboard-url",
            envvar="VULNADVISOR_DASHBOARD_URL",
            help="Dashboard base URL, used only to print a link after --upload.",
        ),
    ] = None,
) -> None:
    """Scan PATH for vulnerable dependencies and emit ranked, prioritized results.

    Matches declared/locked dependencies against OSV, enriches with EPSS and CISA KEV, and ranks
    by the deterministic priority score. ``--format`` selects the terminal three-card view, JSON,
    or SARIF 2.1.0 (for GitHub code scanning). ``--fail-on`` gates the exit code.
    ``--top N`` limits the *output* to the N highest-priority findings (ranking is unchanged;
    the exit-code gate still considers every finding). ``--public/--internal`` is reserved for
    reachability (M4+).
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

    # Findings are already ranked by priority (order_findings); --top is a pure display limit on
    # the leading N. It never reorders and never affects --fail-on, which gates over every finding.
    shown = report.findings if top is None else report.findings[:top]

    if output_format is OutputFormat.JSON:
        print(to_json(shown, report.degraded_sources, tool_version=_resolve_version()))
    elif output_format is OutputFormat.SARIF:
        print(to_sarif_json(shown, report.degraded_sources, tool_version=_resolve_version()))
    else:
        explanations = None
        if not no_explain:
            explainer = build_explainer()
            explanations = [explainer.explain(finding) for finding in shown]
        render_report(shown, report.degraded_sources, Console(), explanations)

    if upload:
        _upload_report(
            report, path, api_url=api_url, api_key=api_key, repo=repo, dashboard_url=dashboard_url
        )

    if threshold is not None and should_fail(report.findings, threshold):
        raise typer.Exit(code=1)


def _upload_report(
    report: ScanReport,
    path: Path,
    *,
    api_url: str | None,
    api_key: str | None,
    repo: str | None,
    dashboard_url: str | None,
) -> None:
    """Build the full JSON report and POST it to the platform; print a confirmation or fail.

    Always uploads every finding (never the ``--top`` display subset). CI commit/ref are read from
    GITHUB_SHA/GITHUB_REF when present so PR diffs line up; otherwise sensible defaults are used.
    """
    document = build_report(
        report.findings, report.degraded_sources, tool_version=_resolve_version()
    )
    repo_name = repo or (path if path.is_dir() else path.parent).resolve().name
    try:
        result = upload_report(
            document,
            api_url=api_url or "",
            api_key=api_key or "",
            repo=repo_name,
            ref=os.environ.get("GITHUB_REF") or "refs/heads/main",
            commit_sha=(os.environ.get("GITHUB_SHA") or "0" * 40)[:40],
        )
    except UploadError as exc:
        typer.secho(f"Upload failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    total = len(report.findings)
    typer.secho(
        f"✓ Uploaded {total} finding(s) to '{repo_name}' (scan {result.scan_id}).",
        fg=typer.colors.GREEN,
    )
    if dashboard_url:
        typer.echo(f"  View: {dashboard_url.rstrip('/')}/scans/{result.scan_id}")


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
