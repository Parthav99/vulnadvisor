"""VulnAdvisor command-line entrypoint (Typer app)."""

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
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.cli.render import render_report
from vulnadvisor.output.gating import parse_fail_on, should_fail
from vulnadvisor.output.json_report import to_json
from vulnadvisor.output.sarif import to_sarif_json
from vulnadvisor.store.cache import SqliteCache, default_cache_path


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

    report = scan_project(path, build_matcher())

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
