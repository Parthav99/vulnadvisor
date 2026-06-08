"""VulnAdvisor command-line entrypoint (Typer app)."""

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
from vulnadvisor.store.cache import SqliteCache, default_cache_path

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
            help="Exit non-zero when findings meet/exceed this tier or score (not yet enforced).",
        ),
    ] = None,
) -> None:
    """Scan PATH for vulnerable dependencies and print the ranked three-card report.

    Matches declared/locked dependencies against OSV, enriches with EPSS and CISA KEV, and ranks
    by the deterministic priority score. ``--fail-on`` is accepted but not yet enforced (exit-code
    gating arrives in Task 3.1); ``--public/--internal`` is reserved for reachability (M4+).
    """
    _ = (public, fail_on)  # reserved for later milestones; accepted now for a stable CLI surface
    report = scan_project(path, build_matcher())
    render_report(report.findings, report.degraded_sources, Console())
