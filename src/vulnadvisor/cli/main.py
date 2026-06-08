"""VulnAdvisor command-line entrypoint (Typer app)."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    name="vulnadvisor",
    help="Stop scanning, start triaging — reachability-first vuln triage for Python.",
    no_args_is_help=True,
    add_completion=False,
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
    """Scan PATH for reachable dependency vulnerabilities.

    This is a scaffolding stub: it echoes the resolved invocation and exits 0. The analysis
    pipeline (dependency inventory, advisory matching, reachability, scoring) is built in later
    milestones.
    """
    project_kind = "public package" if public else "internal application"
    typer.echo(f"VulnAdvisor scan (stub) - target: {path}")
    typer.echo(f"  project kind: {project_kind}")
    typer.echo(f"  fail-on: {fail_on if fail_on is not None else '(unset)'}")
    typer.echo("Analysis pipeline not yet implemented; this is a scaffolding stub.")
