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
from vulnadvisor.coverage import CoverageParseError, apply_coverage_overlay, parse_coverage
from vulnadvisor.engine.sast_scoring import order_unified
from vulnadvisor.llm.client import (
    LLMClient,
    Provider,
    build_anthropic_client,
    build_fix_client_from_env,
)
from vulnadvisor.llm.explainer import Explainer
from vulnadvisor.llm.fix import (
    FixError,
    extract_code_context,
    generate_fix,
    is_alarming,
    resolve_sast_finding,
    sast_finding_id,
)
from vulnadvisor.llm.fix_validate import PatchApplyError, apply_patch_to_tree, build_validator
from vulnadvisor.llm.suggest import generate_suggestions
from vulnadvisor.model.advisory import Advisory
from vulnadvisor.model.fix import FixOutcome
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.model.suggestion import SuggestionReport
from vulnadvisor.output.credentials import (
    Credentials,
    default_credentials_path,
    delete_credentials,
    load_credentials,
    save_credentials,
)
from vulnadvisor.output.devicelogin import LoginError, poll_device_token, request_device_code
from vulnadvisor.output.gating import parse_fail_on, should_fail
from vulnadvisor.output.github_pr import (
    GitHubHttp,
    GitHubPostError,
    UrllibGitHubHttp,
    post_review_suggestions,
    read_pr_context,
)
from vulnadvisor.output.gitmeta import detect_scan_metadata
from vulnadvisor.output.json_report import build_report, to_json
from vulnadvisor.output.pr_suggestion import build_review_comments
from vulnadvisor.output.sarif import to_sarif_json
from vulnadvisor.output.upload import UploadError, upload_report
from vulnadvisor.sast.model import ScoredSastFinding
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


# Provider-agnostic: a free OpenRouter key is enough; ANTHROPIC_API_KEY still works. Listing all
# three keeps the "your own key, the only network call" promise explicit (Task 17.3).
_MISSING_FIX_KEY_MESSAGE = (
    "vulnadvisor fix needs a language model API key. Set OPENROUTER_API_KEY (a free OpenRouter "
    "key works), OPENAI_API_KEY, or ANTHROPIC_API_KEY - your own key. It is the only network "
    "call fix makes; your code stays on this machine."
)


def build_fix_client(
    provider: Provider | None = None, model: str | None = None
) -> LLMClient | None:
    """Build the LLM client for ``vulnadvisor fix`` from the user's own key, or ``None``.

    Provider-flexible (Task 17.3): detects OpenRouter / OpenAI / Anthropic from the key prefix
    (``--provider`` overrides) across ``OPENROUTER_API_KEY`` → ``OPENAI_API_KEY`` →
    ``ANTHROPIC_API_KEY`` (first present wins). Defined as a module-level function so tests can
    substitute a scripted client. The fix loop's only network call goes through this client (the
    user's own key); every validation step is local.
    """
    return build_fix_client_from_env(provider_override=provider, model_override=model)


# Zero-setup PR suggestions need only the built-in Actions token — no GitHub App (Task 17.4).
_MISSING_GITHUB_TOKEN_MESSAGE = (
    "vulnadvisor suggest needs a GitHub token to post PR comments. In GitHub Actions set "
    "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} and grant 'permissions: pull-requests: write' "
    "(the built-in token is enough - no GitHub App required)."
)


def build_github_http() -> GitHubHttp:
    """Build the GitHub REST client for ``suggest`` (stdlib ``urllib``); test-substitutable."""
    return UrllibGitHubHttp()


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
    sca_only: Annotated[
        bool,
        typer.Option(
            "--sca-only",
            help="Only analyze dependency (SCA) reachability; skip the first-party SAST pass.",
        ),
    ] = False,
    sast_only: Annotated[
        bool,
        typer.Option(
            "--sast-only",
            help="Only analyze first-party code (SAST); skip dependency matching (works offline).",
        ),
    ] = False,
    coverage: Annotated[
        Path | None,
        typer.Option(
            "--coverage",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="coverage.py JSON report; confirms ambiguous findings whose code ran at runtime.",
        ),
    ] = None,
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
    suggestions: Annotated[
        Path | None,
        typer.Option(
            "--suggestions",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Validated-fix JSON from 'vulnadvisor fix --suggest-json', uploaded with the "
            "report so the GitHub App can post one-click in-line PR suggestions.",
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

    ``--coverage <coverage.json>`` overlays a coverage.py JSON report: a finding whose code is
    proven to execute at runtime is annotated ``RUNTIME-CONFIRMED`` (shown alongside its static
    tier), while a finding whose covered files ran none of its lines is marked ``not-observed``
    (advisory only). The overlay is escalation-only: it never changes a tier, score, or ranking.
    """
    _ = public  # reserved for later milestones; accepted now for a stable CLI surface

    if sca_only and sast_only:
        raise typer.BadParameter(
            "--sca-only and --sast-only are mutually exclusive", param_hint="--sca-only/--sast-only"
        )

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
            run_sca=not sast_only,
            run_sast=not sca_only,
        )
    finally:
        if analysis_cache is not None:
            analysis_cache.close()

    if coverage is not None:
        report = _overlay_coverage(report, coverage, path)

    # One ranked list across both finding types. --top is a pure display limit on the leading N
    # (never reorders, never affects --fail-on which gates over every finding). Slice the merged
    # ranking, then split back so each output renderer re-merges into the same order.
    ranked = order_unified([*report.findings, *report.sast_findings])
    shown = ranked if top is None else ranked[:top]
    sca_shown = [f for f in shown if isinstance(f, ScoredFinding)]
    sast_shown = [f for f in shown if isinstance(f, ScoredSastFinding)]
    version = _resolve_version()

    if output_format is OutputFormat.JSON:
        print(
            to_json(
                sca_shown, report.degraded_sources, tool_version=version, sast_findings=sast_shown
            )
        )
    elif output_format is OutputFormat.SARIF:
        print(
            to_sarif_json(
                sca_shown, report.degraded_sources, tool_version=version, sast_findings=sast_shown
            )
        )
    else:
        explanations = None
        if not no_explain:
            explainer = build_explainer()
            explanations = [explainer.explain(finding) for finding in sca_shown]
        render_report(
            sca_shown, report.degraded_sources, Console(), explanations, sast_findings=sast_shown
        )

    if upload:
        _upload_report(
            report,
            path,
            api_url=api_url,
            api_key=api_key,
            repo=repo,
            suggestions=suggestions,
            dashboard_url=dashboard_url,
        )

    if threshold is not None and should_fail([*report.findings, *report.sast_findings], threshold):
        raise typer.Exit(code=1)


def _overlay_coverage(report: ScanReport, coverage: Path, scan_path: Path) -> ScanReport:
    """Annotate ``report``'s findings with runtime evidence from a coverage.py JSON report.

    The coverage paths are normalized against the scanned project root (the scan path, or its parent
    when a single file was scanned), matching the project-relative paths findings already use.
    Malformed coverage input fails fast and cleanly (no traceback) per the defensive-parsing rule.
    """
    project_root = scan_path if scan_path.is_dir() else scan_path.parent
    try:
        data = parse_coverage(coverage.read_text(encoding="utf-8"), project_root)
    except (OSError, ValueError, CoverageParseError) as exc:
        raise typer.BadParameter(
            f"could not read coverage report: {exc}", param_hint="--coverage"
        ) from exc
    findings, sast_findings = apply_coverage_overlay(report.findings, report.sast_findings, data)
    return ScanReport(findings, report.degraded_sources, sast_findings)


def _upload_report(
    report: ScanReport,
    path: Path,
    *,
    api_url: str | None,
    api_key: str | None,
    repo: str | None,
    suggestions: Path | None,
    dashboard_url: str | None,
) -> None:
    """Build the full JSON report and POST it to the platform; print a confirmation or fail.

    Always uploads every finding (never the ``--top`` display subset). Commit/ref come from
    GITHUB_SHA/GITHUB_REF in CI, else from git in the scanned directory, else they are sent as
    null (never placeholder zeros) so the dashboard labels the upload a local scan.

    When ``suggestions`` points at a ``fix --suggest-json`` document it is attached to the upload
    so the platform can post validated fixes as in-line PR suggestions (the code stays in CI).

    Credentials resolve flag/env first, then the ``vulnadvisor login`` store — so a bare
    ``scan --upload`` works with no flags after a device login.
    """
    if not api_key or not api_url:
        stored = load_credentials()
        if stored is not None:
            api_key = api_key or stored.api_key
            api_url = api_url or stored.api_url

    document = build_report(
        report.findings,
        report.degraded_sources,
        tool_version=_resolve_version(),
        sast_findings=report.sast_findings,
    )
    suggestions_doc = _load_suggestions_doc(suggestions)
    repo_name = repo or (path if path.is_dir() else path.parent).resolve().name
    metadata = detect_scan_metadata(path)
    try:
        result = upload_report(
            document,
            api_url=api_url or "",
            api_key=api_key or "",
            repo=repo_name,
            ref=metadata.ref,
            commit_sha=metadata.commit_sha,
            suggestions=suggestions_doc,
        )
    except UploadError as exc:
        typer.secho(f"Upload failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    total = len(report.findings)
    # ASCII-only: a cp1252 Windows console (or redirected stdout) cannot encode "✓", and a
    # successful upload must never crash while printing its confirmation.
    typer.secho(
        f"Uploaded {total} finding(s) to '{repo_name}' (scan {result.scan_id}).",
        fg=typer.colors.GREEN,
    )
    if dashboard_url:
        typer.echo(f"  View: {dashboard_url.rstrip('/')}/scans/{result.scan_id}")


def _load_suggestions_doc(suggestions: Path | None) -> dict[str, object] | None:
    """Read + validate a ``fix --suggest-json`` document for upload, or fail with a clear message.

    Defensive (CLAUDE.md): a missing/garbled/wrong-shaped file is a clean ``BadParameter`` rather
    than a traceback; ``None`` (no ``--suggestions`` flag) returns ``None`` so nothing is attached.
    """
    if suggestions is None:
        return None
    try:
        raw = suggestions.read_text(encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(
            f"could not read suggestions file: {exc}", param_hint="--suggestions"
        ) from exc
    try:
        parsed = SuggestionReport.model_validate_json(raw)
    except ValueError as exc:
        raise typer.BadParameter(
            f"suggestions file is not a valid fix --suggest-json document: {exc}",
            param_hint="--suggestions",
        ) from exc
    return parsed.model_dump(mode="json")


def _default_client_name() -> str:
    """A recognizable device label like ``alice@laptop`` (defensive; never raises)."""
    import getpass
    import socket

    try:
        user = getpass.getuser()
    except (OSError, KeyError):
        user = "user"
    try:
        host = socket.gethostname() or "device"
    except OSError:
        host = "device"
    return f"{user}@{host}"[:200]


@app.command()
def login(
    api_url: Annotated[
        str | None,
        typer.Option(
            "--api-url",
            envvar="API_URL",
            help="Platform base URL to log in to (default: the API_URL env var).",
        ),
    ] = None,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="Do not open a browser; just print the activation URL."),
    ] = False,
) -> None:
    """Authenticate this machine with a VulnAdvisor platform (no key copy-paste).

    Requests a device code, opens the dashboard's activation page in your browser, and waits for
    approval. The minted org-scoped API key is stored in a local credentials file (0600) and is
    read automatically by ``scan --upload``; it is never printed.
    """
    import webbrowser

    if not api_url:
        raise typer.BadParameter(
            "no API URL: pass --api-url or set the API_URL environment variable",
            param_hint="--api-url",
        )

    try:
        code = request_device_code(api_url, client_name=_default_client_name())
    except LoginError as exc:
        typer.secho(f"Login failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("To finish logging in, enter this code in your dashboard:")
    typer.secho(f"\n    {code.user_code}\n", bold=True)
    typer.echo(f"Activation page: {code.verification_uri_complete}")

    opened = False
    if not no_browser:
        try:
            opened = webbrowser.open(code.verification_uri_complete)
        except webbrowser.Error:
            opened = False
    if not opened:
        typer.echo("Open the URL above in a browser to approve this device.")
    typer.echo(f"Waiting for approval (code expires in {code.expires_in // 60} min)...")

    try:
        token = poll_device_token(
            api_url, code.device_code, interval=code.interval, expires_in=code.expires_in
        )
    except LoginError as exc:
        typer.secho(f"Login failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    stored_at = save_credentials(
        Credentials(
            api_url=api_url.rstrip("/"), api_key=token.access_token, org_slug=token.org_slug
        )
    )
    # ASCII-only output: a cp1252 Windows console (or redirected stdout) cannot encode "✓"/"—",
    # and a login that succeeds must never crash while printing its confirmation.
    typer.secho(f"Logged in to org '{token.org_slug}'.", fg=typer.colors.GREEN)
    typer.echo(f"Credentials stored at {stored_at} - 'vulnadvisor scan . --upload' now just works.")


@app.command()
def logout() -> None:
    """Remove the stored credentials written by ``vulnadvisor login``."""
    path = default_credentials_path()
    if delete_credentials(path):
        typer.secho(f"Logged out; removed {path}.", fg=typer.colors.GREEN)
    else:
        typer.echo("No stored credentials found; nothing to do.")


@app.command()
def mcp() -> None:
    """Run the VulnAdvisor MCP server over stdio (agent-native local triage).

    Serves the local scan engine to any Model Context Protocol client (Claude Code, Cursor, ...):
    tools to scan a project and triage its findings - reachability, evidence, call paths, and the
    deterministic priority - without leaving the editor. Fully offline beyond the public vuln APIs
    a scan already uses; results are persisted locally so a fresh session can read the last scan.

    Requires the optional ``mcp`` extra: ``pip install 'vulnadvisor[mcp]'``.
    """
    try:
        from vulnadvisor.mcp.server import run_stdio
    except ImportError as exc:
        typer.secho(
            "The MCP server needs the optional 'mcp' extra. Install it with:\n"
            "    pip install 'vulnadvisor[mcp]'",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc
    run_stdio()


@app.command()
def fix(
    finding_id: Annotated[
        str | None,
        typer.Argument(
            help="Id of the first-party finding to fix (e.g. 'app/views.py:42:command-injection'). "
            "Omit with --suggest-json to fix every finding."
        ),
    ] = None,
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Path to the Python project to fix (default: current directory).",
        ),
    ] = Path("."),
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="Write the validated patch to the working tree (default: print it only).",
        ),
    ] = False,
    suggest_json: Annotated[
        Path | None,
        typer.Option(
            "--suggest-json",
            help="Write validated fixes for every finding to this JSON file (CI/PR-agent mode); "
            "upload it with 'scan --upload --suggestions <file>'.",
        ),
    ] = None,
    max_attempts: Annotated[
        int,
        typer.Option(
            "--max-attempts",
            min=1,
            max=5,
            help="How many times to retry the model with validation feedback (default: 3).",
        ),
    ] = 3,
    provider: Annotated[
        Provider | None,
        typer.Option(
            "--provider",
            help="Model provider (default: detected from your key prefix). "
            "A free OpenRouter key works.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Model id (default: the provider's default; or set VULNADVISOR_MODEL).",
        ),
    ] = None,
) -> None:
    """Generate and machine-validate a patch for a first-party (SAST) finding.

    Scans PATH for first-party vulnerabilities (offline), then asks your own LLM for the smallest
    safe patch for FINDING-ID and *proves* it on a throwaway copy of the project: the patch must
    apply cleanly, keep the code parsing/linting/type-checking, pass the project's tests, and — the
    soundness gate — make the finding disappear from a fresh scan without introducing a new one.
    Only a fully validated patch is shown; otherwise you get an honest "no safe fix found". The
    working tree is never touched unless you pass ``--apply``. The only network call is to your own
    model key; your code never leaves the machine otherwise.

    With ``--suggest-json <file>`` (CI / PR-agent mode) the finding id is optional: every alarming
    finding is fixed-and-validated and the validated patches are written to ``<file>`` for upload
    with the scan, where the GitHub App posts them as one-click in-line suggestions.
    """
    report = scan_project(path, build_matcher(), run_sca=False, run_sast=True)

    if suggest_json is not None:
        _fix_suggest_json(
            report, path, suggest_json, max_attempts=max_attempts, provider=provider, model=model
        )
        return

    if finding_id is None:
        typer.secho(
            "provide a finding id to fix, or use --suggest-json <file> to fix every finding.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        target = resolve_sast_finding(report.sast_findings, finding_id)
    except FixError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    client = build_fix_client(provider, model)
    if client is None:
        typer.secho(_MISSING_FIX_KEY_MESSAGE, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    def source_for(rel: str) -> str | None:
        try:
            return (path / rel).read_text(encoding="utf-8")
        except OSError:
            return None

    typer.echo(f"Fixing {sast_finding_id(target)} ({target.finding.cwe})...")
    context = extract_code_context(target.finding, source_for)
    validate = build_validator(project_root=path, target=target, baseline=report.sast_findings)
    result = generate_fix(
        finding=target.finding,
        code_context=context,
        client=client,
        validate=validate,
        max_attempts=max_attempts,
    )

    if result.outcome is not FixOutcome.VALIDATED or result.suggestion is None:
        typer.secho(
            f"No safe fix found after {len(result.attempts)} attempt(s).",
            fg=typer.colors.YELLOW,
            err=True,
        )
        for index, attempt in enumerate(result.attempts, start=1):
            if attempt.report is not None:
                reason = attempt.report.failure_feedback() or "validation failed"
            else:
                reason = attempt.note or "no patch produced"
            typer.echo(f"  Attempt {index}: {reason}", err=True)
        raise typer.Exit(code=1)

    suggestion = result.suggestion
    typer.secho(
        f"Validated patch found (model confidence: {suggestion.confidence.value}).",
        fg=typer.colors.GREEN,
    )
    typer.echo(f"Rationale: {suggestion.rationale}\n")
    typer.echo(suggestion.diff)

    if apply:
        try:
            apply_patch_to_tree(suggestion.diff, path)
        except PatchApplyError as exc:
            typer.secho(f"Failed to apply patch: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc
        typer.secho("Applied the validated patch to your working tree.", fg=typer.colors.GREEN)
    else:
        typer.echo("Re-run with --apply to write this patch to your working tree.")


def _fix_suggest_json(
    report: ScanReport,
    path: Path,
    out_file: Path,
    *,
    max_attempts: int,
    provider: Provider | None = None,
    model: str | None = None,
) -> None:
    """Fix-and-validate every alarming finding and write the validated patches to ``out_file``.

    This is the non-interactive CI half of ``vulnadvisor fix``: it never prints code and never
    touches the working tree — it produces the JSON the platform's GitHub App turns into in-line
    PR suggestions. Exit 0 even when no safe fix is found (an empty document is still valid to
    upload); exit 2 only when the model key is missing or the file cannot be written.
    """
    client = build_fix_client(provider, model)
    if client is None:
        typer.secho(_MISSING_FIX_KEY_MESSAGE, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    suggestion_report = _validate_fixes(report, path, client=client, max_attempts=max_attempts)

    try:
        out_file.write_text(suggestion_report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        typer.secho(f"Could not write {out_file}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho(
        f"Wrote {len(suggestion_report.fixes)} validated fix(es) to {out_file}.",
        fg=typer.colors.GREEN,
    )


def _validate_fixes(
    report: ScanReport, path: Path, *, client: LLMClient, max_attempts: int
) -> SuggestionReport:
    """Run the validated-fix loop over every alarming finding; return the validated patches.

    Shared by ``fix --suggest-json`` (writes the document) and ``suggest`` (posts it to a PR): both
    fix-and-validate every alarming finding with the 17.1 loop and keep only the proven patches.
    Per-finding progress is streamed to stderr so neither caller has to.
    """
    baseline = report.sast_findings

    def source_for(rel: str) -> str | None:
        try:
            return (path / rel).read_text(encoding="utf-8")
        except OSError:
            return None

    def validator_for(target: ScoredSastFinding) -> object:
        return build_validator(project_root=path, target=target, baseline=baseline)

    def on_result(scored: ScoredSastFinding, validated: bool) -> None:
        status = "fixed" if validated else "no safe fix"
        typer.echo(f"  {sast_finding_id(scored)} ({scored.finding.cwe}): {status}", err=True)

    typer.echo(
        f"Fixing {sum(1 for f in baseline if is_alarming(f))} alarming finding(s)...", err=True
    )
    return generate_suggestions(
        findings=baseline,
        client=client,
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=source_for,
        tool_version=_resolve_version(),
        max_attempts=max_attempts,
        on_result=on_result,
    )


@app.command()
def suggest(
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Path to the Python project to scan and fix (default: current directory).",
        ),
    ] = Path("."),
    max_attempts: Annotated[
        int,
        typer.Option(
            "--max-attempts",
            min=1,
            max=5,
            help="How many times to retry the model with validation feedback (default: 3).",
        ),
    ] = 3,
    provider: Annotated[
        Provider | None,
        typer.Option(
            "--provider",
            help="Model provider (default: detected from your key prefix). "
            "A free OpenRouter key works.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Model id (default: the provider's default; or set VULNADVISOR_MODEL).",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Generate and print the suggestions without posting them to the PR.",
        ),
    ] = False,
) -> None:
    """Post validated fixes as one-click in-line PR ``suggestion`` comments (CI, no App needed).

    Designed to run in GitHub Actions on ``pull_request`` events: it scans first-party code,
    machine-validates a patch for every alarming finding (the same loop as ``vulnadvisor fix``), and
    posts the fixes as in-line ``suggestion`` review comments using the built-in ``GITHUB_TOKEN`` -
    **no GitHub App, no webhook, no platform**. The pull request and head commit are read from the
    Actions event payload (``GITHUB_EVENT_PATH``). The review event is always a comment - never a
    "request changes", never an auto-commit; a developer clicks "Commit suggestion". Re-runs prune
    and repost our own prior suggestions, so a fixed finding's suggestion disappears in place.

    The only network calls are to your own model key and to GitHub; your source code stays in CI.
    Outside a pull request (e.g. a push build) this is a clean no-op. Use ``--dry-run`` to preview.
    """
    ctx = read_pr_context(os.environ)
    if ctx is None:
        typer.echo(
            "No pull request context found (GITHUB_EVENT_PATH); nothing to suggest.", err=True
        )
        return

    client = build_fix_client(provider, model)
    if client is None:
        typer.secho(_MISSING_FIX_KEY_MESSAGE, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    report = scan_project(path, build_matcher(), run_sca=False, run_sast=True)
    suggestion_report = _validate_fixes(report, path, client=client, max_attempts=max_attempts)
    comments = build_review_comments(
        [fix.model_dump(mode="json") for fix in suggestion_report.fixes]
    )

    if dry_run:
        typer.secho(
            f"Dry run: {len(comments)} in-line suggestion(s) from "
            f"{len(suggestion_report.fixes)} validated fix(es) for PR #{ctx.pr_number}.",
            fg=typer.colors.GREEN,
        )
        for comment in comments:
            typer.echo(f"\n--- {comment.path}:{comment.line} ---")
            typer.echo(comment.body)
        return

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        typer.secho(_MISSING_GITHUB_TOKEN_MESSAGE, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    try:
        posted = post_review_suggestions(
            build_github_http(), token=token, ctx=ctx, comments=comments
        )
    except GitHubPostError as exc:
        typer.secho(f"Could not post suggestions: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.secho(
        f"Posted {posted} in-line suggestion(s) to {ctx.repo_full_name} PR #{ctx.pr_number}.",
        fg=typer.colors.GREEN,
    )


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
