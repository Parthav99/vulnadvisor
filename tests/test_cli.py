import json
from collections.abc import Callable
from pathlib import Path

from typer.testing import CliRunner

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.cli import main as cli_main
from vulnadvisor.cli.main import app
from vulnadvisor.llm.explainer import Explainer

runner = CliRunner()


def test_version_exits_zero_and_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vulnadvisor" in result.stdout


def test_scan_missing_path_errors() -> None:
    result = runner.invoke(app, ["scan", "this-path-does-not-exist-xyz"])
    assert result.exit_code != 0


def test_scan_renders_ranked_three_cards(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    # Keep the test hermetic (no network) regardless of ANTHROPIC_API_KEY: template-only explainer.
    monkeypatch.setattr(cli_main, "build_explainer", lambda: Explainer(client=None))

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    out = result.stdout
    assert "finding(s), highest priority first" in out
    assert "jinja2" in out
    assert "A - Attack story" in out  # plain-English Card A (templated fallback here)
    assert "Why:" in out  # one-line verdict rationale
    assert "Risk" in out
    assert "Action" in out
    assert 'Fix: pip install --upgrade "jinja2>=2.10.1"' in out
    assert "Fix now" in out  # CRITICAL verdict for this KEV + high-EPSS finding


def test_scan_no_findings_message(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    # With OSV down, no advisories are matched and the source is flagged degraded (not "safe").
    (tmp_path / "requirements.txt").write_text("leftpad==1.0.0\n", encoding="utf-8")
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher({"OSV"}))

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Degraded sources: OSV" in result.stdout


def _project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    return tmp_path


def test_scan_json_format(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1.2"
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["dependency"]["name"] == "jinja2"


def test_scan_sarif_format(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--format", "sarif"])
    assert result.exit_code == 0
    log = json.loads(result.stdout)
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"][0]["ruleId"] == "GHSA-462w-v97r-4m45"


def test_scan_upload_posts_full_report_and_confirms(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    from vulnadvisor.output.upload import UploadResult

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    captured: dict[str, object] = {}

    def fake_upload(report, **kwargs):  # type: ignore[no-untyped-def]
        captured["report"] = report
        captured.update(kwargs)
        return UploadResult(scan_id="scan-123", introduced=1, fixed=0, unchanged=0)

    monkeypatch.setattr(cli_main, "upload_report", fake_upload)
    # Deterministic outside/inside CI: no GITHUB_* env, and tmp_path is not a git repo.
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.delenv("GITHUB_REF", raising=False)
    result = runner.invoke(
        app,
        [
            "scan",
            str(_project(tmp_path)),
            "--format",
            "json",
            "--upload",
            "--api-url",
            "https://api.example.com",
            "--api-key",
            "va_test.secret",
            "--dashboard-url",
            "https://dash.example.com",
        ],
    )
    assert result.exit_code == 0
    assert captured["api_url"] == "https://api.example.com"
    assert captured["api_key"] == "va_test.secret"
    assert captured["repo"] == tmp_path.resolve().name
    assert captured["report"]["schema_version"] == "1.2"  # type: ignore[index]
    # A local scan of a non-repo directory carries null metadata — never "0000000" (Task 12.2).
    assert captured["commit_sha"] is None
    assert captured["ref"] is None
    assert "Uploaded" in result.stdout and "scan-123" in result.stdout
    assert "dash.example.com/scans/scan-123" in result.stdout


def test_scan_upload_failure_exits_nonzero(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    from vulnadvisor.output.upload import UploadError

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())

    def boom(report, **kwargs):  # type: ignore[no-untyped-def]
        raise UploadError("server rejected the upload (HTTP 401)")

    monkeypatch.setattr(cli_main, "upload_report", boom)
    result = runner.invoke(
        app,
        ["scan", str(_project(tmp_path)), "--format", "json", "--upload", "--api-key", "k"],
        env={"API_URL": "https://api.example.com"},
    )
    assert result.exit_code == 1
    assert "Upload failed" in result.output


def test_scan_fail_on_triggers_nonzero_exit(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--fail-on", "high"])
    assert result.exit_code == 1  # jinja2 finding is CRITICAL >= high


def test_scan_fail_on_below_threshold_exits_zero(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--fail-on", "100"])
    assert result.exit_code == 0


def test_scan_invalid_fail_on_is_usage_error(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--fail-on", "bogus"])
    assert result.exit_code == 2  # Typer usage error


def test_scan_top_limits_json_output(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
    sample_findings,  # type: ignore[no-untyped-def]
) -> None:
    from vulnadvisor.cli.pipeline import ScanReport

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    monkeypatch.setattr(cli_main, "scan_project", lambda *a, **k: ScanReport(sample_findings, ()))

    # Without --top, both ranked findings are emitted.
    full = runner.invoke(app, ["scan", str(_project(tmp_path)), "--format", "json"])
    assert json.loads(full.stdout)["summary"]["total"] == 2

    # --top 1 keeps only the highest-priority finding (jinja2), in unchanged order.
    res = runner.invoke(app, ["scan", str(_project(tmp_path)), "--format", "json", "--top", "1"])
    payload = json.loads(res.stdout)
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["dependency"]["name"] == "jinja2"


def test_scan_top_terminal_hides_lower_finding(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
    sample_findings,  # type: ignore[no-untyped-def]
) -> None:
    from vulnadvisor.cli.pipeline import ScanReport

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    monkeypatch.setattr(cli_main, "build_explainer", lambda: Explainer(client=None))
    monkeypatch.setattr(cli_main, "scan_project", lambda *a, **k: ScanReport(sample_findings, ()))

    res = runner.invoke(app, ["scan", str(_project(tmp_path)), "--top", "1"])
    assert res.exit_code == 0
    assert "Jinja2" in res.stdout  # the top finding is shown
    assert "Flask" not in res.stdout  # the lower-priority finding is hidden


def test_scan_top_does_not_weaken_fail_on_gate(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
    sample_findings,  # type: ignore[no-untyped-def]
) -> None:
    # --top is a display limit only: --fail-on still gates over every finding.
    from vulnadvisor.cli.pipeline import ScanReport

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    monkeypatch.setattr(cli_main, "build_explainer", lambda: Explainer(client=None))
    monkeypatch.setattr(cli_main, "scan_project", lambda *a, **k: ScanReport(sample_findings, ()))

    res = runner.invoke(app, ["scan", str(_project(tmp_path)), "--top", "1", "--fail-on", "high"])
    assert res.exit_code == 1  # the CRITICAL jinja2 finding still trips the gate


def test_scan_top_zero_is_usage_error(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    result = runner.invoke(app, ["scan", str(_project(tmp_path)), "--top", "0"])
    assert result.exit_code == 2  # Typer rejects --top below the min of 1


def test_backfill_command(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    from vulnadvisor.model import Advisory, ExtractionStatus, SymbolExtraction

    class _OSV:
        def query(self, dependency):  # type: ignore[no-untyped-def]
            return [Advisory(id="GHSA-cli-1")] if dependency.name == "pyyaml" else []

    class _Ext:
        def extract(self, advisory):  # type: ignore[no-untyped-def]
            return SymbolExtraction(advisory_id=advisory.id, status=ExtractionStatus.NO_FIX_LINK)

    monkeypatch.setattr(cli_main, "build_osv_client", lambda: _OSV())
    monkeypatch.setattr(cli_main, "build_symbol_extractor", lambda: _Ext())

    db = tmp_path / "symbols.sqlite"
    result = runner.invoke(app, ["backfill", "PyYAML", "--db", str(db)])
    assert result.exit_code == 0
    assert "Dataset now holds 1 advisories" in result.stdout

    from vulnadvisor.store import SymbolDataset

    dataset = SymbolDataset(db)
    assert dataset.has("GHSA-cli-1")
    dataset.close()


def test_backfill_requires_targets() -> None:
    result = runner.invoke(app, ["backfill"])
    assert result.exit_code == 2  # no packages and no --top


# --- vulnadvisor login / logout (Task 14.1) -------------------------------------------------------


def test_login_stores_credentials_and_never_prints_key(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    import webbrowser

    from vulnadvisor.output.credentials import load_credentials
    from vulnadvisor.output.devicelogin import DeviceCode, DeviceToken

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
    monkeypatch.setattr(
        cli_main,
        "request_device_code",
        lambda api_url, client_name=None: DeviceCode(
            device_code="dev-secret",
            user_code="XK7M-2PQ9",
            verification_uri="https://dash.example.com/activate",
            verification_uri_complete="https://dash.example.com/activate?code=XK7M-2PQ9",
            expires_in=900,
            interval=5,
        ),
    )
    monkeypatch.setattr(
        cli_main,
        "poll_device_token",
        lambda api_url, device_code, interval, expires_in: DeviceToken(
            access_token="va_k.s3cret-key", org_slug="acme"
        ),
    )

    result = runner.invoke(app, ["login", "--api-url", "https://api.example.com"])

    assert result.exit_code == 0
    assert "XK7M-2PQ9" in result.stdout  # the user code is shown
    assert "va_k.s3cret-key" not in result.output  # the key is never printed
    assert opened == ["https://dash.example.com/activate?code=XK7M-2PQ9"]
    stored = load_credentials(tmp_path / "vulnadvisor" / "credentials")
    assert stored is not None
    assert stored.api_key == "va_k.s3cret-key"
    assert stored.api_url == "https://api.example.com"
    assert stored.org_slug == "acme"
    assert "Logged in to org 'acme'" in result.stdout


def test_login_requires_api_url(
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.delenv("API_URL", raising=False)
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 2
    assert "API URL" in result.output


def test_login_failure_exits_nonzero(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    from vulnadvisor.output.devicelogin import LoginError

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    def boom(api_url, client_name=None):  # type: ignore[no-untyped-def]
        raise LoginError("too many login attempts; wait a minute and retry")

    monkeypatch.setattr(cli_main, "request_device_code", boom)
    result = runner.invoke(app, ["login", "--api-url", "https://api.example.com"])
    assert result.exit_code == 1
    assert "Login failed" in result.output
    assert not (tmp_path / "vulnadvisor" / "credentials").exists()


def test_logout_removes_credentials(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    from vulnadvisor.output.credentials import Credentials, save_credentials

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_credentials(
        Credentials(api_url="https://api.example.com", api_key="k", org_slug="acme"),
        tmp_path / "vulnadvisor" / "credentials",
    )

    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert "Logged out" in result.stdout
    assert not (tmp_path / "vulnadvisor" / "credentials").exists()

    again = runner.invoke(app, ["logout"])
    assert again.exit_code == 0
    assert "nothing to do" in again.stdout


def test_scan_upload_uses_stored_login_with_no_flags(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    """After `vulnadvisor login`, a bare `scan --upload` needs no flags or env vars."""
    from vulnadvisor.output.credentials import Credentials, save_credentials
    from vulnadvisor.output.upload import UploadResult

    config_home = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("VULNADVISOR_API_KEY", raising=False)
    save_credentials(
        Credentials(api_url="https://api.example.com", api_key="va_k.stored", org_slug="acme"),
        config_home / "vulnadvisor" / "credentials",
    )

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    captured: dict[str, object] = {}

    def fake_upload(report, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return UploadResult(scan_id="scan-9", introduced=1, fixed=0, unchanged=0)

    monkeypatch.setattr(cli_main, "upload_report", fake_upload)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project), "--format", "json", "--upload"])

    assert result.exit_code == 0
    assert captured["api_key"] == "va_k.stored"
    assert captured["api_url"] == "https://api.example.com"
    assert "Uploaded" in result.stdout


def test_scan_upload_explicit_flags_beat_stored_login(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    from vulnadvisor.output.credentials import Credentials, save_credentials
    from vulnadvisor.output.upload import UploadResult

    config_home = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    save_credentials(
        Credentials(api_url="https://stored.example.com", api_key="va_k.stored", org_slug="acme"),
        config_home / "vulnadvisor" / "credentials",
    )

    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher())
    captured: dict[str, object] = {}

    def fake_upload(report, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return UploadResult(scan_id="scan-10", introduced=0, fixed=0, unchanged=1)

    monkeypatch.setattr(cli_main, "upload_report", fake_upload)
    result = runner.invoke(
        app,
        [
            "scan",
            str(_project(tmp_path)),
            "--format",
            "json",
            "--upload",
            "--api-url",
            "https://flag.example.com",
            "--api-key",
            "va_k.flag",
        ],
    )

    assert result.exit_code == 0
    assert captured["api_key"] == "va_k.flag"
    assert captured["api_url"] == "https://flag.example.com"


def _tainted_project(tmp_path: Path) -> Path:
    """A first-party project with a confirmed command-injection flow (input() -> os.system)."""
    (tmp_path / "app.py").write_text(
        "import os\n\n\ndef run():\n    cmd = input()\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    return tmp_path


def test_scan_coverage_confirms_executed_finding(tmp_path: Path) -> None:
    # --sast-only keeps the scan offline (no matcher/network). The os.system sink is on line 6.
    project = _tainted_project(tmp_path)
    cov = tmp_path / "coverage.json"
    cov.write_text(json.dumps({"files": {"app.py": {"executed_lines": [6]}}}), encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(project), "--sast-only", "--coverage", str(cov), "--format", "json"]
    )
    assert result.exit_code == 0
    findings = json.loads(result.stdout)["findings"]
    code = [f for f in findings if f["finding_type"] == "code"]
    assert code, "expected a SAST finding"
    assert code[0]["runtime"]["status"] == "runtime-confirmed"
    assert {"file": "app.py", "line": 6} in code[0]["runtime"]["observed"]


def test_scan_coverage_not_observed_when_line_unexecuted(tmp_path: Path) -> None:
    project = _tainted_project(tmp_path)
    cov = tmp_path / "coverage.json"
    # The file is covered but none of the finding's lines ran -> advisory not-observed, tier kept.
    cov.write_text(json.dumps({"files": {"app.py": {"executed_lines": [1]}}}), encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(project), "--sast-only", "--coverage", str(cov), "--format", "json"]
    )
    assert result.exit_code == 0
    code = [f for f in json.loads(result.stdout)["findings"] if f["finding_type"] == "code"]
    assert code and code[0]["runtime"]["status"] == "not-observed"


def test_scan_coverage_terminal_shows_runtime_line(tmp_path: Path) -> None:
    project = _tainted_project(tmp_path)
    cov = tmp_path / "coverage.json"
    cov.write_text(json.dumps({"files": {"app.py": {"executed_lines": [6]}}}), encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project), "--sast-only", "--coverage", str(cov)])
    assert result.exit_code == 0
    assert "RUNTIME-CONFIRMED" in result.stdout


def test_scan_coverage_malformed_is_usage_error(tmp_path: Path) -> None:
    project = _tainted_project(tmp_path)
    cov = tmp_path / "coverage.json"
    cov.write_text("this is not coverage json", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project), "--sast-only", "--coverage", str(cov)])
    assert result.exit_code == 2  # Typer usage error, not a traceback


def test_scan_coverage_missing_file_is_usage_error(tmp_path: Path) -> None:
    project = _tainted_project(tmp_path)
    result = runner.invoke(
        app, ["scan", str(project), "--sast-only", "--coverage", str(tmp_path / "nope.json")]
    )
    assert result.exit_code == 2  # Typer's exists=True validation rejects it
