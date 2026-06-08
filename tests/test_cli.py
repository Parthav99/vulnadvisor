import json
from collections.abc import Callable
from pathlib import Path

from typer.testing import CliRunner

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.cli import main as cli_main
from vulnadvisor.cli.main import app

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

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    out = result.stdout
    assert "finding(s), highest priority first" in out
    assert "jinja2" in out
    assert "Attack summary" in out
    assert "Risk" in out
    assert "Action" in out
    assert "Fix: pip install --upgrade jinja2" in out
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
    assert payload["schema_version"] == "1.0"
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
