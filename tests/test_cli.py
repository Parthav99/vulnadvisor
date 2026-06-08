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
    # A dependency OSV won't match (fixture only returns jinja2 data for any OSV call), so use a
    # project whose only dep is something the matcher maps to no advisory by emptying OSV.
    (tmp_path / "requirements.txt").write_text("leftpad==1.0.0\n", encoding="utf-8")
    monkeypatch.setattr(cli_main, "build_matcher", lambda: fake_matcher({"OSV"}))

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Degraded sources: OSV" in result.stdout
