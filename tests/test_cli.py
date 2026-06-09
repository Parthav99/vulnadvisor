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
