from typer.testing import CliRunner

from vulnadvisor.cli.main import app

runner = CliRunner()


def test_version_exits_zero_and_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vulnadvisor" in result.stdout


def test_scan_stub_exits_zero(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "scan (stub)" in result.stdout
    assert "public package" in result.stdout


def test_scan_internal_flag(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(app, ["scan", str(tmp_path), "--internal"])
    assert result.exit_code == 0
    assert "internal application" in result.stdout


def test_scan_missing_path_errors() -> None:
    result = runner.invoke(app, ["scan", "this-path-does-not-exist-xyz"])
    assert result.exit_code != 0
