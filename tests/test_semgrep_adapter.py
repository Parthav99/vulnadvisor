"""Tests for the Semgrep OSS adapter (Task 21.2).

The whole adapter is exercised with **no Semgrep installed**: ``parse``/``normalize`` are pure over
recorded JSON, and the subprocess + PATH probe are injected. The release-blocking properties are
defensive parsing (never raise, never drop a record), the tool-absent clean skip, and the
soundness floor (every normalized finding is ``DYNAMIC_UNKNOWN`` with ``flow is None`` until the
21.3 overlay refines it).
"""

import json
from pathlib import Path

import pytest

from vulnadvisor.sast.external import SemgrepAdapter
from vulnadvisor.sast.external.base import UNKNOWN_FILE, extract_cwe
from vulnadvisor.sast.model import SastTier


def _result(
    *,
    check_id: str = "python.lang.security.dangerous-subprocess-use",
    path: str = "app/views.py",
    line: int = 12,
    col: int = 5,
    cwe: object = ("CWE-78: Improper Neutralization of Special Elements",),
    severity: str = "ERROR",
    message: str = "Detected subprocess function with shell=True.",
) -> dict[str, object]:
    """Build one Semgrep ``results[]`` object."""
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": col},
        "end": {"line": line, "col": col + 10},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": {"cwe": cwe},
        },
    }


def _output(*results: dict[str, object], errors: list[object] | None = None) -> str:
    """Serialize a Semgrep ``--json`` document."""
    return json.dumps({"results": list(results), "errors": errors or [], "paths": {"scanned": []}})


# --- extract_cwe (the defensive CWE token extractor) ---------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CWE-89: SQL Injection", "CWE-89"),
        (["CWE-78: ...", "CWE-79: ..."], "CWE-78"),
        ("cwe-22 lowercase", "CWE-22"),
        ("no cwe here", None),
        ([], None),
        (None, None),
        (123, None),
        (["not a cwe", "CWE-502: deserialization"], "CWE-502"),
    ],
)
def test_extract_cwe(value: object, expected: str | None) -> None:
    assert extract_cwe(value) == expected


# --- parse: table-driven over recorded JSON ------------------------------------------------------


def test_parse_single_finding() -> None:
    parsed = SemgrepAdapter().parse(_output(_result()))
    assert parsed.degraded == ()
    assert len(parsed.records) == 1
    record = parsed.records[0]
    assert record.tool == "semgrep-oss"
    assert record.check_id == "python.lang.security.dangerous-subprocess-use"
    assert record.file == "app/views.py"
    assert record.line == 12
    assert record.col == 4  # 1-based Semgrep col -> our 0-based offset
    assert record.cwe == "CWE-78"
    assert record.severity == "ERROR"
    assert record.located is True


def test_parse_multiple_findings() -> None:
    parsed = SemgrepAdapter().parse(
        _output(
            _result(check_id="rule.a", line=1),
            _result(check_id="rule.b", line=2, cwe="CWE-89: SQL Injection"),
            _result(check_id="rule.c", line=3, cwe=["CWE-502: Deserialization"]),
        )
    )
    assert parsed.degraded == ()
    assert [r.check_id for r in parsed.records] == ["rule.a", "rule.b", "rule.c"]
    assert [r.cwe for r in parsed.records] == ["CWE-78", "CWE-89", "CWE-502"]


def test_parse_unknown_rule_no_cwe() -> None:
    """A rule that exposes no CWE is kept with ``cwe is None`` (overlay escalates it later)."""
    result = _result(check_id="custom.rule", cwe=None)
    # Remove the metadata.cwe entirely to mirror a rule with no CWE tag at all.
    result["extra"] = {"message": "Some finding", "severity": "WARNING", "metadata": {}}
    parsed = SemgrepAdapter().parse(_output(result))
    assert len(parsed.records) == 1
    assert parsed.records[0].cwe is None
    assert parsed.records[0].located is True


def test_parse_malformed_json_is_safe_skip() -> None:
    parsed = SemgrepAdapter().parse("{not valid json")
    assert parsed.records == ()
    assert any("malformed JSON" in reason for reason in parsed.degraded)


def test_parse_non_object_root_is_safe_skip() -> None:
    parsed = SemgrepAdapter().parse("[1, 2, 3]")
    assert parsed.records == ()
    assert any("unexpected JSON root" in reason for reason in parsed.degraded)


def test_parse_missing_results_array() -> None:
    parsed = SemgrepAdapter().parse(json.dumps({"errors": []}))
    assert parsed.records == ()
    assert any("no 'results' array" in reason for reason in parsed.degraded)


def test_parse_skips_malformed_result_but_keeps_good_ones() -> None:
    raw = json.dumps({"results": [_result(check_id="good"), "not-an-object", 42], "errors": []})
    parsed = SemgrepAdapter().parse(raw)
    assert [r.check_id for r in parsed.records] == ["good"]
    assert any("skipped 2 malformed result(s)" in reason for reason in parsed.degraded)


def test_parse_surfaces_tool_errors_as_degraded() -> None:
    parsed = SemgrepAdapter().parse(_output(_result(), errors=[{"message": "rule failed"}]))
    assert len(parsed.records) == 1  # the finding still lands
    assert any("1 tool error(s)" in reason for reason in parsed.degraded)


def test_parse_missing_location_keeps_record_with_sentinel() -> None:
    """A result with no usable path/line is kept (overlay escalates), never dropped."""
    raw = json.dumps({"results": [{"check_id": "r", "extra": {"metadata": {"cwe": "CWE-22"}}}]})
    parsed = SemgrepAdapter().parse(raw)
    assert len(parsed.records) == 1
    record = parsed.records[0]
    assert record.file == UNKNOWN_FILE
    assert record.line == 0
    assert record.located is False
    assert record.cwe == "CWE-22"


# --- normalize: pre-overlay soundness floor ------------------------------------------------------


def test_normalize_known_cwe_uses_our_label() -> None:
    parsed = SemgrepAdapter().parse(_output(_result(cwe="CWE-78: cmd")))
    (finding,) = SemgrepAdapter().normalize(parsed.records)
    assert finding.cwe == "CWE-78"
    assert finding.kind == "command-injection"  # reused from our native rule pack
    assert finding.tier is SastTier.DYNAMIC_UNKNOWN
    assert finding.flow is None
    assert finding.source_kind is None
    assert finding.callee == "python.lang.security.dangerous-subprocess-use"
    assert "Semgrep OSS" in finding.reason


def test_normalize_unknown_cwe_uses_generic_label() -> None:
    result = _result(check_id="x.y.z", cwe=None, message="Mystery weakness detected")
    result["extra"] = {"message": "Mystery weakness detected", "severity": "INFO", "metadata": {}}
    parsed = SemgrepAdapter().parse(_output(result))
    (finding,) = SemgrepAdapter().normalize(parsed.records)
    assert finding.cwe == ""
    assert finding.kind == "external-finding"
    assert finding.title == "Mystery weakness detected"
    assert finding.tier is SastTier.DYNAMIC_UNKNOWN


def test_normalize_is_deterministic() -> None:
    raw = _output(_result(check_id="a", line=1), _result(check_id="b", line=2))
    adapter = SemgrepAdapter()
    first = adapter.normalize(adapter.parse(raw).records)
    second = adapter.normalize(adapter.parse(raw).records)
    assert first == second


# --- availability + run: subprocess shelled through a mock ---------------------------------------


def test_available_uses_injected_which() -> None:
    present = SemgrepAdapter(which=lambda _name: "/usr/bin/semgrep")
    absent = SemgrepAdapter(which=lambda _name: None)
    assert present.available() is True
    assert absent.available() is False


def test_scan_tool_absent_is_clean_skip(tmp_path: Path) -> None:
    """No Semgrep on PATH → a no-op result with an install hint, never a crash."""
    adapter = SemgrepAdapter(which=lambda _name: None, runner=_unreachable_runner)
    result = adapter.scan(tmp_path)
    assert result.ran is False
    assert result.findings == ()
    assert any("pip install vulnadvisor[semgrep]" in reason for reason in result.degraded)


def test_scan_runs_when_available(tmp_path: Path) -> None:
    captured: list[Path] = []

    def runner(target: Path) -> str:
        captured.append(target)
        return _output(_result(cwe="CWE-89: SQL Injection", line=7))

    adapter = SemgrepAdapter(which=lambda _name: "/usr/bin/semgrep", runner=runner)
    result = adapter.scan(tmp_path)
    assert captured == [tmp_path]
    assert result.ran is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cwe == "CWE-89"
    assert finding.line == 7
    assert finding.tier is SastTier.DYNAMIC_UNKNOWN


def test_scan_run_failure_degrades_not_crashes(tmp_path: Path) -> None:
    """A runner that returns garbage (e.g. a crashed Semgrep) degrades to a logged reason."""
    adapter = SemgrepAdapter(which=lambda _name: "/usr/bin/semgrep", runner=lambda _t: "")
    result = adapter.scan(tmp_path)
    assert result.ran is True
    assert result.findings == ()
    assert result.degraded  # empty output -> malformed JSON degraded reason


def test_default_runner_handles_missing_binary(tmp_path: Path) -> None:
    """The production runner returns '' (not an exception) when the binary cannot be executed."""
    adapter = SemgrepAdapter(which=lambda _name: "/usr/bin/semgrep")
    # No semgrep on this machine; the real subprocess.run raises FileNotFoundError -> '' .
    assert adapter.run(tmp_path) == ""


def _unreachable_runner(_target: Path) -> str:
    raise AssertionError("runner must not be called when the tool is absent")
