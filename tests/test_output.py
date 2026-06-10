import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.protocols import Validator

from vulnadvisor.model import PriorityBand, ScoredFinding
from vulnadvisor.output import (
    EXIT_FINDINGS,
    EXIT_OK,
    FailOn,
    build_report,
    build_sarif,
    parse_fail_on,
    should_fail,
    to_json,
)

SNAP = Path(__file__).resolve().parent.parent / "fixtures" / "snapshots"
SARIF_SCHEMA = Path(__file__).resolve().parent.parent / "fixtures" / "schemas" / "sarif-2.1.0.json"


# --- JSON report ------------------------------------------------------------------------------


def test_json_report_structure(sample_findings: list[ScoredFinding]) -> None:
    report = build_report(sample_findings, ("OSV",), tool_version="0.1.0")
    assert report["schema_version"] == "1.1"
    assert report["tool"] == {"name": "vulnadvisor", "version": "0.1.0"}
    assert report["degraded_sources"] == ["OSV"]
    assert report["summary"]["total"] == 2
    assert report["summary"]["by_band"]["critical"] == 1
    assert report["summary"]["by_band"]["low"] == 1
    first = report["findings"][0]
    assert first["dependency"]["name"] == "jinja2"
    assert first["advisory"]["cve_ids"] == ["CVE-2019-10906"]
    # 1.1 additive field: the canonical CVE-first display id; the raw id stays untouched.
    assert first["advisory"]["display_id"] == "CVE-2019-10906"
    assert first["advisory"]["id"] == "GHSA-462w-v97r-4m45"
    assert first["in_kev"] is True
    assert first["score"]["band"] == "critical"
    assert first["fix"]["command"] == 'pip install --upgrade "Jinja2>=2.10.1"'
    assert first["fix"]["fixed_version"] == "2.10.1"
    assert first["fix"]["has_fix"] is True
    assert first["fix"]["is_major_jump"] is False


def test_json_is_valid_and_ascii(sample_findings: list[ScoredFinding]) -> None:
    text = to_json(sample_findings, (), tool_version="0.1.0")
    json.loads(text)  # parses
    assert text == text.encode("ascii", "strict").decode("ascii")  # ASCII-safe


def test_json_snapshot(sample_findings: list[ScoredFinding]) -> None:
    text = to_json(sample_findings, ("OSV",), tool_version="0.1.0")
    SNAP.mkdir(parents=True, exist_ok=True)
    expected = SNAP / "report.json"
    if not expected.exists():
        expected.write_text(text, encoding="utf-8")
    assert text == expected.read_text(encoding="utf-8")


# --- SARIF ------------------------------------------------------------------------------------


def test_sarif_validates_against_2_1_0_schema(sample_findings: list[ScoredFinding]) -> None:
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    log = build_sarif(sample_findings, ("OSV",), tool_version="0.1.0")
    validator: Validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(log), key=lambda e: list(e.path))
    assert errors == [], "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_sarif_structure_and_levels(sample_findings: list[ScoredFinding]) -> None:
    log = build_sarif(sample_findings, (), tool_version="0.1.0")
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnAdvisor"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert "GHSA-462w-v97r-4m45" in rule_ids  # ruleId stays the stable raw advisory id
    # Only the human-readable shortDescription goes CVE-first.
    jinja_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "GHSA-462w-v97r-4m45")
    assert jinja_rule["shortDescription"]["text"].startswith("CVE-2019-10906: ")
    results = run["results"]
    assert results[0]["level"] == "error"  # critical -> error
    assert results[1]["level"] == "note"  # low -> note
    assert results[0]["properties"]["in_kev"] is True
    assert results[0]["properties"]["fixed_version"] == "2.10.1"
    assert results[0]["properties"]["fix_command"] == 'pip install --upgrade "Jinja2>=2.10.1"'
    # GitHub-facing security-severity is present and numeric.
    sev = run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    assert 0.0 <= float(sev) <= 10.0


# --- fail-on parsing + exit codes -------------------------------------------------------------


def test_exit_code_constants() -> None:
    assert EXIT_OK == 0
    assert EXIT_FINDINGS == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("critical", FailOn(band=PriorityBand.CRITICAL)),
        ("HIGH", FailOn(band=PriorityBand.HIGH)),
        ("low", FailOn(band=PriorityBand.LOW)),
        ("85", FailOn(score=85.0)),
        ("0", FailOn(score=0.0)),
        ("100", FailOn(score=100.0)),
    ],
)
def test_parse_fail_on(value: str, expected: FailOn) -> None:
    assert parse_fail_on(value) == expected


@pytest.mark.parametrize("value", ["nonsense", "-1", "101", ""])
def test_parse_fail_on_invalid(value: str) -> None:
    with pytest.raises(ValueError, match="invalid --fail-on"):
        parse_fail_on(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("critical", True),  # jinja2 is CRITICAL
        ("high", True),
        ("low", True),  # both findings are >= LOW
        ("90", True),  # jinja2 is 91.9 >= 90
        ("95", False),  # nothing reaches 95
    ],
)
def test_should_fail(sample_findings: list[ScoredFinding], value: str, expected: bool) -> None:
    assert should_fail(sample_findings, parse_fail_on(value)) is expected


def test_should_fail_empty_findings() -> None:
    assert should_fail([], parse_fail_on("info")) is False
