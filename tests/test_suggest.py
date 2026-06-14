"""Tests for the CI half of the PR review agent (Task 17.2): ``fix --suggest-json`` orchestration.

The sweep that fixes-and-validates every alarming finding is driven with a *fake* validator and a
scripted client (no subprocess, no network), so we assert the soundness contract directly: only
findings whose patch passed validation appear in the uploaded document, and ``SANITIZED`` findings
are skipped entirely (nothing to fix).
"""

import json
from dataclasses import dataclass
from pathlib import Path

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.llm.client import LLMError
from vulnadvisor.llm.fix import sast_finding_id
from vulnadvisor.llm.suggest import build_validated_fix, generate_suggestions
from vulnadvisor.model.fix import FixConfidence, StepStatus, ValidationReport, ValidationStep
from vulnadvisor.model.suggestion import SUGGESTION_SCHEMA_VERSION, SuggestionReport, ValidatedFix
from vulnadvisor.sast.model import ScoredSastFinding

_TWO_SINKS = (
    "import os\n\n\ndef a():\n    os.system(input())\n\n\ndef b():\n    os.system(input())\n"
)
_DUMMY_DIFF = "--- a/app.py\n+++ b/app.py\n@@ -5 +5 @@\n-    os.system(input())\n+    pass\n"


@dataclass
class _ConstClient:
    """An :class:`LLMClient` returning the same fix JSON for every request (no network)."""

    diff: str = _DUMMY_DIFF
    model: str = "scripted"
    calls: int = 0

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        return json.dumps({"diff": self.diff, "rationale": "fix it", "confidence": "high"})


@dataclass
class _ErrorClient:
    """A client that always errors — exercises the no-safe-fix path without a validator."""

    model: str = "scripted"

    def complete(self, *, system: str, user: str) -> str:
        raise LLMError("model unavailable")


class _NullMatcher:
    def match(self, dependencies: object) -> object:  # pragma: no cover - never called
        raise AssertionError("SAST-only scan must not run SCA matching")


def _findings(tmp_path: Path, source: str) -> list[ScoredSastFinding]:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(source, encoding="utf-8")
    matcher: AdvisoryMatcher = _NullMatcher()  # type: ignore[assignment]
    return scan_project(proj, matcher, run_sca=False, run_sast=True).sast_findings


def _ok() -> ValidationReport:
    step = ValidationStep(name="rescan", status=StepStatus.PASSED)
    return ValidationReport(ok=True, steps=(step,))


def _fail() -> ValidationReport:
    return ValidationReport(
        ok=False,
        steps=(ValidationStep(name="rescan", status=StepStatus.FAILED, detail="still present"),),
    )


def _source_for(tmp_path: Path) -> object:
    def read(rel: str) -> str | None:
        try:
            return (tmp_path / "proj" / rel).read_text(encoding="utf-8")
        except OSError:
            return None

    return read


# --- generate_suggestions -----------------------------------------------------------------------


def test_generate_keeps_only_validated_fixes(tmp_path: Path) -> None:
    findings = _findings(tmp_path, _TWO_SINKS)
    assert len(findings) == 2  # two command-injection sinks, both alarming
    accept = sast_finding_id(findings[0])

    def validator_for(target: ScoredSastFinding) -> object:
        ok = sast_finding_id(target) == accept
        return lambda suggestion: _ok() if ok else _fail()

    seen: list[tuple[str, bool]] = []
    report = generate_suggestions(
        findings=findings,
        client=_ConstClient(),
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=_source_for(tmp_path),  # type: ignore[arg-type]
        tool_version="9.9.9",
        on_result=lambda f, ok: seen.append((sast_finding_id(f), ok)),
    )

    assert report.schema_version == SUGGESTION_SCHEMA_VERSION
    assert report.tool_version == "9.9.9"
    assert [f.finding_id for f in report.fixes] == [accept]
    only = report.fixes[0]
    assert only.diff == _DUMMY_DIFF and only.rationale == "fix it"
    assert only.confidence is FixConfidence.HIGH
    # Both findings were attempted; exactly one validated.
    assert sorted(seen) == sorted(
        [(sast_finding_id(findings[0]), True), (sast_finding_id(findings[1]), False)]
    )


def test_generate_skips_sanitized_findings(tmp_path: Path) -> None:
    # shlex.quote sanitizes the command-injection sink -> SANITIZED -> nothing to fix.
    sanitized = "import os\nimport shlex\n\n\ndef a():\n    os.system(shlex.quote(input()))\n"
    findings = _findings(tmp_path, sanitized)

    def validator_for(target: ScoredSastFinding) -> object:  # pragma: no cover - never called
        raise AssertionError("a SANITIZED finding must not be fixed")

    report = generate_suggestions(
        findings=findings,
        client=_ConstClient(),
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=_source_for(tmp_path),  # type: ignore[arg-type]
        tool_version="1",
    )
    assert report.fixes == ()


def test_generate_no_safe_fix_yields_empty_report(tmp_path: Path) -> None:
    findings = _findings(tmp_path, _TWO_SINKS)

    def validator_for(target: ScoredSastFinding) -> object:  # pragma: no cover - client errors
        return lambda suggestion: _ok()

    report = generate_suggestions(
        findings=findings,
        client=_ErrorClient(),
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=_source_for(tmp_path),  # type: ignore[arg-type]
        tool_version="1",
        max_attempts=2,
    )
    assert report.fixes == ()


def test_build_validated_fix_carries_engine_facts(tmp_path: Path) -> None:
    findings = _findings(tmp_path, _TWO_SINKS)
    fix = build_validated_fix(findings[0], _DUMMY_DIFF, "because", FixConfidence.LOW)
    assert isinstance(fix, ValidatedFix)
    assert fix.finding_id == sast_finding_id(findings[0])
    assert fix.cwe == "CWE-78"
    assert fix.kind == findings[0].finding.kind
    assert fix.tier == findings[0].finding.tier.value
    assert fix.confidence is FixConfidence.LOW
    assert fix.flow  # a rendered source->sink path is present


def test_report_round_trips_through_json() -> None:
    report = SuggestionReport(
        tool_version="2.0.0",
        fixes=(
            ValidatedFix(
                finding_id="app.py:5:command-injection",
                file="app.py",
                line=5,
                cwe="CWE-78",
                kind="command-injection",
                title="OS command injection",
                tier="CONFIRMED-FLOW",
                flow="a -> os.system (app.py:5)",
                rationale="quote it",
                confidence=FixConfidence.HIGH,
                diff=_DUMMY_DIFF,
            ),
        ),
    )
    restored = SuggestionReport.model_validate_json(report.model_dump_json())
    assert restored == report
