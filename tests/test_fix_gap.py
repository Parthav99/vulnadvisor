"""Task 19.1 — the *yield* gap, reproduced as a failing regression test.

A finding with an obvious, safe rewrite (``yaml.load`` -> ``yaml.safe_load``, CWE-502) must come
back with a real, validated fix even with **no model key** (offline). Today the fix loop is
model-only — there is no deterministic quick-fix path — so an offline run declines everything and
returns "no safe fix". This test runs the real validated-fix sweep over a seeded ``yaml.load``
fixture with a declining model client and asserts a validated fix is produced.

It is marked ``xfail(strict=True)``: it genuinely fails today (the gap) but is reported as
``xfailed`` so the gate stays green. Task 19.3 adds the deterministic quick-fix that runs before the
model; when it lands this test will ``XPASS`` and ``strict`` will fail the gate — **remove the
``xfail`` marker then** (see ``docs/fix-gap-trace.md``).
"""

from pathlib import Path

import pytest

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.llm.client import LLMError
from vulnadvisor.llm.fix import is_alarming
from vulnadvisor.llm.fix_validate import build_validator
from vulnadvisor.llm.suggest import generate_suggestions
from vulnadvisor.sast.model import ScoredSastFinding

# A single alarming, trivially-fixable CWE-502 sink: yaml.load on a non-literal argument.
_YAML_LOAD_FIXTURE = "import yaml\n\n\ndef load_config(data):\n    return yaml.load(data)\n"


class _DecliningClient:
    """A model client that always errors — stands in for "no model key / spent cap" in CI."""

    model = "scripted"

    def complete(self, *, system: str, user: str) -> str:
        raise LLMError("no model key configured")


class _NullMatcher:
    def match(self, dependencies: object) -> object:  # pragma: no cover - SAST-only scan
        raise AssertionError("SAST-only scan must not run SCA matching")


@pytest.mark.xfail(
    strict=True,
    reason="19.1 yield gap: no deterministic quick-fix yet, so yaml.load declines offline. "
    "Task 19.3 makes this pass — remove this marker then.",
)
def test_yaml_load_yields_a_validated_fix_offline(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(_YAML_LOAD_FIXTURE, encoding="utf-8")

    matcher: AdvisoryMatcher = _NullMatcher()  # type: ignore[assignment]
    findings = scan_project(proj, matcher, run_sca=False, run_sast=True).sast_findings

    # Sanity: the engine flags the yaml.load sink as an alarming CWE-502 finding.
    assert any(is_alarming(f) and f.finding.cwe == "CWE-502" for f in findings), (
        "fixture should produce an alarming CWE-502 (unsafe-deserialization) finding"
    )

    def source_for(rel: str) -> str | None:
        try:
            return (proj / rel).read_text(encoding="utf-8")
        except OSError:
            return None

    def validator_for(target: ScoredSastFinding) -> object:
        return build_validator(project_root=proj, target=target, baseline=findings)

    report = generate_suggestions(
        findings=findings,
        client=_DecliningClient(),  # offline: the model never yields a usable patch
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=source_for,  # type: ignore[arg-type]
        tool_version="19.1-test",
        max_attempts=1,
    )

    # RED today (no deterministic quick-fix); GREEN once 19.3 rewrites yaml.load -> yaml.safe_load
    # before the model and validates it.
    assert report.fixes, "expected an offline validated quick-fix for yaml.load (CWE-502); got none"
    assert any(fix.cwe == "CWE-502" for fix in report.fixes)
