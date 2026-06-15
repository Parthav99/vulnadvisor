"""Task 19.1/19.3 — the *yield* gap, now a green regression test.

A finding with an obvious, safe rewrite (``yaml.load`` -> ``yaml.safe_load``, CWE-502) must come
back with a real, validated fix even with **no model key** (offline). Before Task 19.3 the fix loop
was model-only — there was no deterministic quick-fix path — so an offline run declined everything
and returned "no safe fix" (the gap reproduced here as ``xfail`` under 19.1).

Task 19.3 added the deterministic quick-fix that runs *before* the model and is accepted only after
the full validation loop, so this now passes: the offline sweep rewrites ``yaml.load`` to
``yaml.safe_load`` and validates it with a declining model client (the ``xfail`` marker is removed).
"""

from pathlib import Path

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

    # GREEN since 19.3: the deterministic quick-fix rewrites yaml.load -> yaml.safe_load before the
    # model and validates it offline (the declining client is never the source of the patch).
    assert report.fixes, "expected an offline validated quick-fix for yaml.load (CWE-502); got none"
    assert any(fix.cwe == "CWE-502" for fix in report.fixes)
    assert all(fix.provenance.value == "deterministic" for fix in report.fixes)
