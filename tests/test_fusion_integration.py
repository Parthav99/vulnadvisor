"""Task 21.4 — fusion output / CLI / provenance integration.

The 21.3 overlay is wired end-to-end here: an external adapter's findings reach the pipeline, fuse
onto the native taint engine, and surface their provenance in every output surface (JSON, SARIF,
the terminal 3-card) and the provenance display helper — honestly ("found by Semgrep OSS · ranked
by VulnAdvisor reachability") and without ever displacing our deterministic rank or losing a
finding.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from jsonschema.protocols import Validator

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.cli.render import render_to_string
from vulnadvisor.engine.sast_scoring import score_sast_finding
from vulnadvisor.output.json_report import build_report
from vulnadvisor.output.sarif import build_sarif
from vulnadvisor.sast.external.base import ExternalScanResult
from vulnadvisor.sast.external.provenance import provenance_line
from vulnadvisor.sast.external.semgrep import SEMGREP_TOOL
from vulnadvisor.sast.model import NATIVE_PROVENANCE, SastFinding, SastTier, ScoredSastFinding

_ROOT = Path(__file__).resolve().parent.parent
SARIF_SCHEMA = _ROOT / "fixtures" / "schemas" / "sarif-2.1.0.json"


def _scored(provenance: tuple[str, ...]) -> ScoredSastFinding:
    """A scored CWE-78 SAST finding carrying ``provenance`` (default native)."""
    finding = SastFinding(
        cwe="CWE-78",
        kind="command-injection",
        title="OS command injection",
        file="app/run.py",
        line=12,
        col=4,
        callee="os.system",
        tier=SastTier.CONFIRMED_FLOW,
        reason="a tainted value reaches this sink with no sanitizer",
        provenance=provenance,
    )
    return score_sast_finding(finding)


# --- provenance display helper --------------------------------------------------------------------


def test_provenance_line_only_for_external_corroboration() -> None:
    # Native-only: no line (we found and ranked it — the default).
    assert provenance_line((NATIVE_PROVENANCE,)) is None
    assert provenance_line(()) is None
    # Corroborated: every detector credited, ranking always ours.
    assert (
        provenance_line((NATIVE_PROVENANCE, SEMGREP_TOOL))
        == "Found by VulnAdvisor + Semgrep OSS · ranked by VulnAdvisor reachability"
    )
    # External-only (un-overlayable, escalated): still credited, never reads as ours-only.
    assert (
        provenance_line((SEMGREP_TOOL,))
        == "Found by Semgrep OSS · ranked by VulnAdvisor reachability"
    )


# --- JSON: additive provenance on the code finding (schema stays 1.2) -----------------------------


def test_json_code_finding_carries_native_provenance() -> None:
    report = build_report(
        [], (), tool_version="2.3.0", sast_findings=[_scored((NATIVE_PROVENANCE,))]
    )
    assert report["schema_version"] == "1.2"  # additive, no bump (fusion-design §12.2)
    assert report["findings"][0]["provenance"] == ["vulnadvisor"]


def test_json_code_finding_carries_fused_provenance() -> None:
    report = build_report(
        [], (), tool_version="2.3.0", sast_findings=[_scored((NATIVE_PROVENANCE, SEMGREP_TOOL))]
    )
    assert report["findings"][0]["provenance"] == ["vulnadvisor", "semgrep-oss"]


# --- SARIF: result properties + the external tool component, still schema-valid ------------------


def test_sarif_surfaces_provenance_and_external_tool_component() -> None:
    log = build_sarif(
        [], (), tool_version="2.3.0", sast_findings=[_scored((NATIVE_PROVENANCE, SEMGREP_TOOL))]
    )

    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    validator: Validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(log), key=lambda e: list(e.path))
    assert errors == [], "\n".join(f"{list(e.path)}: {e.message}" for e in errors)

    run = log["runs"][0]
    result = run["results"][0]
    assert result["properties"]["provenance"] == ["vulnadvisor", "semgrep-oss"]
    # The fused tool is declared as a SARIF tool extension (toolComponent).
    extensions = run["tool"]["extensions"]
    assert any(component["name"] == SEMGREP_TOOL for component in extensions)


def test_sarif_native_only_declares_no_external_extensions() -> None:
    log = build_sarif([], (), tool_version="2.3.0", sast_findings=[_scored((NATIVE_PROVENANCE,))])
    # No external scanner contributed → no `extensions` key at all (clean default SARIF).
    assert "extensions" not in log["runs"][0]["tool"]


# --- terminal 3-card: the provenance line renders for a fused finding -----------------------------


def test_terminal_renders_provenance_line_for_fused_finding() -> None:
    fused = render_to_string([], sast_findings=[_scored((NATIVE_PROVENANCE, SEMGREP_TOOL))])
    assert "Found by VulnAdvisor + Semgrep OSS" in fused
    assert "ranked by VulnAdvisor reachability" in fused


def test_terminal_omits_provenance_line_for_native_finding() -> None:
    native = render_to_string([], sast_findings=[_scored((NATIVE_PROVENANCE,))])
    assert "Found by" not in native


# --- pipeline wiring: an external adapter's findings fuse + degrade, native-only unchanged --------


class _FakeAdapter:
    """A minimal external adapter (ExternalToolAdapter-shaped) for the pipeline test.

    ``scan`` is the only method the pipeline calls; it returns a fixed external finding plus a
    degraded reason so we can assert both fusion and degraded-source propagation without Semgrep.
    """

    name = SEMGREP_TOOL

    def __init__(self, findings: tuple[SastFinding, ...], degraded: tuple[str, ...]) -> None:
        self._findings = findings
        self._degraded = degraded

    def scan(self, target: Path) -> ExternalScanResult:
        return ExternalScanResult(
            tool=self.name, ran=True, findings=self._findings, degraded=self._degraded
        )


def _vulnerable_project(root: Path) -> None:
    """Write a tiny Flask app whose request param flows into ``os.system`` (a native CONFIRMED)."""
    (root / "app.py").write_text(
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    os.system('ping ' + host)\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )


def test_pipeline_fuses_external_and_carries_degraded(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    _vulnerable_project(tmp_path)
    # An un-overlayable external finding (a CWE/location our engine produced nothing for): it must
    # survive in the fused list with its provenance, never be dropped.
    external = SastFinding(
        cwe="CWE-1004",
        kind="external-finding",
        title="Sensitive cookie without HttpOnly",
        file="app.py",
        line=99,
        col=0,
        callee="python.flask.security.cookie",
        tier=SastTier.DYNAMIC_UNKNOWN,
        reason="Located by Semgrep OSS; overlay pending.",
        provenance=(SEMGREP_TOOL,),
    )
    adapter = _FakeAdapter((external,), (f"{SEMGREP_TOOL}: 1 tool error(s) during scan",))

    report = scan_project(
        tmp_path, fake_matcher(), run_sca=False, run_sast=True, external=[adapter]
    )

    provenances = [f.finding.provenance for f in report.sast_findings]
    assert (SEMGREP_TOOL,) in provenances  # the external finding survived, with its provenance
    assert any("tool error" in reason for reason in report.degraded_sources)


def test_pipeline_native_only_when_no_external(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    _vulnerable_project(tmp_path)
    report = scan_project(tmp_path, fake_matcher(), run_sca=False, run_sast=True)
    # Every finding is native; no degraded reasons from a missing external scanner.
    assert report.sast_findings  # the native CONFIRMED flow is found
    assert all(f.finding.provenance == (NATIVE_PROVENANCE,) for f in report.sast_findings)
    assert report.degraded_sources == ()


# --- CLI flag resolution --------------------------------------------------------------------------


def test_cli_resolves_external_selectors_to_adapters() -> None:
    from vulnadvisor.cli.main import ExternalScanner, _resolve_external_adapters

    assert _resolve_external_adapters(ExternalScanner.NONE, False, None) == []
    assert len(_resolve_external_adapters(ExternalScanner.SEMGREP, False, None)) == 1
    assert len(_resolve_external_adapters(ExternalScanner.NONE, True, None)) == 1  # --with-semgrep


@pytest.mark.parametrize("config", [None, "auto"])
def test_cli_semgrep_config_override(config: str | None) -> None:
    from vulnadvisor.cli.main import build_semgrep_adapter

    adapter = build_semgrep_adapter(config)
    assert adapter.name == SEMGREP_TOOL
