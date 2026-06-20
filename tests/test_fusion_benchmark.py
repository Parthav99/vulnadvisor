"""Task 21.4 — the fusion benchmark: reachability deprioritizes a pattern scanner's noise.

Pure-metric tests plus one end-to-end corpus run asserting the headline reproduces, the no-loss
invariant holds (every external finding represented), and our reachability actually moves the
sanitized/orphan sinks off the top tier — the measured answer to Semgrep's "up to 98%" claim.
"""

from benchmarks.fusion_corpus import model_external_findings, run_fusion_corpus
from benchmarks.fusion_metrics import compute_fusion_metrics
from benchmarks.sast_metrics import build_sast_report
from benchmarks.sast_report import render_sast_markdown

from vulnadvisor.sast.external.fusion import fuse_findings
from vulnadvisor.sast.external.semgrep import SEMGREP_TOOL
from vulnadvisor.sast.model import NATIVE_PROVENANCE, SastFinding, SastTier


def _native(tier: SastTier, *, line: int = 10) -> SastFinding:
    return SastFinding(
        cwe="CWE-89",
        kind="sql-injection",
        title="SQL injection",
        file="app.py",
        line=line,
        col=0,
        callee="cursor.execute",
        tier=tier,
        reason="native",
        provenance=(NATIVE_PROVENANCE,),
    )


def _external(*, line: int = 10, cwe: str = "CWE-89") -> SastFinding:
    return SastFinding(
        cwe=cwe,
        kind="sql-injection",
        title="SQL injection",
        file="app.py",
        line=line,
        col=0,
        callee="modeled.rule",
        tier=SastTier.DYNAMIC_UNKNOWN,
        reason="modeled",
        provenance=(SEMGREP_TOOL,),
    )


def test_metrics_count_actionable_vs_deprioritized() -> None:
    # Three external findings: one corroborates a CONFIRMED native (actionable), one a SANITIZED
    # native (deprioritized), one un-overlayable (escalates to DYNAMIC-UNKNOWN — off the top tier).
    native = [_native(SastTier.CONFIRMED_FLOW, line=10), _native(SastTier.SANITIZED, line=20)]
    external = [_external(line=10), _external(line=20), _external(line=30, cwe="CWE-1004")]
    fused = fuse_findings(native, external)

    metrics = compute_fusion_metrics(external, fused)
    assert metrics.represented is True
    assert metrics.external_total == 3
    assert metrics.actionable == 1
    assert metrics.deprioritized == 2
    assert round(metrics.deprioritized_pct) == 67


def test_metrics_flag_a_lost_external_finding() -> None:
    # An external finding with no representative in the fused list breaks the no-loss invariant.
    external = [_external(line=10)]
    metrics = compute_fusion_metrics(external, fused=[])  # nothing represents it
    assert metrics.represented is False


def test_model_external_findings_one_per_seed() -> None:
    source = (
        "import os\n"
        "def f(x):\n"
        '    os.system(x)  # seed: CWE-78 vuln note="a"\n'
        "    os.system('ok')  # seed: CWE-78 safe note=\"b\"\n"
    )
    modeled = model_external_findings("app.py", source)
    assert len(modeled) == 2
    assert all(f.provenance == (SEMGREP_TOOL,) for f in modeled)
    assert all(f.tier is SastTier.DYNAMIC_UNKNOWN for f in modeled)  # pre-overlay floor


def test_corpus_run_is_deterministic_and_loses_nothing() -> None:
    first = run_fusion_corpus()
    second = run_fusion_corpus()
    assert first.represented is True  # release-blocking: no external finding silently lost
    assert first.external_total > 0
    assert first.deprioritized > 0  # reachability actually quiets the sanitized/orphan sinks
    # Deterministic: the same corpus yields byte-identical metrics (the gate's reproducibility).
    assert first == second


def test_report_includes_fusion_section() -> None:
    external = [_external(line=10)]
    fused = fuse_findings([_native(SastTier.SANITIZED, line=10)], external)
    metrics = compute_fusion_metrics(external, fused)

    empty_sast = build_sast_report([], [], bandit_available=False)
    markdown = render_sast_markdown(empty_sast, fusion=metrics)
    assert "Multi-tool fusion (M21)" in markdown
    assert "deprioritizes" in markdown
    assert "No-loss invariant" in markdown
    assert "**PASS**" in markdown  # the self-consistent fuse loses nothing
