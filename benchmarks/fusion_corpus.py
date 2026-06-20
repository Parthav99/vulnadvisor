"""Run the fusion benchmark over the seeded SAST corpus (Task 21.4).

The deprioritization number must be **reproducible by a stranger** (the gate), so it cannot depend
on whether Semgrep happens to be installed. We therefore *model* the external scanner from the same
ground-truth corpus the SAST benchmark uses: a pattern scanner with no reachability model fires on
**every** sink site — the real ``vuln`` flows, the ``safe`` (sanitized/literal) sinks, and the
``possible`` (entry-point-unreachable) orphans alike — which is exactly Semgrep's behavior on
Python, where it has no taint model. We synthesize one external finding per seeded sink, fuse it
onto the *real* native taint-engine output through the real :func:`fuse_findings`, and measure how
many our reachability moves off the top tier.

This is honest about its modeling: the external findings are synthetic (so the number is hermetic
and reproducible), but the *overlay that re-tiers them is the production engine* — the same code a
real ``scan --with-semgrep`` runs. When Semgrep is installed, that overlay applies identically to
its real output; here we measure the overlay's effect on the broad-firing pattern set it represents.
"""

import tempfile
from collections.abc import Sequence
from pathlib import Path

from benchmarks.fusion_metrics import FusionMetrics, compute_fusion_metrics
from benchmarks.sast_corpus import CORPUS, SastCase
from benchmarks.sast_metrics import parse_seeds
from vulnadvisor.sast.external.base import cwe_kind_title
from vulnadvisor.sast.external.fusion import fuse_findings
from vulnadvisor.sast.external.semgrep import SEMGREP_TOOL
from vulnadvisor.sast.model import SastFinding, SastTier
from vulnadvisor.sast.taint import analyze_taint

__all__ = ["model_external_findings", "run_fusion_corpus"]


def model_external_findings(rel: str, source: str) -> list[SastFinding]:
    """Synthesize the pattern-scanner findings for one corpus file from its ``# seed:`` markers.

    One pre-overlay finding per seeded sink site (every site — a pattern scanner has no reachability
    model to skip the safe/orphan ones), at the ``DYNAMIC_UNKNOWN`` floor with ``flow=None`` and
    Semgrep's provenance — exactly the shape :meth:`SemgrepAdapter.normalize` produces, so they fuse
    through the production overlay identically.
    """
    findings: list[SastFinding] = []
    for seed in parse_seeds("modeled", rel, source):
        kind, title = cwe_kind_title(seed.cwe, fallback_title=seed.note or seed.cwe)
        findings.append(
            SastFinding(
                cwe=seed.cwe,
                kind=kind,
                title=title,
                file=rel,
                line=seed.line,
                col=0,
                callee="<modeled-semgrep-rule>",
                tier=SastTier.DYNAMIC_UNKNOWN,
                reason="Modeled pattern-scanner hit (fusion benchmark).",
                source_kind=None,
                flow=None,
                provenance=(SEMGREP_TOOL,),
            )
        )
    return findings


def run_fusion_corpus(corpus: Sequence[SastCase] = CORPUS) -> FusionMetrics:
    """Fuse a modeled pattern scanner onto the real native engine over the corpus; return metrics.

    Each case runs in its own temp dir (isolation preserves ground truth, as in the SAST corpus):
    the native taint engine analyzes the real source, the modeled external findings are fused onto
    it, and the per-case external/fused pairs are accumulated into one :class:`FusionMetrics`.
    """
    all_external: list[SastFinding] = []
    all_fused: list[SastFinding] = []
    for case in corpus:
        with tempfile.TemporaryDirectory(prefix=f"vulnadvisor-fusion-bench-{case.name}-") as tmp:
            root = Path(tmp)
            external: list[SastFinding] = []
            for rel, source in case.files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
                external.extend(model_external_findings(rel, source))
            native = analyze_taint(root)
            fused = fuse_findings(native, external)
            all_external.extend(external)
            all_fused.extend(fused)
    return compute_fusion_metrics(all_external, all_fused)
