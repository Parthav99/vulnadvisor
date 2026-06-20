"""Pure metrics for the fusion benchmark — how much of a pattern scanner's output we deprioritize.

This is M21's headline, measured (``docs/fusion-design.md`` §11, Task 21.4). Semgrep (and friends)
emit a flat list of pattern matches with no Python-deep reachability model, so on Python — where
they are *weak* — they raise their loudest alarm on sanitized and entry-point-unreachable sinks
alike. We fuse that raw list through our reachability overlay and re-tier it. This module measures,
deterministically, what fraction of an external scanner's findings our overlay moves **off** the
top ``CONFIRMED-FLOW`` tier (deprioritized) versus keeps actionable — our honest, Python-measured
answer to Semgrep's own "up to 98% fewer critical false positives" claim.

Pure and total: it folds over an external finding list and the fused result, with no I/O and no
clock, so the same inputs always yield the same numbers (the reproducibility the gate requires).
The release-blocking soundness invariant (§4.1, *no external finding silently lost*) is checked
here too: :attr:`FusionMetrics.represented` must be ``True``.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from vulnadvisor.sast.external.fusion import LINE_TOLERANCE
from vulnadvisor.sast.model import SastFinding, SastTier

__all__ = ["FusionMetrics", "compute_fusion_metrics"]

#: The one tier that is "actionable, top concern". Anything else is a deprioritization of the
#: external tool's alarm (it flagged the sink; we proved it sanitized / unreachable / dynamic).
_ACTIONABLE_TIER = SastTier.CONFIRMED_FLOW


@dataclass(frozen=True)
class FusionMetrics:
    """Aggregate of how an external scanner's findings land after our reachability overlay."""

    external_total: int
    by_tier: dict[str, int] = field(default_factory=dict)
    represented: bool = True

    @property
    def actionable(self) -> int:
        """External findings our overlay kept at the top ``CONFIRMED-FLOW`` tier."""
        return self.by_tier.get(_ACTIONABLE_TIER.value, 0)

    @property
    def deprioritized(self) -> int:
        """External findings our reachability moved off the top tier (the noise-reduction story)."""
        return self.external_total - self.actionable

    @property
    def deprioritized_pct(self) -> float:
        """Percentage of the external tool's output our reachability deprioritized."""
        if self.external_total == 0:
            return 0.0
        return 100.0 * self.deprioritized / self.external_total


def _represents(record: SastFinding, ext: SastFinding, tool: str) -> bool:
    """Whether ``record`` is the fused record that represents ``ext`` (its tool, same location).

    Mirrors the fusion merge key (``sast/external/fusion.py``): same file + CWE, line within the ±1
    tolerance, and the external tool present in the record's provenance (so a corroborated survivor
    or an escalated own-record both count).
    """
    return (
        tool in record.provenance
        and record.file == ext.file
        and record.cwe == ext.cwe
        and abs(record.line - ext.line) <= LINE_TOLERANCE
    )


def compute_fusion_metrics(
    external: Sequence[SastFinding], fused: Sequence[SastFinding]
) -> FusionMetrics:
    """Bucket each external finding by the tier its representing fused record carries.

    For every external finding we locate the fused record that represents it (same location, our
    overlay's tool-in-provenance rule) and tally that record's tier. An external finding with no
    representative breaks the no-loss invariant — recorded in :attr:`FusionMetrics.represented` so
    the gate fails loudly rather than quietly under-counting.
    """
    by_tier: dict[str, int] = {tier.value: 0 for tier in SastTier}
    represented = True
    for ext in external:
        tool = ext.provenance[0] if ext.provenance else ""
        match = next((rec for rec in fused if _represents(rec, ext, tool)), None)
        if match is None:
            represented = False
            continue
        by_tier[match.tier.value] += 1
    return FusionMetrics(
        external_total=len(external),
        by_tier=by_tier,
        represented=represented,
    )
