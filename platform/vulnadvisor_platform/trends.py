"""Sound categorization of findings for the repo trend.

The only confidently-safe tier is ``not-imported`` (the engine's single deprioritized tier).
Everything else — ``imported-and-called``, ``imported``, ``dynamic-unknown``, and any unrecognized
or ``unknown`` tier from an older/partial report — counts as **actionable**. This mirrors the
engine's soundness rule: never treat a finding we cannot prove safe as deprioritized.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from vulnadvisor.model.reachability import ReachabilityTier

_DEPRIORITIZED_TIER = ReachabilityTier.NOT_IMPORTED.value
_REACHABLE_CALLED_TIER = ReachabilityTier.IMPORTED_AND_CALLED.value


@dataclass(frozen=True)
class TierTotals:
    """Aggregated counts for one trend point."""

    actionable: int
    deprioritized: int
    reachable_called: int


def summarize_tiers(tier_counts: Mapping[str, int]) -> TierTotals:
    """Fold per-tier counts into actionable / deprioritized / reachable-called totals."""
    actionable = 0
    deprioritized = 0
    reachable_called = 0
    for tier, count in tier_counts.items():
        if tier == _DEPRIORITIZED_TIER:
            deprioritized += count
        else:
            actionable += count
        if tier == _REACHABLE_CALLED_TIER:
            reachable_called += count
    return TierTotals(
        actionable=actionable,
        deprioritized=deprioritized,
        reachable_called=reachable_called,
    )
