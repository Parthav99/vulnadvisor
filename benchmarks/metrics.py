"""Pure metric models for the benchmark — no I/O, no engine, fully unit-testable.

An :class:`AdvisoryOutcome` records, per advisory, the tier VulnAdvisor assigned and (when known)
whether it is genuinely reachable. From a repo's outcomes we derive the headline numbers: how many
of the naive scanner's findings VulnAdvisor deprioritizes (noise reduction) and — the
release-blocking check — whether any *reachable* finding was wrongly deprioritized (false negative).
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from vulnadvisor.model.reachability import ReachabilityTier

__all__ = [
    "AdvisoryOutcome",
    "BenchmarkReport",
    "RepoResult",
    "is_actionable",
]

# Everything except NOT_IMPORTED is something a developer should still look at. NOT_IMPORTED is the
# only "confidently safe" tier, so it is the only one we count as removed noise.
_DEPRIORITIZED = ReachabilityTier.NOT_IMPORTED


def is_actionable(tier: ReachabilityTier) -> bool:
    """Whether a finding at ``tier`` survives triage (i.e. is not confidently safe)."""
    return tier is not _DEPRIORITIZED


@dataclass(frozen=True)
class AdvisoryOutcome:
    """One advisory's fate under VulnAdvisor triage.

    ``reachable_truth`` is the ground truth where known (the synthetic corpus labels it); ``None``
    means unknown (live repos, where we cannot label every advisory) and is excluded from the
    false-negative tally.
    """

    advisory_id: str
    package: str
    tier: ReachabilityTier
    is_critical: bool = False
    reachable_truth: bool | None = None

    @property
    def deprioritized(self) -> bool:
        """Whether triage moved this advisory to the confidently-safe tier."""
        return not is_actionable(self.tier)

    @property
    def is_false_negative(self) -> bool:
        """A known-reachable advisory that triage wrongly deprioritized (release-blocking)."""
        return self.reachable_truth is True and self.deprioritized


@dataclass(frozen=True)
class RepoResult:
    """The triage outcomes for one repository."""

    repo: str
    commit: str
    outcomes: tuple[AdvisoryOutcome, ...]

    @property
    def baseline_total(self) -> int:
        """Findings the naive scanner reports (every advisory, untriaged)."""
        return len(self.outcomes)

    @property
    def deprioritized(self) -> int:
        """Findings VulnAdvisor moved to NOT_IMPORTED (removed noise)."""
        return sum(1 for o in self.outcomes if o.deprioritized)

    @property
    def actionable(self) -> int:
        """Findings that survive triage."""
        return self.baseline_total - self.deprioritized

    @property
    def reachable_called(self) -> int:
        """Findings with a concrete call path to the vulnerable symbol (highest concern)."""
        return sum(1 for o in self.outcomes if o.tier is ReachabilityTier.IMPORTED_AND_CALLED)

    @property
    def false_negatives(self) -> int:
        """Known-reachable findings wrongly deprioritized (must be zero)."""
        return sum(1 for o in self.outcomes if o.is_false_negative)

    @property
    def missed_criticals(self) -> int:
        """The subset of false negatives that are critical (the release-blocking headline)."""
        return sum(1 for o in self.outcomes if o.is_false_negative and o.is_critical)

    @property
    def noise_reduction_pct(self) -> float:
        """Percentage of the naive scanner's findings VulnAdvisor deprioritized."""
        if self.baseline_total == 0:
            return 0.0
        return 100.0 * self.deprioritized / self.baseline_total


@dataclass(frozen=True)
class BenchmarkReport:
    """Aggregated results across all benchmarked repositories."""

    rows: tuple[RepoResult, ...]

    @property
    def baseline_total(self) -> int:
        """Total naive-scanner findings across all repos."""
        return sum(r.baseline_total for r in self.rows)

    @property
    def actionable(self) -> int:
        """Total findings surviving triage across all repos."""
        return sum(r.actionable for r in self.rows)

    @property
    def deprioritized(self) -> int:
        """Total findings deprioritized across all repos."""
        return sum(r.deprioritized for r in self.rows)

    @property
    def reachable_called(self) -> int:
        """Total IMPORTED_AND_CALLED findings across all repos."""
        return sum(r.reachable_called for r in self.rows)

    @property
    def false_negatives(self) -> int:
        """Total known-reachable findings wrongly deprioritized (must be zero)."""
        return sum(r.false_negatives for r in self.rows)

    @property
    def missed_criticals(self) -> int:
        """Total missed reachable criticals (the release-blocking number — must be zero)."""
        return sum(r.missed_criticals for r in self.rows)

    @property
    def noise_reduction_pct(self) -> float:
        """Overall percentage of naive findings deprioritized."""
        if self.baseline_total == 0:
            return 0.0
        return 100.0 * self.deprioritized / self.baseline_total

    @property
    def repo_count(self) -> int:
        """Number of repositories benchmarked."""
        return len(self.rows)


def build_report(rows: Iterable[RepoResult]) -> BenchmarkReport:
    """Assemble a :class:`BenchmarkReport` from per-repo results (deterministically ordered)."""
    ordered: Sequence[RepoResult] = sorted(rows, key=lambda r: r.repo)
    return BenchmarkReport(tuple(ordered))
