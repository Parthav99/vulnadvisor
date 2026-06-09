from benchmarks.corpus import CORPUS, run_corpus
from benchmarks.metrics import AdvisoryOutcome, RepoResult, build_report, is_actionable
from benchmarks.report import render_markdown

from vulnadvisor.model.reachability import ReachabilityTier

NI = ReachabilityTier.NOT_IMPORTED
IMP = ReachabilityTier.IMPORTED
CALLED = ReachabilityTier.IMPORTED_AND_CALLED
DYN = ReachabilityTier.DYNAMIC_UNKNOWN


def _outcome(
    tier: ReachabilityTier, *, critical: bool = False, truth: bool | None = None
) -> AdvisoryOutcome:
    return AdvisoryOutcome(
        advisory_id="X", package="p", tier=tier, is_critical=critical, reachable_truth=truth
    )


# --- pure metrics --------------------------------------------------------------------------------


def test_only_not_imported_is_deprioritized() -> None:
    assert is_actionable(CALLED)
    assert is_actionable(IMP)
    assert is_actionable(DYN)
    assert not is_actionable(NI)


def test_repo_result_counts_and_noise_reduction() -> None:
    row = RepoResult(
        "r",
        "c",
        (
            _outcome(CALLED, truth=True),
            _outcome(IMP, truth=True),
            _outcome(NI, truth=False),
            _outcome(NI, truth=False),
        ),
    )
    assert row.baseline_total == 4
    assert row.deprioritized == 2
    assert row.actionable == 2
    assert row.reachable_called == 1
    assert row.noise_reduction_pct == 50.0
    assert row.false_negatives == 0
    assert row.missed_criticals == 0


def test_false_negative_is_reachable_but_deprioritized() -> None:
    row = RepoResult("r", "c", (_outcome(NI, critical=True, truth=True),))
    assert row.false_negatives == 1
    assert row.missed_criticals == 1


def test_unknown_truth_excluded_from_false_negatives() -> None:
    # Live repos leave reachable_truth=None; a NOT_IMPORTED there is not a false negative.
    row = RepoResult("r", "c", (_outcome(NI, critical=True, truth=None),))
    assert row.false_negatives == 0
    assert row.missed_criticals == 0


def test_report_aggregates_and_orders() -> None:
    a = RepoResult("zeta", "c", (_outcome(NI, truth=False), _outcome(CALLED, truth=True)))
    b = RepoResult("alpha", "c", (_outcome(IMP, truth=True),))
    report = build_report([a, b])
    assert [r.repo for r in report.rows] == ["alpha", "zeta"]  # deterministic ordering
    assert report.baseline_total == 3
    assert report.deprioritized == 1
    assert report.noise_reduction_pct == 100.0 * 1 / 3


def test_empty_report_has_zero_noise_reduction() -> None:
    assert build_report([]).noise_reduction_pct == 0.0


# --- end-to-end hermetic corpus (the validation gate) --------------------------------------------


def test_corpus_runs_end_to_end_over_at_least_ten_repos() -> None:
    report = run_corpus()
    assert report.repo_count >= 10
    assert report.baseline_total > 0


def test_corpus_reduces_noise_with_zero_missed_criticals() -> None:
    report = run_corpus()
    assert report.actionable < report.baseline_total  # triage removed noise
    assert report.noise_reduction_pct > 0
    # Release-blocking: no reachable finding (critical or otherwise) was reported as safe.
    assert report.missed_criticals == 0
    assert report.false_negatives == 0


def test_corpus_labels_match_engine_verdicts() -> None:
    # Every labeled-reachable advisory must survive triage; every unused one must be deprioritized.
    report = run_corpus()
    for row in report.rows:
        for outcome in row.outcomes:
            if outcome.reachable_truth:
                assert is_actionable(outcome.tier), f"{row.repo}/{outcome.advisory_id} dropped"
            else:
                assert outcome.tier is NI, f"{row.repo}/{outcome.advisory_id} not deprioritized"


def test_corpus_has_reachable_called_findings() -> None:
    # The corpus must contain genuinely called vulns, not only easy deprioritizations.
    assert run_corpus().reachable_called >= 5


def test_render_markdown_contains_headline_and_gate() -> None:
    report = run_corpus()
    md = render_markdown(report, title="T", mode="hermetic")
    assert "% less noise" in md
    assert "Soundness gate: **PASS**" in md
    assert "| **Total** |" in md
    assert md.isascii()  # portable / Windows-safe


def test_corpus_repo_names_are_unique() -> None:
    names = [repo.name for repo in CORPUS]
    assert len(names) == len(set(names))
