import pytest

from vulnadvisor.engine import (
    advisory_severity,
    compute_score,
    cvss_base_score,
    score_matches,
)
from vulnadvisor.model import (
    Advisory,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
    PriorityBand,
)

# --- CVSS base-score computation --------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_score(vector: str, expected: float) -> None:
    assert cvss_base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "not-a-vector",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",  # v2 unsupported
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v4 unsupported
        "CVSS:3.1/AV:N/AC:L",  # missing metrics
    ],
)
def test_cvss_unsupported_returns_none(vector: str | None) -> None:
    assert cvss_base_score(vector) is None


# --- determinism (property) -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cvss", "epss", "kev"),
    [
        (9.8, 0.9, False),
        (5.0, None, True),
        (None, 0.5, False),
        (2.1, 0.01, False),
        (None, None, False),
    ],
)
def test_score_is_deterministic(cvss: float | None, epss: float | None, kev: bool) -> None:
    first = compute_score(cvss_base=cvss, epss_probability=epss, in_kev=kev)
    second = compute_score(cvss_base=cvss, epss_probability=epss, in_kev=kev)
    assert first == second
    assert first.value == second.value


# --- boundary table ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cvss", "epss", "kev", "expected_band"),
    [
        # KEV always forces CRITICAL, even with trivial severity / EPSS.
        (1.0, 0.0, True, PriorityBand.CRITICAL),
        (None, None, True, PriorityBand.CRITICAL),
        # EPSS high + high severity -> CRITICAL.
        (9.8, 0.9, False, PriorityBand.CRITICAL),
        # High severity but ~zero EPSS -> deprioritized (the noise-reduction thesis).
        (9.8, 0.01, False, PriorityBand.LOW),
        # No CVSS, EPSS unknown -> moderate default severity, not zero.
        (None, None, False, PriorityBand.MEDIUM),
        # No CVSS but very high EPSS -> HIGH.
        (None, 0.99, False, PriorityBand.HIGH),
        # Low severity, zero EPSS -> INFO.
        (2.0, 0.0, False, PriorityBand.INFO),
    ],
)
def test_score_bands(
    cvss: float | None, epss: float | None, kev: bool, expected_band: PriorityBand
) -> None:
    score = compute_score(cvss_base=cvss, epss_probability=epss, in_kev=kev)
    assert score.band is expected_band
    assert 0.0 <= score.value <= 100.0


def test_kev_floor_value() -> None:
    score = compute_score(cvss_base=1.0, epss_probability=0.0, in_kev=True)
    assert score.value >= 90.0
    assert score.verdict == "Fix now"


def test_unknown_cvss_flagged_and_defaulted() -> None:
    score = compute_score(cvss_base=None, epss_probability=None, in_kev=False)
    assert score.cvss_known is False
    assert score.cvss_used == 5.0
    assert "CVSS unknown" in score.rationale


def test_unknown_epss_does_not_zero_out_severity() -> None:
    # CVSS 9.8 with unknown EPSS must remain high, not collapse to near-zero.
    score = compute_score(cvss_base=9.8, epss_probability=None, in_kev=False)
    assert score.band is PriorityBand.CRITICAL


# --- advisory_severity + sorting --------------------------------------------------------------


def test_advisory_severity_from_vector() -> None:
    advisory = Advisory(id="GHSA-x", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    base, used = advisory_severity(advisory)
    assert base == 8.8
    assert used == 8.8


def test_advisory_severity_unknown_defaults() -> None:
    base, used = advisory_severity(Advisory(id="GHSA-y"))
    assert base is None
    assert used == 5.0


def _match(advisory_id: str, *, cvss: str | None, epss: float | None, kev: bool) -> MatchedAdvisory:
    dep = Dependency(name="pkg", version="1.0", source=DependencySource.REQUIREMENTS_TXT)
    advisory = Advisory(id=advisory_id, cvss_vector=cvss)
    epss_score = EpssScore(cve="CVE-0000-0000", probability=epss, percentile=0.5) if epss else None
    return MatchedAdvisory(dependency=dep, advisory=advisory, epss=epss_score, in_kev=kev)


def test_score_matches_sorted_descending_and_deterministic() -> None:
    matches = [
        _match(
            "GHSA-low", cvss="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", epss=0.01, kev=False
        ),
        _match("GHSA-kev", cvss=None, epss=None, kev=True),
        _match(
            "GHSA-high", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", epss=0.9, kev=False
        ),
    ]
    first = score_matches(matches)
    values = [f.score.value for f in first]
    assert values == sorted(values, reverse=True)
    # High severity + high EPSS (93.2) outranks the KEV floor (90.0); both beat the low finding.
    assert [f.matched.advisory.id for f in first] == ["GHSA-high", "GHSA-kev", "GHSA-low"]
    # Re-running on a reordered input yields the identical ordering (deterministic).
    second = score_matches(list(reversed(matches)))
    assert [f.matched.advisory.id for f in first] == [f.matched.advisory.id for f in second]
