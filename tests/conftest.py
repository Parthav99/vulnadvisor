"""Shared test fixtures: an offline advisory matcher backed by recorded API fixtures."""

from collections.abc import Callable
from pathlib import Path

import pytest

from vulnadvisor.advisories import (
    AdvisoryMatcher,
    EpssClient,
    KevClient,
    OSVClient,
    TransportError,
)
from vulnadvisor.engine.scoring import score_match
from vulnadvisor.model import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
    ScoredFinding,
)
from vulnadvisor.store import SqliteCache

_FIX = Path(__file__).resolve().parent.parent / "fixtures" / "api"
_OSV = (_FIX / "osv_jinja2.json").read_bytes()
_EPSS = (_FIX / "epss.json").read_bytes()
_KEV = (_FIX / "kev.json").read_bytes()


class RecordingTransport:
    """Serves recorded API fixtures by host and can simulate per-source outages."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.fail = fail or set()
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, *, body=None, headers=None):
        self.calls.append((method, url))
        if "api.osv.dev" in url:
            if "OSV" in self.fail:
                raise TransportError("osv down")
            return _OSV
        if "first.org" in url:
            if "EPSS" in self.fail:
                raise TransportError("epss down")
            return _EPSS
        if "cisa.gov" in url:
            if "KEV" in self.fail:
                raise TransportError("kev down")
            return _KEV
        raise TransportError(f"no route for {url}")


@pytest.fixture
def fake_matcher() -> Callable[..., AdvisoryMatcher]:
    """Return a factory that builds an offline ``AdvisoryMatcher`` over recorded fixtures."""

    def make(fail: set[str] | None = None) -> AdvisoryMatcher:
        cache = SqliteCache()
        transport = RecordingTransport(fail=fail)
        return AdvisoryMatcher(
            OSVClient(transport, cache),
            EpssClient(transport, cache),
            KevClient(transport, cache),
        )

    return make


@pytest.fixture
def sample_findings() -> list[ScoredFinding]:
    """Two deterministic scored findings (CRITICAL jinja2, LOW flask) in priority order."""
    jinja = MatchedAdvisory(
        dependency=Dependency(
            name="jinja2",
            raw_name="Jinja2",
            version="2.10",
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id="GHSA-462w-v97r-4m45",
            aliases=("CVE-2019-10906",),
            summary="Jinja2 sandbox escape via str.format_map.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            affected=(
                AffectedPackage(
                    name="jinja2",
                    ranges=(AffectedRange(introduced="0", fixed="2.10.1"),),
                ),
            ),
        ),
        epss=EpssScore(cve="CVE-2019-10906", probability=0.945, percentile=0.991),
        in_kev=True,
    )
    flask = MatchedAdvisory(
        dependency=Dependency(
            name="flask",
            raw_name="Flask",
            version="0.12",
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id="GHSA-flask-dos0",
            aliases=("CVE-2018-1000656",),
            summary="Flask denial of service via crafted JSON.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            affected=(
                AffectedPackage(
                    name="flask",
                    ranges=(AffectedRange(introduced="0", fixed="0.12.3"),),
                ),
            ),
        ),
        epss=EpssScore(cve="CVE-2018-1000656", probability=0.02, percentile=0.40),
        in_kev=False,
    )
    return [score_match(jinja), score_match(flask)]
