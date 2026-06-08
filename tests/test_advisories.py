from pathlib import Path

import pytest

from vulnadvisor.advisories import (
    AdvisoryMatcher,
    EpssClient,
    KevClient,
    OSVClient,
    TransportError,
)
from vulnadvisor.model import Dependency, DependencySource
from vulnadvisor.store import SqliteCache

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "api"
OSV_BYTES = (FIX / "osv_jinja2.json").read_bytes()
EPSS_BYTES = (FIX / "epss.json").read_bytes()
KEV_BYTES = (FIX / "kev.json").read_bytes()


class FakeTransport:
    """Routes requests to recorded fixtures by host, counts calls, can simulate outages."""

    def __init__(
        self,
        *,
        osv: bytes = b"{}",
        epss: bytes = b"{}",
        kev: bytes = b"{}",
        fail: set[str] | None = None,
    ) -> None:
        self.osv = osv
        self.epss = epss
        self.kev = kev
        self.fail = fail or set()
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, *, body=None, headers=None):
        self.calls.append((method, url))
        if "api.osv.dev" in url:
            if "OSV" in self.fail:
                raise TransportError("osv down")
            return self.osv
        if "first.org" in url:
            if "EPSS" in self.fail:
                raise TransportError("epss down")
            return self.epss
        if "cisa.gov" in url:
            if "KEV" in self.fail:
                raise TransportError("kev down")
            return self.kev
        raise TransportError(f"no route for {url}")


def _dep() -> Dependency:
    return Dependency(
        name="jinja2",
        raw_name="Jinja2",
        version="2.10",
        source=DependencySource.REQUIREMENTS_TXT,
        is_direct=True,
    )


def _matcher(transport: FakeTransport, cache: SqliteCache) -> AdvisoryMatcher:
    return AdvisoryMatcher(
        OSVClient(transport, cache),
        EpssClient(transport, cache),
        KevClient(transport, cache),
    )


# --- cache TTL --------------------------------------------------------------------------------


def test_cache_respects_ttl() -> None:
    cache = SqliteCache()
    cache.set("k", "v", ttl=100.0, now=1000.0)
    assert cache.get("k", now=1050.0) == "v"
    assert cache.get("k", now=1101.0) is None  # expired


def test_cache_negative_ttl_never_expires() -> None:
    cache = SqliteCache()
    cache.set("k", "v", ttl=-1.0, now=0.0)
    assert cache.get("k", now=1e12) == "v"


# --- full match against recorded fixtures -----------------------------------------------------


def test_match_yields_advisory_epss_and_kev() -> None:
    transport = FakeTransport(osv=OSV_BYTES, epss=EPSS_BYTES, kev=KEV_BYTES)
    cache = SqliteCache()
    result = _matcher(transport, cache).match([_dep()])

    assert result.degraded_sources == ()
    assert len(result.matches) == 1
    match = result.matches[0]
    assert match.advisory.id == "GHSA-462w-v97r-4m45"
    assert "CVE-2019-10906" in match.advisory.cve_ids
    assert match.advisory.cvss_vector is not None
    assert match.advisory.cvss_vector.startswith("CVSS:")
    assert match.epss is not None
    assert match.epss.probability == pytest.approx(0.945)
    assert match.in_kev is True


def test_second_run_hits_cache_no_network() -> None:
    transport = FakeTransport(osv=OSV_BYTES, epss=EPSS_BYTES, kev=KEV_BYTES)
    cache = SqliteCache()
    matcher = _matcher(transport, cache)

    matcher.match([_dep()])
    calls_after_first = len(transport.calls)
    assert calls_after_first == 3  # OSV + EPSS + KEV

    second = matcher.match([_dep()])
    assert len(transport.calls) == calls_after_first  # zero new network calls
    assert second.matches[0].epss is not None
    assert second.matches[0].in_kev is True


# --- defensive parsing ------------------------------------------------------------------------


@pytest.mark.parametrize("blob", [b"not json at all", b"", b"{", b"[1,2,3]", b"null"])
def test_malformed_payloads_do_not_crash(blob: bytes) -> None:
    transport = FakeTransport(osv=blob, epss=blob, kev=blob)
    cache = SqliteCache()
    result = _matcher(transport, cache).match([_dep()])
    assert result.matches == ()
    assert result.degraded_sources == ()  # bad body != transport failure


def test_empty_osv_object_yields_no_matches() -> None:
    transport = FakeTransport(osv=b"{}", epss=EPSS_BYTES, kev=KEV_BYTES)
    result = _matcher(transport, SqliteCache()).match([_dep()])
    assert result.matches == ()


# --- degraded mode on source outage -----------------------------------------------------------


def test_osv_outage_is_flagged_degraded_not_safe() -> None:
    transport = FakeTransport(osv=OSV_BYTES, epss=EPSS_BYTES, kev=KEV_BYTES, fail={"OSV"})
    result = _matcher(transport, SqliteCache()).match([_dep()])
    assert "OSV" in result.degraded_sources
    assert result.matches == ()


def test_epss_outage_keeps_advisory_but_flags_degraded() -> None:
    transport = FakeTransport(osv=OSV_BYTES, epss=EPSS_BYTES, kev=KEV_BYTES, fail={"EPSS"})
    result = _matcher(transport, SqliteCache()).match([_dep()])
    assert len(result.matches) == 1
    assert result.matches[0].epss is None
    assert result.matches[0].in_kev is True
    assert "EPSS" in result.degraded_sources


def test_kev_outage_keeps_advisory_but_flags_degraded() -> None:
    transport = FakeTransport(osv=OSV_BYTES, epss=EPSS_BYTES, kev=KEV_BYTES, fail={"KEV"})
    result = _matcher(transport, SqliteCache()).match([_dep()])
    assert len(result.matches) == 1
    assert result.matches[0].in_kev is False
    assert "KEV" in result.degraded_sources


# --- individual client behavior ---------------------------------------------------------------


def test_osv_client_parses_fixture() -> None:
    client = OSVClient(FakeTransport(osv=OSV_BYTES), SqliteCache())
    advisories = client.query(_dep())
    assert [a.id for a in advisories] == ["GHSA-462w-v97r-4m45"]
    assert advisories[0].summary is not None


def test_epss_client_caches_misses() -> None:
    transport = FakeTransport(epss=EPSS_BYTES)
    cache = SqliteCache()
    client = EpssClient(transport, cache)
    # CVE present in fixture + one absent: both should be cached (hit and miss).
    first = client.scores(["CVE-2019-10906", "CVE-2000-0001"])
    assert "CVE-2019-10906" in first
    assert "CVE-2000-0001" not in first
    calls = len(transport.calls)
    client.scores(["CVE-2019-10906", "CVE-2000-0001"])
    assert len(transport.calls) == calls  # miss was cached too -> no re-query


def test_kev_client_returns_cve_set() -> None:
    client = KevClient(FakeTransport(kev=KEV_BYTES), SqliteCache())
    cves = client.cve_set()
    assert "CVE-2019-10906" in cves
    assert "CVE-2021-44228" in cves
