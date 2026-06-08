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
