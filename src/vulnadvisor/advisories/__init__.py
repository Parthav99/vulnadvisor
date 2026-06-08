"""Advisories: OSV, GitHub Advisory, EPSS, and CISA KEV clients with local cache."""

from vulnadvisor.advisories.clients import (
    DEFAULT_TTL_SECONDS,
    EPSS_URL,
    KEV_URL,
    OSV_QUERY_URL,
    EpssClient,
    KevClient,
    OSVClient,
)
from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.advisories.transport import (
    Transport,
    TransportError,
    UrllibTransport,
)

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "EPSS_URL",
    "KEV_URL",
    "OSV_QUERY_URL",
    "AdvisoryMatcher",
    "EpssClient",
    "KevClient",
    "OSVClient",
    "Transport",
    "TransportError",
    "UrllibTransport",
]
