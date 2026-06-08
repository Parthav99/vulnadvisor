"""Clients for OSV (advisories), EPSS (exploit probability), and CISA KEV (known-exploited).

Each client caches successful responses in a :class:`SqliteCache` with a TTL and checks the
cache before touching the network, so a second run performs zero requests. Malformed responses
are parsed defensively (safe defaults, never a crash); transport failures raise
:class:`TransportError` for the orchestrator to record as a degraded source.
"""

import json
from collections.abc import Iterable
from typing import Any

from vulnadvisor.advisories.parsing import safe_float, safe_json, safe_str
from vulnadvisor.advisories.transport import Transport
from vulnadvisor.deps.parsers import canonicalize_name
from vulnadvisor.model.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EpssScore,
)
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.store.cache import SqliteCache

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "EpssClient",
    "KevClient",
    "OSVClient",
]

DEFAULT_TTL_SECONDS = 86_400.0  # 24h

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_EPSS_BATCH_SIZE = 100


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    """Return a tuple of the string elements of ``value`` when it is a list, else empty."""
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


class OSVClient:
    """Query OSV.dev for advisories affecting a specific package version."""

    def __init__(
        self, transport: Transport, cache: SqliteCache, *, ttl: float = DEFAULT_TTL_SECONDS
    ) -> None:
        """Bind the client to a ``transport`` and a cache, with a cache ``ttl`` in seconds."""
        self._transport = transport
        self._cache = cache
        self._ttl = ttl

    def query(self, dependency: Dependency) -> list[Advisory]:
        """Return advisories affecting ``dependency`` (cache-first, then OSV)."""
        version = dependency.version
        key = f"osv:v1:query:{dependency.name}:{version or '*'}"
        raw = self._cache.get(key)
        if raw is None:
            payload_obj: dict[str, Any] = {
                "package": {"name": dependency.name, "ecosystem": "PyPI"}
            }
            if version is not None:
                payload_obj["version"] = version
            body = json.dumps(payload_obj).encode("utf-8")
            data = self._transport.request(
                "POST", OSV_QUERY_URL, body=body, headers={"Content-Type": "application/json"}
            )
            raw = data.decode("utf-8", errors="replace")
            self._cache.set(key, raw, self._ttl)
        return _parse_osv_response(safe_json(raw))


def _parse_osv_response(payload: Any) -> list[Advisory]:
    """Parse an OSV ``/v1/query`` response into advisories, ignoring malformed entries."""
    if not isinstance(payload, dict):
        return []
    vulns = payload.get("vulns")
    if not isinstance(vulns, list):
        return []
    advisories: list[Advisory] = []
    for entry in vulns:
        advisory = _parse_osv_vuln(entry)
        if advisory is not None:
            advisories.append(advisory)
    return advisories


def _parse_osv_vuln(entry: Any) -> Advisory | None:
    """Parse one OSV vuln object into an :class:`Advisory`, or ``None`` if it has no id."""
    if not isinstance(entry, dict):
        return None
    advisory_id = safe_str(entry.get("id"))
    if advisory_id is None:
        return None
    cvss_vector = _first_cvss_vector(entry.get("severity"))
    return Advisory(
        id=advisory_id,
        aliases=_as_str_tuple(entry.get("aliases")),
        summary=safe_str(entry.get("summary")),
        details=safe_str(entry.get("details")),
        cvss_vector=cvss_vector,
        modified=safe_str(entry.get("modified")),
        source="OSV",
        affected=_parse_affected(entry.get("affected")),
    )


def _parse_affected(value: Any) -> tuple[AffectedPackage, ...]:
    """Parse an OSV ``affected`` array into typed affected-package records."""
    if not isinstance(value, list):
        return ()
    packages: list[AffectedPackage] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        raw_name = safe_str(package.get("name")) if isinstance(package, dict) else None
        ecosystem = safe_str(package.get("ecosystem")) if isinstance(package, dict) else None
        packages.append(
            AffectedPackage(
                name=canonicalize_name(raw_name) if raw_name else "",
                ecosystem=ecosystem,
                ranges=_parse_ranges(entry.get("ranges")),
                versions=_as_str_tuple(entry.get("versions")),
            )
        )
    return tuple(packages)


def _parse_ranges(value: Any) -> tuple[AffectedRange, ...]:
    """Parse OSV range ``events`` into ``AffectedRange`` records (one per fix/last_affected)."""
    if not isinstance(value, list):
        return ()
    ranges: list[AffectedRange] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        events = entry.get("events")
        if not isinstance(events, list):
            continue
        introduced: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = safe_str(event.get("introduced"))
            elif "fixed" in event:
                ranges.append(
                    AffectedRange(introduced=introduced, fixed=safe_str(event.get("fixed")))
                )
            elif "last_affected" in event:
                ranges.append(
                    AffectedRange(
                        introduced=introduced, last_affected=safe_str(event.get("last_affected"))
                    )
                )
    return tuple(ranges)


def _first_cvss_vector(severity: Any) -> str | None:
    """Return the first CVSS vector string from an OSV ``severity`` list, if any."""
    if not isinstance(severity, list):
        return None
    for item in severity:
        if not isinstance(item, dict):
            continue
        score = safe_str(item.get("score"))
        if score is not None and score.upper().startswith("CVSS:"):
            return score
    return None


class EpssClient:
    """Look up EPSS exploit-probability scores for CVE identifiers."""

    def __init__(
        self, transport: Transport, cache: SqliteCache, *, ttl: float = DEFAULT_TTL_SECONDS
    ) -> None:
        """Bind the client to a ``transport`` and a cache, with a cache ``ttl`` in seconds."""
        self._transport = transport
        self._cache = cache
        self._ttl = ttl

    def scores(self, cves: Iterable[str]) -> dict[str, EpssScore]:
        """Return EPSS scores for the given CVEs (cache-first; misses are cached too)."""
        wanted = sorted({c.upper() for c in cves if c})
        result: dict[str, EpssScore] = {}
        missing: list[str] = []
        for cve in wanted:
            cached = self._cache.get(f"epss:{cve}")
            if cached is None:
                missing.append(cve)
                continue
            score = _epss_from_obj(cve, safe_json(cached))
            if score is not None:
                result[cve] = score

        for start in range(0, len(missing), _EPSS_BATCH_SIZE):
            chunk = missing[start : start + _EPSS_BATCH_SIZE]
            url = f"{EPSS_URL}?cve={','.join(chunk)}"
            data = self._transport.request("GET", url)
            indexed = _index_epss(safe_json(data.decode("utf-8", errors="replace")))
            for cve in chunk:
                obj = indexed.get(cve)
                # Cache the hit or the miss (``null``) so we do not re-query next run.
                self._cache.set(f"epss:{cve}", json.dumps(obj), self._ttl)
                score = _epss_from_obj(cve, obj)
                if score is not None:
                    result[cve] = score
        return result


def _index_epss(payload: Any) -> dict[str, Any]:
    """Index an EPSS API response's ``data`` array by upper-cased CVE id."""
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if not isinstance(data, list):
        return {}
    indexed: dict[str, Any] = {}
    for item in data:
        if isinstance(item, dict):
            cve = safe_str(item.get("cve"))
            if cve is not None:
                indexed[cve.upper()] = item
    return indexed


def _epss_from_obj(cve: str, obj: Any) -> EpssScore | None:
    """Build an :class:`EpssScore` from an EPSS data object, or ``None`` if unusable."""
    if not isinstance(obj, dict):
        return None
    probability = safe_float(obj.get("epss"))
    percentile = safe_float(obj.get("percentile"))
    if probability is None:
        return None
    return EpssScore(cve=cve, probability=probability, percentile=percentile or 0.0)


class KevClient:
    """Check membership in the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(
        self, transport: Transport, cache: SqliteCache, *, ttl: float = DEFAULT_TTL_SECONDS
    ) -> None:
        """Bind the client to a ``transport`` and a cache, with a cache ``ttl`` in seconds."""
        self._transport = transport
        self._cache = cache
        self._ttl = ttl

    def cve_set(self) -> set[str]:
        """Return the set of CVE ids in the KEV catalog (cache-first, then CISA)."""
        cached = self._cache.get("kev:feed")
        if cached is not None:
            parsed = safe_json(cached)
            if isinstance(parsed, list):
                return {c.upper() for c in parsed if isinstance(c, str)}
            return set()
        data = self._transport.request("GET", KEV_URL)
        cves = _parse_kev(safe_json(data.decode("utf-8", errors="replace")))
        self._cache.set("kev:feed", json.dumps(sorted(cves)), self._ttl)
        return cves


def _parse_kev(payload: Any) -> set[str]:
    """Extract the set of upper-cased CVE ids from a KEV catalog payload."""
    if not isinstance(payload, dict):
        return set()
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return set()
    cves: set[str] = set()
    for item in vulnerabilities:
        if isinstance(item, dict):
            cve = safe_str(item.get("cveID"))
            if cve is not None:
                cves.add(cve.upper())
    return cves
