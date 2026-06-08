"""Models for vulnerability advisories and their risk-signal enrichment."""

import re

from pydantic import BaseModel, ConfigDict

from vulnadvisor.model.dependency import Dependency

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class AffectedRange(BaseModel):
    """One affected version interval from an advisory.

    A ``fixed`` version (when present) is the first version that is no longer affected by this
    interval; ``last_affected`` marks the highest affected version when no fix exists.
    """

    model_config = ConfigDict(frozen=True)

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class AffectedPackage(BaseModel):
    """The affected ranges/versions of a single package within an advisory."""

    model_config = ConfigDict(frozen=True)

    name: str
    ecosystem: str | None = None
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()


class Advisory(BaseModel):
    """A single vulnerability advisory matched to a package version (typically from OSV).

    Attributes:
        id: The advisory's primary identifier (e.g. a ``GHSA-...`` or ``PYSEC-...`` id).
        aliases: Other identifiers for the same vulnerability (CVE ids, GHSA ids, ...).
        summary: Short human-readable summary, if provided.
        details: Longer description, if provided.
        cvss_score: Numeric CVSS base score when known. Left ``None`` here; computed from the
            vector by the scoring engine (Task 2.2).
        cvss_vector: CVSS vector string when provided by the advisory.
        modified: Last-modified timestamp string from the source, if provided.
        source: Which database produced this record.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    details: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    modified: str | None = None
    source: str = "OSV"
    affected: tuple[AffectedPackage, ...] = ()

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """Return the CVE identifiers among this advisory's id and aliases (de-duplicated)."""
        candidates = (self.id, *self.aliases)
        return tuple(dict.fromkeys(c.upper() for c in candidates if _CVE_RE.match(c)))


class EpssScore(BaseModel):
    """An EPSS (Exploit Prediction Scoring System) result for one CVE.

    Attributes:
        cve: The CVE identifier.
        probability: Probability (0..1) of exploitation in the next 30 days.
        percentile: Percentile rank (0..1) of that probability among all scored CVEs.
    """

    model_config = ConfigDict(frozen=True)

    cve: str
    probability: float
    percentile: float


class MatchedAdvisory(BaseModel):
    """One advisory matched to a dependency, enriched with EPSS and KEV signals."""

    model_config = ConfigDict(frozen=True)

    dependency: Dependency
    advisory: Advisory
    epss: EpssScore | None = None
    in_kev: bool = False


class MatchResult(BaseModel):
    """The full result of matching a dependency list against advisory/risk sources.

    Attributes:
        matches: Every matched advisory (one dependency may yield several).
        degraded_sources: Sources that failed and returned no data (e.g. ``("OSV",)``). Non-empty
            means results are incomplete and must NOT be read as "confidently safe".
    """

    model_config = ConfigDict(frozen=True)

    matches: tuple[MatchedAdvisory, ...] = ()
    degraded_sources: tuple[str, ...] = ()
