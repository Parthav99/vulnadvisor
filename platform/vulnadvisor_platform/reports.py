"""Parse + denormalize an uploaded ``vulnadvisor scan --format json`` report, and diff two scans.

Pure and defensive (CLAUDE.md): every field of the external report is validated and a malformed
report is rejected with a clear message rather than crashing or silently storing garbage. The full
finding object is preserved verbatim as the row ``payload`` so the platform and CLI never diverge;
the denormalized columns are only for querying and trends.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "SUPPORTED_SCHEMA_VERSIONS",
    "DiffCounts",
    "FindingRow",
    "ParsedReport",
    "ReportValidationError",
    "diff_finding_keys",
    "parse_report",
]

# The JSON report schema versions this platform understands (see output/json_report.py).
# 1.1 is additive over 1.0 (advisory.display_id); 1.2 is additive over 1.1 (the ``finding_type``
# discriminator + the first-party "code"/SAST finding shape), so all three parse here.
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "1.1", "1.2"})

# Stored when reachability was not computed for a finding (the report's reachability was null).
_UNKNOWN_TIER = "unknown"

# Finding-type discriminator (1.2). Absent on 1.0/1.1 reports, which are all dependency findings.
_TYPE_DEPENDENCY = "dependency"
_TYPE_CODE = "code"


class ReportValidationError(ValueError):
    """Raised when an uploaded report is missing required fields or uses an unsupported schema."""


@dataclass(frozen=True)
class FindingRow:
    """One finding denormalized for storage; ``payload`` is the original finding object verbatim.

    For a dependency finding ``package``/``advisory_id`` identify the vulnerable dependency; for a
    first-party code (SAST) finding they hold the sink file and the namespaced rule id
    (``vulnadvisor/<kind>``), and ``tier`` is the SAST confidence tier. ``finding_type`` lets the
    dashboard and analytics branch on the kind without re-parsing the payload.
    """

    advisory_id: str
    package: str
    version: str
    tier: str
    band: str
    priority: float
    payload: dict[str, Any]
    finding_type: str = _TYPE_DEPENDENCY

    @property
    def key(self) -> tuple[str, str]:
        """Identity of a finding across scans: ``(package, advisory_id)``."""
        return (self.package, self.advisory_id)


@dataclass(frozen=True)
class ParsedReport:
    """A validated report ready to persist as a scan + findings."""

    tool_version: str
    degraded_sources: list[str]
    summary: dict[str, Any]
    findings: list[FindingRow]


@dataclass(frozen=True)
class DiffCounts:
    """Counts of findings introduced / fixed / unchanged between two scans on the same ref."""

    introduced: int
    fixed: int
    unchanged: int


def _require_object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportValidationError(f"{what} must be a JSON object")
    return value


def _require_nonempty_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReportValidationError(f"{what} must be a non-empty string")
    return value


def _score_value(score: dict[str, Any], index: int) -> tuple[str, float]:
    """Validate and return ``(band, value)`` from a finding's ``score`` block."""
    band = _require_nonempty_str(score.get("band"), f"findings[{index}].score.band")
    value = score.get("value")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ReportValidationError(f"findings[{index}].score.value must be a number")
    return band, float(value)


def _parse_dependency_finding(index: int, finding: dict[str, Any]) -> FindingRow:
    dependency = _require_object(finding.get("dependency"), f"findings[{index}].dependency")
    advisory = _require_object(finding.get("advisory"), f"findings[{index}].advisory")
    score = _require_object(finding.get("score"), f"findings[{index}].score")

    package = _require_nonempty_str(dependency.get("name"), f"findings[{index}].dependency.name")
    advisory_id = _require_nonempty_str(advisory.get("id"), f"findings[{index}].advisory.id")
    band, value = _score_value(score, index)

    raw_version = dependency.get("version")
    version = raw_version if isinstance(raw_version, str) else ""

    reachability = finding.get("reachability")
    tier = _UNKNOWN_TIER
    if isinstance(reachability, dict):
        raw_tier = reachability.get("tier")
        if isinstance(raw_tier, str) and raw_tier:
            tier = raw_tier

    return FindingRow(
        advisory_id=advisory_id,
        package=package,
        version=version,
        tier=tier,
        band=band,
        priority=value,
        payload=finding,
        finding_type=_TYPE_DEPENDENCY,
    )


def _parse_code_finding(index: int, finding: dict[str, Any]) -> FindingRow:
    """Denormalize a first-party (SAST) finding: package=file, advisory_id=vulnadvisor/<kind>."""
    rule = _require_object(finding.get("rule"), f"findings[{index}].rule")
    location = _require_object(finding.get("location"), f"findings[{index}].location")
    score = _require_object(finding.get("score"), f"findings[{index}].score")

    kind = _require_nonempty_str(rule.get("kind"), f"findings[{index}].rule.kind")
    file = _require_nonempty_str(location.get("file"), f"findings[{index}].location.file")
    band, value = _score_value(score, index)

    flow = finding.get("flow")
    tier = _UNKNOWN_TIER
    if isinstance(flow, dict):
        raw_tier = flow.get("tier")
        if isinstance(raw_tier, str) and raw_tier:
            tier = raw_tier

    # advisory_id (a String(64) column) namespaces the rule so code findings never collide with
    # advisory ids; package (String(200)) holds the sink file. Both are truncated defensively.
    return FindingRow(
        advisory_id=f"vulnadvisor/{kind}"[:64],
        package=file[:200],
        version="",
        tier=tier,
        band=band,
        priority=value,
        payload=finding,
        finding_type=_TYPE_CODE,
    )


def _parse_finding(index: int, raw: Any) -> FindingRow:
    finding = _require_object(raw, f"findings[{index}]")
    finding_type = finding.get("finding_type", _TYPE_DEPENDENCY)
    if finding_type == _TYPE_CODE:
        return _parse_code_finding(index, finding)
    if finding_type not in (_TYPE_DEPENDENCY, None):
        raise ReportValidationError(
            f"findings[{index}].finding_type {finding_type!r} is not recognized"
        )
    return _parse_dependency_finding(index, finding)


def parse_report(report: Any) -> ParsedReport:
    """Validate an uploaded report and denormalize its findings.

    Raises :class:`ReportValidationError` for a non-object report, an unsupported
    ``schema_version``, a non-list ``findings``, or any finding missing its required fields.
    """
    document = _require_object(report, "report")

    version = document.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise ReportValidationError(
            f"unsupported schema_version {version!r}; this server supports: {supported}"
        )

    raw_findings = document.get("findings")
    if not isinstance(raw_findings, list):
        raise ReportValidationError("report.findings must be a list")
    findings = [_parse_finding(i, raw) for i, raw in enumerate(raw_findings)]

    tool = document.get("tool")
    tool_version = "unknown"
    if isinstance(tool, dict) and isinstance(tool.get("version"), str):
        tool_version = tool["version"]

    raw_degraded = document.get("degraded_sources")
    degraded_sources = (
        [str(item) for item in raw_degraded] if isinstance(raw_degraded, list) else []
    )

    raw_summary = document.get("summary")
    summary: dict[str, Any] = (
        raw_summary if isinstance(raw_summary, dict) else {"total": len(findings), "by_band": {}}
    )

    return ParsedReport(
        tool_version=tool_version,
        degraded_sources=degraded_sources,
        summary=summary,
        findings=findings,
    )


def diff_finding_keys(
    previous: Iterable[tuple[str, str]], current: Iterable[tuple[str, str]]
) -> DiffCounts:
    """Diff two scans by finding identity ``(package, advisory_id)``.

    ``introduced`` are in ``current`` only, ``fixed`` are in ``previous`` only, ``unchanged`` are in
    both. With no previous scan, every current finding is ``introduced``.
    """
    previous_keys = set(previous)
    current_keys = set(current)
    return DiffCounts(
        introduced=len(current_keys - previous_keys),
        fixed=len(previous_keys - current_keys),
        unchanged=len(current_keys & previous_keys),
    )
