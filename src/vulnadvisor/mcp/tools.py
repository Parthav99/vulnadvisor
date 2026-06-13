# File: src/vulnadvisor/mcp/tools.py
"""Pure tool logic for the MCP server: filter, look up, and explain findings in a report.

Everything here operates on a plain report ``dict`` (exactly the document produced by
:func:`vulnadvisor.output.json_report.build_report`) so it is fully unit-testable with no MCP SDK,
no network, and no filesystem. The MCP wiring in :mod:`vulnadvisor.mcp.server` is a thin adapter
over these functions.

Soundness rules from CLAUDE.md hold here verbatim: the engine is the authority on priority and
reachability, so these tools only *report* engine truth — they never re-rank, never invent a
verdict, and never emit an unfounded "all clear". ``explain_finding`` deliberately returns
deterministic *facts*, not prose: the client's LLM does the wording.
"""

from typing import Any

from vulnadvisor.model.reachability import ReachabilityTier
from vulnadvisor.model.score import PriorityBand

__all__ = [
    "AmbiguousFindingError",
    "FindingNotFoundError",
    "McpToolError",
    "NoScanError",
    "compact_finding",
    "explain_finding_facts",
    "filter_findings",
    "finding_id",
    "get_finding_detail",
    "scan_summary",
]

_VALID_TIERS = frozenset(t.value for t in ReachabilityTier)
_VALID_BANDS = frozenset(b.value for b in PriorityBand)

# Plain-language meaning of each reachability tier (the CLAUDE.md confidence-tier definitions),
# surfaced so the client LLM can explain *why* a tier matters without re-deriving the semantics.
TIER_MEANING: dict[str, str] = {
    ReachabilityTier.IMPORTED_AND_CALLED.value: (
        "A concrete call path from your code to the vulnerable symbol exists — the highest concern."
    ),
    ReachabilityTier.IMPORTED.value: (
        "The vulnerable module/symbol is imported, but no call to it was confirmed."
    ),
    ReachabilityTier.DYNAMIC_UNKNOWN.value: (
        "Reflection, eval/exec, dynamic import, or framework magic blocks certainty — "
        "this is never treated as safe."
    ),
    ReachabilityTier.NOT_IMPORTED.value: (
        "The package is never imported from your code — the only confidently-safe tier."
    ),
}


class McpToolError(Exception):
    """Base class for expected, user-facing tool failures (surface as MCP tool errors)."""


class NoScanError(McpToolError):
    """No scan results are available yet; the client must call ``scan(path)`` first."""


class FindingNotFoundError(McpToolError):
    """No finding in the current report matches the supplied identifier."""


class AmbiguousFindingError(McpToolError):
    """The identifier matched more than one finding; the caller must disambiguate."""


def _dependency(finding: dict[str, Any]) -> dict[str, Any]:
    dep = finding.get("dependency")
    return dep if isinstance(dep, dict) else {}


def _advisory(finding: dict[str, Any]) -> dict[str, Any]:
    adv = finding.get("advisory")
    return adv if isinstance(adv, dict) else {}


def _score(finding: dict[str, Any]) -> dict[str, Any]:
    score = finding.get("score")
    return score if isinstance(score, dict) else {}


def _reachability(finding: dict[str, Any]) -> dict[str, Any] | None:
    reach = finding.get("reachability")
    return reach if isinstance(reach, dict) else None


def _epss(finding: dict[str, Any]) -> dict[str, Any] | None:
    epss = finding.get("epss")
    return epss if isinstance(epss, dict) else None


def _fix(finding: dict[str, Any]) -> dict[str, Any]:
    fix = finding.get("fix")
    return fix if isinstance(fix, dict) else {}


def finding_id(finding: dict[str, Any]) -> str:
    """Return the stable identifier for a finding: ``<package>:<raw-advisory-id>``.

    A finding is the pairing of one dependency with one advisory, so this is unique within a scan
    and stable across runs (it never depends on ordering). Clients may also reference a finding by
    its CVE/display id or any alias — see :func:`_match_tokens`.
    """
    return f"{_dependency(finding).get('name', '?')}:{_advisory(finding).get('id', '?')}"


def _match_tokens(finding: dict[str, Any]) -> set[str]:
    """Casefolded identifiers a client may use to reference this finding.

    Includes the bare package name for ergonomics ("explain jinja2"); when a package has more than
    one finding that resolves to an :class:`AmbiguousFindingError` listing the exact finding_ids,
    so it is helpful, never lossy.
    """
    advisory = _advisory(finding)
    tokens: set[str] = {finding_id(finding)}
    package = _dependency(finding).get("name")
    if isinstance(package, str):
        tokens.add(package)
    for key in ("id", "display_id"):
        value = advisory.get(key)
        if isinstance(value, str):
            tokens.add(value)
    for key in ("aliases", "cve_ids"):
        for value in advisory.get(key, []) or []:
            if isinstance(value, str):
                tokens.add(value)
    return {token.casefold() for token in tokens if token}


def _match_findings(report: dict[str, Any], identifier: str) -> list[dict[str, Any]]:
    """Return every finding whose id/display-id/alias/cve matches ``identifier`` (casefolded)."""
    needle = identifier.strip().casefold()
    findings = report.get("findings", [])
    return [
        finding
        for finding in findings
        if isinstance(finding, dict) and needle in _match_tokens(finding)
    ]


def compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """A one-row summary of a finding for list/scan results (scannable, not the full story)."""
    dependency = _dependency(finding)
    advisory = _advisory(finding)
    score = _score(finding)
    reachability = _reachability(finding)
    return {
        "finding_id": finding_id(finding),
        "display_id": advisory.get("display_id"),
        "package": dependency.get("name"),
        "version": dependency.get("version"),
        "band": score.get("band"),
        "priority": score.get("value"),
        "verdict": score.get("verdict"),
        "tier": reachability.get("tier") if reachability is not None else None,
        "in_kev": bool(finding.get("in_kev", False)),
    }


def _tier_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per reachability tier, with all four tiers present for a stable shape."""
    counts = {tier.value: 0 for tier in ReachabilityTier}
    counts["unknown"] = 0
    for finding in findings:
        reachability = _reachability(finding)
        tier = reachability.get("tier") if reachability is not None else None
        if isinstance(tier, str) and tier in counts:
            counts[tier] += 1
        else:
            counts["unknown"] += 1
    return counts


def _actionable_count(findings: list[dict[str, Any]]) -> int:
    """Findings that are not in the only confidently-safe tier (``not-imported``).

    This is a count, never a safety verdict: a higher number is not "bad" and zero is not an
    all-clear. The deterministic tiers carry the meaning; we only tally them.
    """
    safe = ReachabilityTier.NOT_IMPORTED.value
    actionable = 0
    for finding in findings:
        reachability = _reachability(finding)
        tier = reachability.get("tier") if reachability is not None else None
        if tier != safe:
            actionable += 1
    return actionable


def scan_summary(report: dict[str, Any], scanned_path: str) -> dict[str, Any]:
    """The result of ``scan(path)``: counts plus every finding in priority order (compact rows)."""
    findings = [f for f in report.get("findings", []) if isinstance(f, dict)]
    summary = report.get("summary", {})
    by_band = summary.get("by_band", {}) if isinstance(summary, dict) else {}
    return {
        "scanned_path": scanned_path,
        "total": len(findings),
        "by_band": by_band,
        "by_tier": _tier_counts(findings),
        "actionable": _actionable_count(findings),
        "degraded_sources": list(report.get("degraded_sources", []) or []),
        "findings": [compact_finding(f) for f in findings],
    }


def _validate_choice(value: str, valid: frozenset[str], label: str) -> str:
    """Return ``value`` if it is in ``valid``; else raise a helpful error listing the options."""
    if value not in valid:
        options = ", ".join(sorted(valid))
        raise McpToolError(f"unknown {label} '{value}'; valid {label}s: {options}")
    return value


def filter_findings(
    report: dict[str, Any],
    *,
    tier: str | None = None,
    band: str | None = None,
    package: str | None = None,
    min_score: float | None = None,
    in_kev: bool | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Filter the report's findings and return matching compact rows (priority order preserved).

    All filters are optional and combine with AND. ``tier``/``band`` are validated against the
    engine's vocabularies (an unknown value raises rather than silently matching nothing).
    ``package`` matches the canonical name case-insensitively. ``limit`` caps the returned rows;
    ``total_matched`` always reports the full match count so the client knows it was truncated.
    """
    if tier is not None:
        tier = _validate_choice(tier, _VALID_TIERS, "tier")
    if band is not None:
        band = _validate_choice(band, _VALID_BANDS, "band")
    if limit is not None and limit < 0:
        raise McpToolError("limit must be non-negative")

    package_key = package.strip().casefold() if package is not None else None
    rows = [compact_finding(f) for f in report.get("findings", []) if isinstance(f, dict)]

    def keep(row: dict[str, Any]) -> bool:
        if tier is not None and row["tier"] != tier:
            return False
        if band is not None and row["band"] != band:
            return False
        if package_key is not None:
            name = row["package"]
            if not isinstance(name, str) or name.casefold() != package_key:
                return False
        if min_score is not None:
            value = row["priority"]
            if not isinstance(value, int | float) or value < min_score:
                return False
        return not (in_kev is not None and row["in_kev"] != in_kev)

    matched = [row for row in rows if keep(row)]
    shown = matched if limit is None else matched[:limit]
    return {
        "count": len(shown),
        "total_matched": len(matched),
        "findings": shown,
        "filters": {
            "tier": tier,
            "band": band,
            "package": package,
            "min_score": min_score,
            "in_kev": in_kev,
            "limit": limit,
        },
    }


def _resolve_one(report: dict[str, Any], identifier: str) -> dict[str, Any]:
    """Resolve ``identifier`` to exactly one finding, or raise a precise error."""
    matches = _match_findings(report, identifier)
    if not matches:
        raise FindingNotFoundError(
            f"no finding matches '{identifier}'. Use a finding_id, advisory id, "
            f"display id (e.g. CVE-XXXX-YYYY), or alias from a list_findings result."
        )
    if len(matches) > 1:
        ids = ", ".join(finding_id(m) for m in matches)
        raise AmbiguousFindingError(
            f"'{identifier}' matches multiple findings: {ids}. Pass one of these finding_ids."
        )
    return matches[0]


def get_finding_detail(report: dict[str, Any], identifier: str) -> dict[str, Any]:
    """Return the full evidence for one finding (advisory, score, reachability + call path, fix)."""
    finding = _resolve_one(report, identifier)
    detail = dict(finding)
    detail["finding_id"] = finding_id(finding)
    return detail


def explain_finding_facts(report: dict[str, Any], identifier: str) -> dict[str, Any]:
    """Return the deterministic facts behind one finding for the client's LLM to narrate.

    No prose, no LLM call, no opinion: the priority, the reachability tier and its meaning, the
    exploitability signals, the fix, and a list of plain factual statements — all straight from the
    engine. The client decides the wording; the engine decides the truth.
    """
    finding = _resolve_one(report, identifier)
    dependency = _dependency(finding)
    advisory = _advisory(finding)
    score = _score(finding)
    reachability = _reachability(finding)
    epss = _epss(finding)
    fix = _fix(finding)

    name = dependency.get("name")
    version = dependency.get("version")
    display = advisory.get("display_id")
    tier = reachability.get("tier") if reachability is not None else None

    facts: list[str] = []
    facts.append(
        f"{display} affects {name} {version or '(unpinned)'}."
        if display
        else f"Advisory affects {name} {version or '(unpinned)'}."
    )
    if score.get("value") is not None:
        facts.append(
            f"Deterministic priority is {score.get('value')}/100 "
            f"(band: {score.get('band')}) — {score.get('verdict')}."
        )
    if reachability is not None:
        facts.append(f"Reachability tier is '{tier}': {reachability.get('reason')}")
        for path in reachability.get("call_paths", []) or []:
            facts.append(f"Call path: {path}")
    if finding.get("in_kev"):
        facts.append("Listed in CISA KEV: known to be exploited in the wild.")
    if epss is not None and epss.get("probability") is not None:
        facts.append(
            f"EPSS exploit probability {epss.get('probability')} "
            f"(percentile {epss.get('percentile')})."
        )
    if fix.get("has_fix") and fix.get("command"):
        facts.append(f"A fix is available: {fix.get('command')}")
    elif not fix.get("has_fix"):
        facts.append("No fixed version is currently available.")

    return {
        "finding_id": finding_id(finding),
        "display_id": display,
        "package": name,
        "version": version,
        "priority": {
            "score": score.get("value"),
            "band": score.get("band"),
            "verdict": score.get("verdict"),
            "rationale": score.get("rationale"),
        },
        "reachability": (
            {
                "tier": tier,
                "reason": reachability.get("reason"),
                "meaning": TIER_MEANING.get(tier) if isinstance(tier, str) else None,
                "call_paths": list(reachability.get("call_paths", []) or []),
                "evidence": list(reachability.get("evidence", []) or []),
            }
            if reachability is not None
            else None
        ),
        "exploitability": {
            "in_kev": bool(finding.get("in_kev", False)),
            "epss_probability": epss.get("probability") if epss is not None else None,
            "epss_percentile": epss.get("percentile") if epss is not None else None,
            "cvss_base": advisory.get("cvss_base"),
            "cvss_known": score.get("cvss_known"),
        },
        "fix": {
            "command": fix.get("command"),
            "fixed_version": fix.get("fixed_version"),
            "has_fix": bool(fix.get("has_fix", False)),
            "note": fix.get("note"),
        },
        "facts": facts,
    }
