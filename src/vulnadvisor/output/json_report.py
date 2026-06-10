"""Build the stable, documented JSON report for machine consumption.

Schema (``schema_version`` 1.1) — top-level object::

    {
      "schema_version": "1.1",
      "tool": {"name": "vulnadvisor", "version": "<x.y.z>"},
      "degraded_sources": ["OSV", ...],          # sources that failed; results incomplete
      "summary": {"total": <int>, "by_band": {"critical": n, "high": n, ...}},
      "findings": [
        {
          "dependency": {"name", "version"|null, "source", "is_direct"},
          "advisory":   {"id", "display_id", "aliases":[...], "cve_ids":[...], "summary"|null,
                          "cvss_base": <float>|null, "cvss_vector": <str>|null, "source"},
          "epss":       {"probability": <float>, "percentile": <float>} | null,
          "in_kev":     <bool>,
          "score":      {"value": <float>, "band", "verdict", "rationale", "cvss_known": <bool>},
          "reachability": {"tier", "reason", "evidence": [{"file", "line"}]} | null,
          "fix":        {"command": <str>|null, "fixed_version": <str>|null, "has_fix": <bool>,
                          "is_major_jump": <bool>, "available_fixes": [...], "note": <str>}
        }
      ]
    }

Findings are ordered by descending priority (the deterministic engine ordering).

Version history: 1.1 adds the additive ``advisory.display_id`` (the canonical CVE-first display
identifier); everything in 1.0 is unchanged, so 1.0 consumers can read 1.1 reports.
"""

import json
from collections.abc import Sequence
from typing import Any

from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.model.display import display_id
from vulnadvisor.model.score import PriorityBand, ScoredFinding
from vulnadvisor.output.remediation import fix_command

__all__ = ["SCHEMA_VERSION", "build_report", "to_json"]

SCHEMA_VERSION = "1.1"


def _finding_dict(finding: ScoredFinding) -> dict[str, Any]:
    """Serialize one scored finding to the documented JSON shape."""
    dependency = finding.matched.dependency
    advisory = finding.matched.advisory
    epss = finding.matched.epss
    score = finding.score
    reachability = finding.reachability
    safe_fix = resolve_safe_fix(dependency, advisory)
    return {
        "dependency": {
            "name": dependency.name,
            "version": dependency.version,
            "source": dependency.source.value,
            "is_direct": dependency.is_direct,
        },
        "advisory": {
            "id": advisory.id,
            "display_id": display_id(advisory),
            "aliases": list(advisory.aliases),
            "cve_ids": list(advisory.cve_ids),
            "summary": advisory.summary,
            "cvss_base": score.cvss_base,
            "cvss_vector": advisory.cvss_vector,
            "source": advisory.source,
        },
        "epss": (
            {"probability": epss.probability, "percentile": epss.percentile}
            if epss is not None
            else None
        ),
        "in_kev": finding.matched.in_kev,
        "score": {
            "value": score.value,
            "band": score.band.value,
            "verdict": score.verdict,
            "rationale": score.rationale,
            "cvss_known": score.cvss_known,
        },
        "reachability": (
            {
                "tier": reachability.tier.value,
                "reason": reachability.reason,
                "evidence": [
                    {"file": site.file, "line": site.lineno} for site in reachability.evidence
                ],
                "call_paths": [path.render() for path in reachability.call_paths],
            }
            if reachability is not None
            else None
        ),
        "fix": {
            "command": fix_command(dependency, safe_fix),
            "fixed_version": safe_fix.fixed_version,
            "has_fix": safe_fix.has_fix,
            "is_major_jump": safe_fix.is_major_jump,
            "available_fixes": list(safe_fix.available_fixes),
            "note": safe_fix.note,
        },
    }


def _count_bands(findings: Sequence[ScoredFinding]) -> dict[str, int]:
    """Count findings per band, with all bands present for a stable shape."""
    counts = {band.value: 0 for band in PriorityBand}
    for finding in findings:
        counts[finding.score.band.value] += 1
    return counts


def build_report(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
) -> dict[str, Any]:
    """Build the full JSON report object (schema_version 1.1)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "vulnadvisor", "version": tool_version},
        "degraded_sources": list(degraded_sources),
        "summary": {"total": len(findings), "by_band": _count_bands(findings)},
        "findings": [_finding_dict(finding) for finding in findings],
    }


def to_json(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
) -> str:
    """Render the JSON report as a deterministic, ASCII-safe string."""
    report = build_report(findings, degraded_sources, tool_version=tool_version)
    return json.dumps(report, indent=2, ensure_ascii=True)
