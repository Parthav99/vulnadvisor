"""Build the stable, documented JSON report for machine consumption.

Schema (``schema_version`` 1.2) — top-level object::

    {
      "schema_version": "1.2",
      "tool": {"name": "vulnadvisor", "version": "<x.y.z>"},
      "degraded_sources": ["OSV", ...],          # sources that failed; results incomplete
      "summary": {"total": <int>, "by_band": {"critical": n, "high": n, ...}},
      "findings": [
        {
          "finding_type": "dependency",          # present on every finding (1.2)
          "dependency": {"name", "version"|null, "source", "is_direct"},
          "advisory":   {"id", "display_id", "aliases":[...], "cve_ids":[...], "summary"|null,
                          "cvss_base": <float>|null, "cvss_vector": <str>|null, "source"},
          "epss":       {"probability": <float>, "percentile": <float>} | null,
          "in_kev":     <bool>,
          "score":      {"value": <float>, "band", "verdict", "rationale", "cvss_known": <bool>},
          "reachability": {"tier", "reason", "evidence":[...], "call_paths":[...]} | null,
          "fix":        {"command": <str>|null, "fixed_version": <str>|null, "has_fix": <bool>,
                          "is_major_jump": <bool>, "available_fixes": [...], "note": <str>},
          "runtime":    {"status": "runtime-confirmed"|"not-observed", "reason": <str>,
                          "observed": [{"file", "line"}]}   # only when --coverage annotated it
        },
        {
          "finding_type": "code",                # first-party (SAST) finding (1.2)
          "rule":     {"cwe", "kind", "title"},
          "location": {"file", "line", "column"},
          "flow":     {"tier", "source": {"kind"|null, "file"|null, "line"|null},
                        "sink": {"kind", "file", "line"}, "path": [...], "sanitizers": [...]},
          "score":    {"value", "band", "verdict", "rationale", "cvss_known": false},
          "fix":      {"direction": <str>, "has_fix": false},
          "provenance": ["vulnadvisor", ...],    # tools that found it (1.2 additive; fusion, 21.4)
          "runtime":  {"status", "reason", "observed": [...]}   # only when --coverage annotated it
        }
      ]
    }

Findings are ordered by descending priority (the deterministic engine ordering), mixing dependency
(SCA) and code (SAST) findings into one ranked list.

Version history: 1.2 adds the additive ``finding_type`` discriminator (set to ``"dependency"`` on
the existing SCA shape) and the ``"code"`` finding sub-shape; everything in 1.1 (which added
``advisory.display_id``) and 1.0 is unchanged, so 1.0/1.1 consumers can read 1.2 reports. The
optional ``runtime`` annotation (Task 16.6, present only under ``--coverage``) is additive within
1.2 — absent unless a coverage overlay confirmed/observed the finding, so reports without coverage
are byte-for-byte unchanged. The code finding's ``provenance`` array (Task 21.4 multi-tool fusion —
``["vulnadvisor"]`` natively, ``["vulnadvisor", "semgrep-oss"]`` when corroborated) is likewise
additive under 1.2 (``docs/fusion-design.md`` §12.2 — no schema bump); older consumers ignore it.
"""

import json
from collections.abc import Sequence
from typing import Any

from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.engine.sast_scoring import UnifiedFinding, order_unified
from vulnadvisor.model.display import display_id
from vulnadvisor.model.runtime import RuntimeEvidence
from vulnadvisor.model.score import PriorityBand, ScoredFinding
from vulnadvisor.output.remediation import fix_command
from vulnadvisor.sast.model import ScoredSastFinding
from vulnadvisor.sast.remediation import remediation_direction

__all__ = ["SCHEMA_VERSION", "build_report", "to_json"]

SCHEMA_VERSION = "1.2"


def _add_runtime(target: dict[str, Any], runtime: RuntimeEvidence | None) -> None:
    """Add the optional dynamic-coverage annotation (Task 16.6) to ``target`` in place.

    Additive within schema 1.2: the ``runtime`` key appears only when a ``--coverage`` overlay
    annotated the finding, so reports without coverage are byte-for-byte unchanged and consumers
    that ignore the key keep reading every report.
    """
    if runtime is None:
        return
    target["runtime"] = {
        "status": runtime.status.value,
        "reason": runtime.reason,
        "observed": [{"file": line.file, "line": line.line} for line in runtime.observed],
    }


def _finding_dict(finding: ScoredFinding) -> dict[str, Any]:
    """Serialize one scored dependency (SCA) finding to the documented JSON shape."""
    dependency = finding.matched.dependency
    advisory = finding.matched.advisory
    epss = finding.matched.epss
    score = finding.score
    reachability = finding.reachability
    safe_fix = resolve_safe_fix(dependency, advisory)
    result: dict[str, Any] = {
        "finding_type": "dependency",
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
    _add_runtime(result, finding.runtime)
    return result


def _sast_finding_dict(scored: ScoredSastFinding) -> dict[str, Any]:
    """Serialize one scored first-party (SAST) finding to the ``finding_type: "code"`` shape."""
    finding = scored.finding
    score = scored.score
    flow = finding.flow
    if flow is not None and flow.steps:
        first = flow.steps[0]
        source = {"kind": finding.source_kind, "file": first.file, "line": first.line}
        path = [flow.render()]
    else:
        # Intra-procedural or literal (CWE-798): source == sink, empty path.
        source = {"kind": finding.source_kind, "file": finding.file, "line": finding.line}
        path = []
    result: dict[str, Any] = {
        "finding_type": "code",
        "rule": {"cwe": finding.cwe, "kind": finding.kind, "title": finding.title},
        "location": {"file": finding.file, "line": finding.line, "column": finding.col},
        "flow": {
            "tier": finding.tier.value,
            "reason": finding.reason,
            "source": source,
            "sink": {"kind": finding.kind, "file": finding.file, "line": finding.line},
            "path": path,
            "sanitizers": [],
        },
        "score": {
            "value": score.value,
            "band": score.band.value,
            "verdict": score.verdict,
            "rationale": score.rationale,
            "cvss_known": score.cvss_known,
        },
        "fix": {"direction": remediation_direction(finding.cwe), "has_fix": False},
        # Who found it, who ranked it (Task 21.4 fusion): native is ["vulnadvisor"]; a corroborated
        # finding lists every tool, our engine first. Additive under 1.2 (fusion-design §12.2).
        "provenance": list(finding.provenance),
    }
    _add_runtime(result, scored.runtime)
    return result


def _serialize(finding: UnifiedFinding) -> dict[str, Any]:
    """Dispatch a unified finding to its type-specific serializer."""
    if isinstance(finding, ScoredFinding):
        return _finding_dict(finding)
    return _sast_finding_dict(finding)


def _count_bands(findings: Sequence[UnifiedFinding]) -> dict[str, int]:
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
    sast_findings: Sequence[ScoredSastFinding] = (),
) -> dict[str, Any]:
    """Build the full JSON report object (schema_version 1.2).

    Dependency (``findings``) and first-party code (``sast_findings``) findings are merged into one
    deterministically ranked list. ``sast_findings`` defaults to empty, so SCA-only callers are
    unchanged.
    """
    unified = order_unified([*findings, *sast_findings])
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "vulnadvisor", "version": tool_version},
        "degraded_sources": list(degraded_sources),
        "summary": {"total": len(unified), "by_band": _count_bands(unified)},
        "findings": [_serialize(finding) for finding in unified],
    }


def to_json(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
    sast_findings: Sequence[ScoredSastFinding] = (),
) -> str:
    """Render the JSON report as a deterministic, ASCII-safe string."""
    report = build_report(
        findings, degraded_sources, tool_version=tool_version, sast_findings=sast_findings
    )
    return json.dumps(report, indent=2, ensure_ascii=True)
