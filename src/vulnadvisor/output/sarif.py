"""Emit SARIF 2.1.0 so findings surface in GitHub code scanning (Security tab).

We emit one ``rule`` per advisory id (SCA) or per code-rule kind (SAST), and one ``result`` per
finding. ``level`` maps the priority band (error / warning / note), and
``properties["security-severity"]`` is set so GitHub orders findings by our triage priority.

* **Dependency (SCA) findings** keep the raw advisory id as ``ruleId`` and point at the manifest.
* **Code (SAST) findings** use the namespaced ``ruleId`` ``vulnadvisor/<kind>``, carry a CWE
  taxonomy relationship (so GitHub shows the CWE), point at the sink's real ``file:line``, and emit
  the source->sink path as a SARIF ``codeFlow`` so the flow renders inline. Both finding kinds are
  merged into one ranked list of results.
"""

import json
from collections.abc import Sequence
from typing import Any

from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.engine.sast_scoring import cwe_base_severity, order_unified
from vulnadvisor.model.dependency import DependencySource
from vulnadvisor.model.display import display_id
from vulnadvisor.model.score import PriorityBand, ScoredFinding
from vulnadvisor.output.remediation import fix_command
from vulnadvisor.sast.model import ScoredSastFinding
from vulnadvisor.sast.remediation import remediation_direction

__all__ = ["SARIF_SCHEMA_URI", "SARIF_VERSION", "build_sarif", "to_sarif_json"]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/your-org/vulnadvisor"
_CWE_TAXONOMY_NAME = "CWE"
_CWE_INFORMATION_URI = "https://cwe.mitre.org/"

_LEVELS: dict[PriorityBand, str] = {
    PriorityBand.CRITICAL: "error",
    PriorityBand.HIGH: "error",
    PriorityBand.MEDIUM: "warning",
    PriorityBand.LOW: "note",
    PriorityBand.INFO: "note",
}

_MANIFEST_FILENAMES = {
    DependencySource.REQUIREMENTS_TXT: "requirements.txt",
    DependencySource.PYPROJECT_TOML: "pyproject.toml",
    DependencySource.POETRY_LOCK: "poetry.lock",
    DependencySource.PIPFILE_LOCK: "Pipfile.lock",
    DependencySource.ENVIRONMENT: "environment",
}

# CWE id -> (full name, MITRE definition number) for the SARIF CWE taxonomy `taxa`.
_CWE_NAMES: dict[str, tuple[str, str]] = {
    "CWE-89": ("Improper Neutralization of Special Elements used in an SQL Command", "89"),
    "CWE-78": ("Improper Neutralization of Special Elements used in an OS Command", "78"),
    "CWE-94": ("Improper Control of Generation of Code ('Code Injection')", "94"),
    "CWE-95": ("Improper Neutralization of Directives in Dynamically Evaluated Code", "95"),
    "CWE-502": ("Deserialization of Untrusted Data", "502"),
    "CWE-22": ("Improper Limitation of a Pathname to a Restricted Directory", "22"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "918"),
    "CWE-798": ("Use of Hard-coded Credentials", "798"),
}


def _security_severity(finding: ScoredFinding) -> str:
    """0-10 severity string GitHub reads: the CVSS base if known, else priority/10."""
    score = finding.score
    value = score.cvss_base if score.cvss_base is not None else round(score.value / 10.0, 1)
    return f"{value:.1f}"


def _rule(finding: ScoredFinding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) for a dependency finding's advisory.

    ``id`` (the SARIF ruleId) stays the stable raw advisory id; only the human-readable
    ``shortDescription`` uses the canonical CVE-first display identity.
    """
    advisory = finding.matched.advisory
    label = display_id(advisory)
    return {
        "id": advisory.id,
        "name": "VulnerableDependency",
        "shortDescription": {"text": f"{label}: {advisory.summary}" if advisory.summary else label},
        "helpUri": f"https://osv.dev/vulnerability/{advisory.id}",
        "properties": {"security-severity": _security_severity(finding)},
    }


def _result(finding: ScoredFinding) -> dict[str, Any]:
    """Build a SARIF result for a single dependency finding."""
    dependency = finding.matched.dependency
    advisory = finding.matched.advisory
    score = finding.score
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"
    summary = advisory.summary or "No description provided by the advisory."
    uri = _MANIFEST_FILENAMES.get(dependency.source, "environment")
    safe_fix = resolve_safe_fix(dependency, advisory)
    reachability = finding.reachability
    return {
        "ruleId": advisory.id,
        "level": _LEVELS[score.band],
        "message": {"text": f"{name} {version}: {summary} ({score.verdict}.)"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "properties": {
            "priority": score.value,
            "band": score.band.value,
            "verdict": score.verdict,
            "in_kev": finding.matched.in_kev,
            "cve_ids": list(advisory.cve_ids),
            "reachability_tier": reachability.tier.value if reachability is not None else None,
            "fixed_version": safe_fix.fixed_version,
            "fix_command": fix_command(dependency, safe_fix),
        },
    }


def _sast_rule_id(kind: str) -> str:
    """The namespaced SARIF ruleId for a code rule (e.g. ``vulnadvisor/sql-injection``)."""
    return f"vulnadvisor/{kind}"


def _sast_rule(scored: ScoredSastFinding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor for a code rule, related to its CWE taxonomy entry."""
    finding = scored.finding
    return {
        "id": _sast_rule_id(finding.kind),
        "name": "".join(part.capitalize() for part in finding.kind.split("-")),
        "shortDescription": {"text": f"{finding.cwe}: {finding.title}"},
        "relationships": [
            {
                "target": {
                    "id": finding.cwe,
                    "toolComponent": {"name": _CWE_TAXONOMY_NAME},
                },
                "kinds": ["superset"],
            }
        ],
        "properties": {"security-severity": f"{cwe_base_severity(finding.cwe):.1f}"},
    }


def _code_flows(scored: ScoredSastFinding) -> list[dict[str, Any]]:
    """Render the source->sink path as a SARIF codeFlow (empty list when there is no flow)."""
    flow = scored.finding.flow
    if flow is None or not flow.steps:
        return []
    locations = []
    for step in flow.steps:
        physical: dict[str, Any] = {}
        if step.file:
            physical["artifactLocation"] = {"uri": step.file}
        if step.line is not None:
            physical["region"] = {"startLine": step.line}
        location: dict[str, Any] = {"message": {"text": step.qualname}}
        if physical:
            location["physicalLocation"] = physical
        locations.append({"location": location})
    return [{"threadFlows": [{"locations": locations}]}]


def _sast_result(scored: ScoredSastFinding) -> dict[str, Any]:
    """Build a SARIF result for a single code finding (sink location + source->sink codeFlow)."""
    finding = scored.finding
    score = scored.score
    result: dict[str, Any] = {
        "ruleId": _sast_rule_id(finding.kind),
        "level": _LEVELS[score.band],
        "message": {"text": f"{finding.title}: {finding.reason} ({score.verdict}.)"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": finding.line, "startColumn": finding.col + 1},
                }
            }
        ],
        "properties": {
            "priority": score.value,
            "band": score.band.value,
            "verdict": score.verdict,
            "cwe": finding.cwe,
            "tier": finding.tier.value,
            "source_kind": finding.source_kind,
            "remediation": remediation_direction(finding.cwe),
        },
    }
    code_flows = _code_flows(scored)
    if code_flows:
        result["codeFlows"] = code_flows
    return result


def _cwe_taxonomy(cwes: Sequence[str]) -> dict[str, Any]:
    """Build the CWE taxonomy toolComponent referenced by code-rule relationships."""
    taxa = []
    for cwe in cwes:
        name, number = _CWE_NAMES.get(cwe, (cwe, cwe.removeprefix("CWE-")))
        taxa.append(
            {
                "id": cwe,
                "name": name,
                "helpUri": f"https://cwe.mitre.org/data/definitions/{number}.html",
            }
        )
    return {
        "name": _CWE_TAXONOMY_NAME,
        "informationUri": _CWE_INFORMATION_URI,
        "organization": "MITRE",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration."},
        "taxa": taxa,
    }


def build_sarif(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
    sast_findings: Sequence[ScoredSastFinding] = (),
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for the dependency and code findings (merged, one ranked list)."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    cwes: list[str] = []

    for finding in order_unified([*findings, *sast_findings]):
        if isinstance(finding, ScoredFinding):
            rule_id = finding.matched.advisory.id
            if rule_id not in rules:
                rules[rule_id] = _rule(finding)
            results.append(_result(finding))
        else:
            rule_id = _sast_rule_id(finding.finding.kind)
            if rule_id not in rules:
                rules[rule_id] = _sast_rule(finding)
            cwe = finding.finding.cwe
            if cwe not in cwes:
                cwes.append(cwe)
            results.append(_sast_result(finding))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "VulnAdvisor",
                "informationUri": _INFORMATION_URI,
                "version": tool_version,
                "rules": list(rules.values()),
            }
        },
        "properties": {"degraded_sources": list(degraded_sources)},
        "results": results,
    }
    if cwes:
        run["taxonomies"] = [_cwe_taxonomy(cwes)]

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def to_sarif_json(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
    sast_findings: Sequence[ScoredSastFinding] = (),
) -> str:
    """Render the SARIF log as a deterministic, ASCII-safe string."""
    log = build_sarif(
        findings, degraded_sources, tool_version=tool_version, sast_findings=sast_findings
    )
    return json.dumps(log, indent=2, ensure_ascii=True)
