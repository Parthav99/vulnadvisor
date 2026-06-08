"""Emit SARIF 2.1.0 so findings surface in GitHub code scanning (Security tab).

We emit one ``rule`` per advisory id and one ``result`` per finding. ``level`` maps the priority
band (error / warning / note), and ``properties["security-severity"]`` is set so GitHub orders
findings by our triage priority. Locations point at the manifest the dependency came from; precise
code locations arrive with reachability (M4+).
"""

import json
from collections.abc import Sequence
from typing import Any

from vulnadvisor.model.dependency import DependencySource
from vulnadvisor.model.score import PriorityBand, ScoredFinding

__all__ = ["SARIF_SCHEMA_URI", "SARIF_VERSION", "build_sarif", "to_sarif_json"]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/your-org/vulnadvisor"

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


def _security_severity(finding: ScoredFinding) -> str:
    """0-10 severity string GitHub reads: the CVSS base if known, else priority/10."""
    score = finding.score
    value = score.cvss_base if score.cvss_base is not None else round(score.value / 10.0, 1)
    return f"{value:.1f}"


def _rule(finding: ScoredFinding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) for a finding's advisory."""
    advisory = finding.matched.advisory
    return {
        "id": advisory.id,
        "name": "VulnerableDependency",
        "shortDescription": {"text": advisory.summary or advisory.id},
        "helpUri": f"https://osv.dev/vulnerability/{advisory.id}",
        "properties": {"security-severity": _security_severity(finding)},
    }


def _result(finding: ScoredFinding) -> dict[str, Any]:
    """Build a SARIF result for a single finding."""
    dependency = finding.matched.dependency
    advisory = finding.matched.advisory
    score = finding.score
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"
    summary = advisory.summary or "No description provided by the advisory."
    uri = _MANIFEST_FILENAMES.get(dependency.source, "environment")
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
        },
    }


def build_sarif(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object for the given findings."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.matched.advisory.id
        if rule_id not in rules:
            rules[rule_id] = _rule(finding)
        results.append(_result(finding))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
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
        ],
    }


def to_sarif_json(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    *,
    tool_version: str,
) -> str:
    """Render the SARIF log as a deterministic, ASCII-safe string."""
    log = build_sarif(findings, degraded_sources, tool_version=tool_version)
    return json.dumps(log, indent=2, ensure_ascii=True)
