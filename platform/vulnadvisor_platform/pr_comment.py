"""Render the PR diff comment (pure) — the 3-card reachability triage for a pull request.

Given the findings introduced (and the count fixed) between the base and head scans, produce a
Markdown comment. A hidden marker lets the GitHub client find and update its own comment instead
of posting a new one each push. Soundness: anything not provably ``not-imported`` is shown.
"""

from typing import Any

from vulnadvisor.model.display import select_display_id

MARKER = "<!-- vulnadvisor:pr -->"

# Tiers that are not the confidently-safe "not-imported" — i.e. worth surfacing on a PR.
_REACHABLE_TIERS = frozenset({"imported-and-called", "imported", "dynamic-unknown"})
_CALLED_TIER = "imported-and-called"


def _tier(finding: dict[str, Any]) -> str:
    reachability = finding.get("reachability")
    if isinstance(reachability, dict):
        tier = reachability.get("tier")
        if isinstance(tier, str):
            return tier
    return "unknown"


def _priority(finding: dict[str, Any]) -> float:
    score = finding.get("score")
    if isinstance(score, dict) and isinstance(score.get("value"), (int, float)):
        return float(score["value"])
    return 0.0


def _display_id(finding: dict[str, Any]) -> str:
    """The CVE-first display identifier for a finding payload.

    Prefers the report's own ``advisory.display_id`` (schema 1.1+); for older reports it is
    computed from the raw id + aliases with the same canonical rule.
    """
    advisory = finding.get("advisory")
    if not isinstance(advisory, dict):
        return "—"
    explicit = advisory.get("display_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    raw_id = advisory.get("id")
    if not isinstance(raw_id, str) or not raw_id:
        return "—"
    aliases = advisory.get("aliases")
    return select_display_id(raw_id, aliases if isinstance(aliases, list) else ())


def _cell(finding: dict[str, Any], *keys: str) -> str:
    node: Any = finding
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    return str(node) if node not in (None, "") else "—"


def render_pr_comment(
    *, introduced: list[dict[str, Any]], fixed_count: int, repo: str, pr_number: int
) -> str:
    """Render the PR comment Markdown for the given introduced findings + fixed count."""
    reachable = [f for f in introduced if _tier(f) in _REACHABLE_TIERS or _tier(f) == "unknown"]
    called = sum(1 for f in introduced if _tier(f) == _CALLED_TIER)

    lines = [MARKER, "## VulnAdvisor — reachability triage", ""]
    if not reachable:
        lines.append(
            f"No new reachable vulnerable dependencies in this PR. "
            f"{fixed_count} finding(s) fixed. :white_check_mark:"
        )
        return "\n".join(lines)

    lines.append(
        f"**{len(reachable)} new reachable finding(s)** "
        f"({called} with a confirmed call path) · {fixed_count} fixed."
    )
    lines.append("")
    lines.append("| Package | Advisory | Tier | Priority | Fix |")
    lines.append("|---|---|---|---|---|")
    for finding in sorted(reachable, key=_priority, reverse=True)[:10]:
        pkg = _cell(finding, "dependency", "name")
        version = _cell(finding, "dependency", "version")
        advisory = _display_id(finding)
        tier = _tier(finding)
        priority = _priority(finding)
        band = _cell(finding, "score", "band")
        fix = _cell(finding, "fix", "command")
        lines.append(
            f"| `{pkg} {version}` | {advisory} | {tier} | {priority:.0f} ({band}) | {fix} |"
        )

    lines.append("")
    lines.append(
        f"<sub>Reachability-first triage for `{repo}` #{pr_number}. "
        "Only findings VulnAdvisor cannot prove unreachable are shown.</sub>"
    )
    return "\n".join(lines)
