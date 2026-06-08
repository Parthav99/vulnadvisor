"""Render scored findings as the signature three-card terminal output (Rich).

Each finding is shown as three stacked cards:

* **Card A — Attack summary**: a plain-English description of the vulnerability (templated for
  now; an LLM "attack story" replaces this in M9).
* **Card B — Risk**: a Red / Yellow / Green badge derived from the EPSS+KEV-driven priority band,
  plus the deterministic scoring rationale.
* **Card C — Action**: the verdict, the priority, and a copy-pasteable fix command (the exact
  minimal-upgrade command arrives in Task 3.2; this is a templated upgrade for now).

Rendering is deterministic and uses ASCII box art so output is stable for snapshot tests and safe
on legacy Windows consoles.
"""

from collections.abc import Sequence
from io import StringIO

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.score import PriorityBand, ScoredFinding

__all__ = ["badge_for_band", "fix_command", "render_report", "render_to_string"]

_RED_BANDS = (PriorityBand.CRITICAL, PriorityBand.HIGH)
_MAX_SUMMARY_CHARS = 320


def badge_for_band(band: PriorityBand) -> str:
    """Map a priority band to a Red / Yellow / Green risk badge."""
    if band in _RED_BANDS:
        return "RED"
    if band is PriorityBand.MEDIUM:
        return "YELLOW"
    return "GREEN"


def fix_command(dependency: Dependency) -> str:
    """Return a templated upgrade command appropriate to the dependency's manifest type."""
    name = dependency.raw_name or dependency.name
    if dependency.source is DependencySource.POETRY_LOCK:
        return f"poetry update {name}"
    if dependency.source is DependencySource.PIPFILE_LOCK:
        return f"pipenv update {name}"
    return f"pip install --upgrade {name}"


def _attack_summary(finding: ScoredFinding) -> str:
    """Build the templated Card A attack summary."""
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"
    identifiers = ", ".join(advisory.cve_ids) or advisory.id
    lead = advisory.summary or advisory.details or "No description provided by the advisory."
    if len(lead) > _MAX_SUMMARY_CHARS:
        lead = lead[: _MAX_SUMMARY_CHARS - 3].rstrip() + "..."
    return f"{name} {version} is affected by {advisory.id} ({identifiers}).\n{lead}"


def _card(label: str, body: str) -> Panel:
    """Build one labeled inner card panel."""
    return Panel(Text(body), title=label, title_align="left", box=box.ASCII, padding=(0, 1))


def _render_finding(finding: ScoredFinding) -> Panel:
    """Render a single scored finding as the outer panel wrapping three cards."""
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    score = finding.score
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"

    badge = badge_for_band(score.band)
    card_a = _card("A - Attack summary", _attack_summary(finding))
    card_b = _card("B - Risk", f"Badge: {badge}\n{score.rationale}")
    card_c = _card(
        "C - Action",
        f"Verdict: {score.verdict}  (priority {score.value:.1f}, {score.band.value})\n"
        f"Fix: {fix_command(dependency)}\n"
        "Evidence: package-level match (reachability analysis not yet run)",
    )

    header = (
        f"{name} {version}  |  {advisory.id}  |  priority {score.value:.1f} ({score.band.value})"
    )
    return Panel(
        Group(card_a, card_b, card_c),
        title=header,
        title_align="left",
        box=box.ASCII,
        padding=(0, 1),
    )


def render_report(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str],
    console: Console,
) -> None:
    """Print the full ranked three-card report to ``console``."""
    if degraded_sources:
        console.print(
            Text(
                f"! Degraded sources: {', '.join(degraded_sources)} - "
                "results may be incomplete; do not read as 'safe'."
            )
        )
    if not findings:
        console.print(Text("No matching advisories found."))
        return
    console.print(Text(f"{len(findings)} finding(s), highest priority first:"))
    for finding in findings:
        console.print(_render_finding(finding))


def render_to_string(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str] = (),
    *,
    width: int = 100,
) -> str:
    """Render the report to a deterministic plain-text string (for snapshot tests)."""
    buffer = StringIO()
    console = Console(
        file=buffer,
        width=width,
        no_color=True,
        highlight=False,
        emoji=False,
        markup=False,
        legacy_windows=False,
    )
    render_report(findings, degraded_sources, console)
    return buffer.getvalue()
