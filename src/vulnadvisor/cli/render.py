"""Render scored findings as the signature three-card terminal output (Rich).

Each finding — dependency (SCA) or first-party code (SAST) — is shown as three stacked cards:

* **Card A — Attack story/summary**: plain-English description (templated, or the LLM story for
  dependency findings when an explanation is supplied).
* **Card B — Risk**: a Red / Yellow / Green badge derived from the priority band, plus the
  deterministic scoring rationale.
* **Card C — Action**: the verdict, the priority, and either a copy-pasteable fix command (SCA) or
  the *remediation direction* (SAST — the validated fix is M17). For SAST the source->sink path is
  shown as evidence.

Dependency and code findings are merged into one priority-ranked list. Rendering is deterministic
and uses ASCII box art so output is stable for snapshot tests and safe on legacy Windows consoles.
"""

from collections.abc import Sequence
from io import StringIO

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from vulnadvisor.engine.safe_fix import resolve_safe_fix
from vulnadvisor.engine.sast_scoring import order_unified
from vulnadvisor.model.display import display_title
from vulnadvisor.model.explanation import Explanation, ExplanationSource
from vulnadvisor.model.score import PriorityBand, ScoredFinding
from vulnadvisor.output.remediation import fix_command
from vulnadvisor.sast.model import ScoredSastFinding
from vulnadvisor.sast.remediation import remediation_direction

__all__ = ["badge_for_band", "render_report", "render_to_string"]

_RED_BANDS = (PriorityBand.CRITICAL, PriorityBand.HIGH)
_MAX_SUMMARY_CHARS = 320


def badge_for_band(band: PriorityBand) -> str:
    """Map a priority band to a Red / Yellow / Green risk badge."""
    if band in _RED_BANDS:
        return "RED"
    if band is PriorityBand.MEDIUM:
        return "YELLOW"
    return "GREEN"


def _attack_summary(finding: ScoredFinding) -> str:
    """Build the templated Card A attack summary for a dependency finding."""
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


def _render_finding(finding: ScoredFinding, explanation: Explanation | None = None) -> Panel:
    """Render a single scored dependency finding as the outer panel wrapping three cards.

    When an ``explanation`` is supplied, Card A shows the LLM/template attack story and Card C adds
    a one-line "Why" rationale. The priority shown always comes from the deterministic score - the
    explanation is narrative only and cannot change it.
    """
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    score = finding.score

    badge = badge_for_band(score.band)
    safe_fix = resolve_safe_fix(dependency, advisory)
    command = fix_command(dependency, safe_fix)
    fix_line = f"Fix: {command}" if command is not None else "Fix: no fixed version available yet"

    reachability = finding.reachability
    if reachability is not None:
        reach_line = f"Reachability: {reachability.tier.value.upper()} - {reachability.reason}"
    else:
        reach_line = "Reachability: not analyzed"

    if explanation is not None:
        suffix = " (AI)" if explanation.source is ExplanationSource.LLM else ""
        card_a = _card(f"A - Attack story{suffix}", explanation.attack_story)
        why_line = f"\nWhy: {explanation.verdict_rationale}"
    else:
        card_a = _card("A - Attack summary", _attack_summary(finding))
        why_line = ""

    card_b = _card("B - Risk", f"Badge: {badge}\n{score.rationale}")
    card_c = _card(
        "C - Action",
        f"Verdict: {score.verdict}  (priority {score.value:.1f}, {score.band.value})\n"
        f"{fix_line}\n"
        f"{safe_fix.note}\n"
        f"{reach_line}"
        f"{why_line}",
    )

    header = f"{display_title(finding)}  |  priority {score.value:.1f} ({score.band.value})"
    return Panel(
        Group(card_a, card_b, card_c),
        title=header,
        title_align="left",
        box=box.ASCII,
        padding=(0, 1),
    )


def _render_sast_finding(scored: ScoredSastFinding) -> Panel:
    """Render a single scored first-party (SAST) finding as the three-card panel.

    Card C gives the *remediation direction* (the validated fix is M17) and shows the source->sink
    path as evidence; the priority always comes from the deterministic score.
    """
    finding = scored.finding
    score = scored.score
    badge = badge_for_band(score.band)

    location = f"{finding.file}:{finding.line}"
    card_a = _card(
        "A - Attack summary",
        f"{finding.title} ({finding.cwe}) at {location} via {finding.callee}.\n{finding.reason}",
    )
    card_b = _card("B - Risk", f"Badge: {badge}\n{score.rationale}")

    flow = finding.flow
    flow_line = f"Flow: {flow.render()}" if flow is not None else f"Sink: {location}"
    card_c = _card(
        "C - Action",
        f"Verdict: {score.verdict}  (priority {score.value:.1f}, {score.band.value})\n"
        f"Fix direction: {remediation_direction(finding.cwe)}\n"
        f"Tier: {finding.tier.value.upper()}\n"
        f"{flow_line}",
    )

    header = f"{finding.cwe} {finding.title}  |  priority {score.value:.1f} ({score.band.value})"
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
    explanations: Sequence[Explanation | None] | None = None,
    *,
    sast_findings: Sequence[ScoredSastFinding] = (),
) -> None:
    """Print the full ranked three-card report to ``console`` (dependency + code findings).

    ``explanations``, when given, is aligned by index with ``findings`` (the dependency findings);
    each supplies Card A's attack story. When omitted, Card A falls back to the inline templated
    summary. ``sast_findings`` are merged into the same priority-ranked list; an explanation never
    applies to a code finding (its Card A is always templated).
    """
    if degraded_sources:
        console.print(
            Text(
                f"! Degraded sources: {', '.join(degraded_sources)} - "
                "results may be incomplete; do not read as 'safe'."
            )
        )
    unified = order_unified([*findings, *sast_findings])
    if not unified:
        console.print(Text("No matching advisories found."))
        return

    # Pair each dependency finding with its explanation by object identity, so the merged ranking
    # (which interleaves SCA and SAST) keeps the right story on the right card.
    explanation_for = {
        id(finding): explanations[index]
        for index, finding in enumerate(findings)
        if explanations is not None and index < len(explanations)
    }

    console.print(Text(f"{len(unified)} finding(s), highest priority first:"))
    for finding in unified:
        if isinstance(finding, ScoredFinding):
            console.print(_render_finding(finding, explanation_for.get(id(finding))))
        else:
            console.print(_render_sast_finding(finding))


def render_to_string(
    findings: Sequence[ScoredFinding],
    degraded_sources: Sequence[str] = (),
    *,
    width: int = 100,
    explanations: Sequence[Explanation | None] | None = None,
    sast_findings: Sequence[ScoredSastFinding] = (),
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
    render_report(findings, degraded_sources, console, explanations, sast_findings=sast_findings)
    return buffer.getvalue()
