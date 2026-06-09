"""Build the LLM prompt from a finding, and the deterministic template fallback.

The prompt hands the model everything the engine already computed — package, advisory, reachability
tier, the concrete call path, EPSS/KEV, and the deterministic verdict — and asks only for prose. The
model is told in no uncertain terms to return strict JSON and never to restate or change the
priority. :func:`templated_explanation` produces the same shape deterministically, so Card A always
renders even with no API key or a failed/garbled response.
"""

from vulnadvisor.model.explanation import Explanation, ExplanationSource
from vulnadvisor.model.reachability import ReachabilityTier
from vulnadvisor.model.score import ScoredFinding

__all__ = ["SYSTEM_PROMPT", "build_messages", "finding_context", "templated_explanation"]

SYSTEM_PROMPT = (
    "You are a senior application-security engineer helping a developer triage a dependency "
    "vulnerability. You are given facts already computed by a deterministic engine. Your job is "
    "ONLY to explain, in plain English, how this vulnerability could realistically be exploited "
    "given the reachability evidence, and to give a one-line rationale for the verdict.\n\n"
    "Rules:\n"
    "- Respond with STRICT JSON and nothing else: "
    '{"attack_story": "<2-4 sentences>", "verdict_rationale": "<one sentence>"}.\n'
    "- Be specific to the call path and tier. Do not invent functions, versions, or CVEs.\n"
    "- You MUST NOT change, recompute, or propose a different priority/score - it is fixed. The "
    "verdict_rationale explains the given verdict; it never overrides it.\n"
    "- If reachability is NOT-IMPORTED, make clear the package is not used and the risk is low.\n"
    "- No markdown, no code fences, no preamble - JSON only."
)

_TIER_PHRASE = {
    ReachabilityTier.IMPORTED_AND_CALLED: "a concrete call path reaches the vulnerable symbol",
    ReachabilityTier.IMPORTED: "the package is imported but no vulnerable call is confirmed",
    ReachabilityTier.DYNAMIC_UNKNOWN: "dynamic dispatch prevents confirming or ruling out a call",
    ReachabilityTier.NOT_IMPORTED: "the package is never imported in this codebase",
}


def finding_context(finding: ScoredFinding) -> str:
    """Render the engine's facts about ``finding`` as a compact, unambiguous context block."""
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    score = finding.score
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"
    identifiers = ", ".join(advisory.cve_ids) or advisory.id

    lines = [
        f"Package: {name} {version}",
        f"Advisory: {advisory.id} ({identifiers})",
        f"Summary: {advisory.summary or advisory.details or 'n/a'}",
        f"EPSS probability: {_fmt_epss(score.epss_probability)}",
        f"In CISA KEV (known exploited): {'yes' if score.in_kev else 'no'}",
        f"Deterministic verdict: {score.verdict} "
        f"(priority {score.value:.1f}, band {score.band.value})",
    ]
    reachability = finding.reachability
    if reachability is not None:
        lines.append(f"Reachability tier: {reachability.tier.value} - {reachability.reason}")
        if reachability.call_paths:
            lines.append(f"Call path: {reachability.call_paths[0].render()}")
    else:
        lines.append("Reachability tier: not analyzed")
    return "\n".join(lines)


def build_messages(finding: ScoredFinding) -> tuple[str, str]:
    """Return the ``(system, user)`` prompt pair for ``finding``."""
    user = (
        "Explain this finding for a developer. Facts (do not contradict them):\n\n"
        f"{finding_context(finding)}\n\n"
        'Return only: {"attack_story": "...", "verdict_rationale": "..."}'
    )
    return SYSTEM_PROMPT, user


def _fmt_epss(probability: float | None) -> str:
    """Format an EPSS probability as a percentage, or 'unknown'."""
    if probability is None:
        return "unknown"
    return f"{probability * 100:.1f}%"


def templated_explanation(finding: ScoredFinding) -> Explanation:
    """Build a deterministic explanation from the engine's facts (the always-available fallback)."""
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    score = finding.score
    name = dependency.raw_name or dependency.name
    version = dependency.version or "(unpinned)"
    identifiers = ", ".join(advisory.cve_ids) or advisory.id
    summary = advisory.summary or advisory.details or "No description provided by the advisory."

    tier = finding.reachability.tier if finding.reachability is not None else None
    tier_phrase = _TIER_PHRASE.get(tier) if tier is not None else "reachability was not analyzed"
    story = f"{name} {version} is affected by {advisory.id} ({identifiers}). {summary} "
    story += f"In this project, {tier_phrase}."
    if finding.reachability is not None and finding.reachability.call_paths:
        story += f" Path: {finding.reachability.call_paths[0].render()}."

    signal = "in CISA KEV" if score.in_kev else f"EPSS {_fmt_epss(score.epss_probability)}"
    rationale = (
        f"{score.verdict}: priority {score.value:.1f} ({score.band.value}), "
        f"driven by {signal} and the reachability tier."
    )
    return Explanation(
        attack_story=story.strip(),
        verdict_rationale=rationale,
        source=ExplanationSource.TEMPLATE,
    )
