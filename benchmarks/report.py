"""Render a :class:`BenchmarkReport` as a reproducible Markdown artifact."""

from benchmarks.metrics import BenchmarkReport

__all__ = ["render_markdown"]


def render_markdown(report: BenchmarkReport, *, title: str, mode: str) -> str:
    """Render ``report`` as Markdown: a headline, a per-repo table, and the soundness check.

    Output is deterministic (rows are pre-sorted) so the artifact is reproducible from its inputs.
    """
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Mode: {mode} - repos: {report.repo_count}_")
    lines.append("")
    lines.append(
        f"**{report.noise_reduction_pct:.0f}% less noise** - "
        f"{report.baseline_total} naive findings reduced to {report.actionable} after reachability "
        f"triage, with **{report.missed_criticals} missed reachable criticals** "
        f"(false negatives: {report.false_negatives})."
    )
    lines.append("")
    lines.append(
        "| Repo | Baseline | After triage | Deprioritized | Noise % | Reachable-called | "
        "Missed crit |"
    )
    lines.append(
        "|------|---------:|-------------:|--------------:|--------:|-----------------:|-----------:|"
    )
    for row in report.rows:
        lines.append(
            f"| {row.repo} | {row.baseline_total} | {row.actionable} | {row.deprioritized} | "
            f"{row.noise_reduction_pct:.0f}% | {row.reachable_called} | {row.missed_criticals} |"
        )
    lines.append(
        f"| **Total** | **{report.baseline_total}** | **{report.actionable}** | "
        f"**{report.deprioritized}** | **{report.noise_reduction_pct:.0f}%** | "
        f"**{report.reachable_called}** | **{report.missed_criticals}** |"
    )
    lines.append("")
    verdict = "PASS" if report.missed_criticals == 0 and report.false_negatives == 0 else "FAIL"
    lines.append(f"Soundness gate: **{verdict}** - a reachable finding is never reported as safe.")
    lines.append("")
    return "\n".join(lines)
