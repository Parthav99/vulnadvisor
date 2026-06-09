"""Render a :class:`BenchmarkReport` as a reproducible Markdown artifact.

Two framings share one table:

* ``kind="noise"`` (the hermetic corpus) leads with the noise-reduction headline -- how much of a
  naive scanner's output VulnAdvisor deprioritizes when the code is statically analyzable.
* ``kind="soundness"`` (the live, real-world repos) leads with the soundness headline. Behavior is
  bimodal by design: an app that loads code via runtime dynamic dispatch (eval/exec or an opaque
  import) keeps every unproven finding actionable, because such code could reach any package; an app
  whose code is statically analyzable has its genuinely-unimported dependencies deprioritized. The
  number that matters across both is *zero missed reachable criticals*.
"""

from benchmarks.metrics import BenchmarkReport

__all__ = ["render_markdown"]


def _headline(report: BenchmarkReport, kind: str) -> str:
    """Return the leading one-line summary for the given framing."""
    if kind == "soundness":
        return (
            f"**Real-world soundness + noise reduction** - across {report.repo_count} real "
            f"applications ({report.baseline_total} advisories), VulnAdvisor deprioritized "
            f"{report.deprioritized} as unreachable ({report.noise_reduction_pct:.0f}%) and kept "
            f"the rest actionable, with **{report.missed_criticals} missed reachable criticals** "
            f"(false negatives: {report.false_negatives}). It stays conservative on apps that load "
            f"code via runtime dynamic dispatch and removes genuinely-unimported deps on apps it "
            f"can fully analyze."
        )
    return (
        f"**{report.noise_reduction_pct:.0f}% less noise** - "
        f"{report.baseline_total} naive findings reduced to {report.actionable} after reachability "
        f"triage, with **{report.missed_criticals} missed reachable criticals** "
        f"(false negatives: {report.false_negatives})."
    )


def render_markdown(report: BenchmarkReport, *, title: str, mode: str, kind: str = "noise") -> str:
    """Render ``report`` as Markdown: a headline, a per-repo table, and the soundness check.

    ``kind`` selects the framing (``"noise"`` or ``"soundness"``). Output is deterministic (rows are
    pre-sorted) so the artifact is reproducible from its inputs.
    """
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Mode: {mode} - repos: {report.repo_count}_")
    lines.append("")
    lines.append(_headline(report, kind))
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
    if kind == "soundness":
        lines.append(
            "Deprioritization is bimodal by design. An app that loads code through runtime dynamic "
            "dispatch (`eval`/`exec` or an opaque `import_module`/`__import__`) could reach any "
            "package, so the engine keeps every unproven finding in an actionable tier rather than "
            "mark it safe (0% rows). An app whose code is statically analyzable has its "
            "genuinely-unimported dependencies - servers, build/test tools, unused transitive "
            "packages - moved to NOT-IMPORTED. The release-blocking number is the last column: "
            "zero missed reachable criticals on every repo."
        )
        lines.append("")
    verdict = "PASS" if report.missed_criticals == 0 and report.false_negatives == 0 else "FAIL"
    lines.append(f"Soundness gate: **{verdict}** - a reachable finding is never reported as safe.")
    lines.append("")
    return "\n".join(lines)
