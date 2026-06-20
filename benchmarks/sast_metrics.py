"""Pure metric models for the SAST benchmark — no I/O, no engine, fully unit-testable.

The SCA benchmark (:mod:`benchmarks.metrics`) measures *noise reduction* over a naive dependency
scanner. The SAST benchmark measures something sharper: on a **ground-truth-labeled** corpus of
first-party code, how each tool does on the two numbers that matter for first-party security —

* **recall** on real, seeded vulnerabilities (a missed real vuln is release-blocking), and
* **top-tier precision** — of the findings a tool presents as *most serious*
  (VulnAdvisor ``CONFIRMED-FLOW`` / Bandit ``HIGH`` severity / Semgrep ``ERROR``), how many are real
  vs. noise raised on safe or unreachable code.

That second number is the whole pitch: Bandit and Semgrep OSS have no taint/reachability model for
Python's dynamic flows, so they raise their loudest alarm on sanitized and entry-point-unreachable
sinks; VulnAdvisor deprioritizes those to ``SANITIZED`` / ``POSSIBLE-FLOW`` and keeps
``CONFIRMED-FLOW`` for proven flows. (The M21 fusion milestone *re-ranks* Semgrep's raw output
through this same reachability overlay; this benchmark forward-references it by measuring Semgrep
side by side here.)

The metric code is deliberately tool-agnostic: each tool's "is this an alarm / is this its top
tier" judgment is a small per-tool predicate on :class:`Detection`, so adding Semgrep OSS alongside
Bandit is a predicate and a label, never new metric math.

Ground truth lives in the corpus source as ``# seed:`` marker comments, parsed here, so the labels
sit next to the code they describe and survive edits (no hand-maintained line numbers).
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

__all__ = [
    "EXPECT_POSSIBLE",
    "EXPECT_SAFE",
    "EXPECT_VULN",
    "TOOL_BANDIT",
    "TOOL_SEMGREP",
    "TOOL_VULNADVISOR",
    "CweRecall",
    "Detection",
    "SastBenchmarkReport",
    "Seed",
    "ToolMetrics",
    "build_sast_report",
    "compute_cwe_recall",
    "compute_tool_metrics",
    "parse_seeds",
]

# Ground-truth expectation for a seeded sink site.
EXPECT_VULN = "vuln"  # a real, entry-point-reachable vulnerability — must be caught (gate)
EXPECT_SAFE = "safe"  # sanitized or literal-only — must NOT be a top-tier alarm
EXPECT_POSSIBLE = "possible"  # a real sink not reachable from any entry point — deprioritized
_EXPECTATIONS = frozenset({EXPECT_VULN, EXPECT_SAFE, EXPECT_POSSIBLE})

TOOL_VULNADVISOR = "vulnadvisor"
TOOL_BANDIT = "bandit"
TOOL_SEMGREP = "semgrep"

# VulnAdvisor's tier value that means "we believe this is safe" — the only outcome that counts as a
# *miss* on a real vuln. Mirrors NOT_IMPORTED on the SCA side.
_VA_SAFE_TIER = "sanitized"
# The top tier each tool uses for "most serious"; top-tier precision is measured over these.
_VA_TOP_TIER = "confirmed-flow"
_BANDIT_TOP_SEVERITY = "HIGH"
_SEMGREP_TOP_SEVERITY = "ERROR"

# `# seed: CWE-78 vuln` / `# seed: CWE-502 safe note="yaml.safe_load"`
_SEED_RE = re.compile(
    r"#\s*seed:\s*(?P<cwe>CWE-\d+)\s+(?P<expect>vuln|safe|possible)(?:\s+note=\"(?P<note>[^\"]*)\")?"
)


@dataclass(frozen=True)
class Seed:
    """One ground-truth sink site in the corpus: where it is, its CWE, and what should happen.

    ``expect`` is the verdict a sound, reachability-aware engine should reach (see the ``EXPECT_*``
    constants). The marker comment lives on the same physical line as the sink call, so ``line``
    aligns with where both tools anchor their finding.
    """

    case: str
    file: str
    line: int
    cwe: str
    expect: str
    note: str = ""

    @property
    def is_real(self) -> bool:
        """Whether this is a genuine vulnerability (a tool *should* surface it somehow)."""
        return self.expect in {EXPECT_VULN, EXPECT_POSSIBLE}


@dataclass(frozen=True)
class Detection:
    """One normalized finding from a tool, anchored to a file/line for matching against seeds.

    ``label`` is the tool's own severity word — VulnAdvisor's tier value (``"confirmed-flow"`` …),
    Bandit's severity (``"HIGH"`` …), or Semgrep's (``"ERROR"`` …) — interpreted by the small
    per-tool predicates below so the metric code stays tool-agnostic.
    """

    tool: str
    file: str
    line: int
    cwe: str
    label: str

    @property
    def is_alarm(self) -> bool:
        """Whether the tool is raising this as something to look at (not a 'safe' verdict).

        Bandit and Semgrep have no safe tier — every result is an alarm. VulnAdvisor's ``SANITIZED``
        is the one outcome that is *not* an alarm (it is the engine saying "covered on every path").
        """
        if self.tool == TOOL_VULNADVISOR:
            return self.label != _VA_SAFE_TIER
        return True

    @property
    def is_top(self) -> bool:
        """Whether this is the tool's *most serious* tier (where top-tier precision is measured)."""
        if self.tool == TOOL_VULNADVISOR:
            return self.label == _VA_TOP_TIER
        if self.tool == TOOL_SEMGREP:
            return self.label == _SEMGREP_TOP_SEVERITY
        return self.label == _BANDIT_TOP_SEVERITY


def parse_seeds(case: str, file: str, source: str) -> tuple[Seed, ...]:
    """Extract the ground-truth :class:`Seed`s from a corpus file's ``# seed:`` marker comments.

    Pure: a line carrying a well-formed marker yields one seed at that 1-based line number;
    malformed or absent markers are simply ignored.
    """
    seeds: list[Seed] = []
    for index, text in enumerate(source.splitlines(), start=1):
        match = _SEED_RE.search(text)
        if match is None:
            continue
        expect = match.group("expect")
        if expect not in _EXPECTATIONS:  # pragma: no cover - regex already constrains this
            continue
        seeds.append(
            Seed(
                case=case,
                file=file,
                line=index,
                cwe=match.group("cwe"),
                expect=expect,
                note=match.group("note") or "",
            )
        )
    return tuple(seeds)


def _matches(seed: Seed, detection: Detection) -> bool:
    """Whether ``detection`` lands on ``seed`` (same file and line).

    CWE agreement is reported elsewhere, not required here: a tool that flags the right line for a
    different stated reason still 'found' the seeded site.
    """
    return detection.file == seed.file and detection.line == seed.line


@dataclass(frozen=True)
class ToolMetrics:
    """Per-tool aggregate over the seeded corpus (all counts derived, deterministic)."""

    tool: str
    vuln_total: int
    caught_vuln: int
    possible_total: int
    safe_total: int
    top_on_real: int
    top_on_safe: int
    alarms_on_safe: int
    unmatched_findings: int

    @property
    def missed_vuln(self) -> int:
        """Real, entry-point-reachable vulns the tool failed to surface (release-blocking == 0)."""
        return self.vuln_total - self.caught_vuln

    @property
    def recall_pct(self) -> float:
        """Percentage of seeded real vulnerabilities the tool surfaced."""
        if self.vuln_total == 0:
            return 0.0
        return 100.0 * self.caught_vuln / self.vuln_total

    @property
    def top_total(self) -> int:
        """Findings the tool placed in its most-serious tier, matched to a seed."""
        return self.top_on_real + self.top_on_safe

    @property
    def top_precision_pct(self) -> float:
        """Of the tool's most-serious findings, the percentage that land on a real vuln."""
        if self.top_total == 0:
            return 100.0
        return 100.0 * self.top_on_real / self.top_total


def compute_tool_metrics(
    tool: str, seeds: Sequence[Seed], detections: Sequence[Detection]
) -> ToolMetrics:
    """Compute one tool's :class:`ToolMetrics` from ground-truth ``seeds`` and its ``detections``.

    Pure and total: every count is a fold over the inputs, so the same inputs always yield the same
    numbers (the reproducibility the gate requires). Detections are deduplicated by location so a
    tool that reports a line twice is not double-counted.
    """
    own = {(d.file, d.line, d.cwe, d.label) for d in detections if d.tool == tool}
    deduped = tuple(Detection(tool, f, ln, cwe, label) for (f, ln, cwe, label) in sorted(own))

    vuln_seeds = [s for s in seeds if s.expect == EXPECT_VULN]
    possible_seeds = [s for s in seeds if s.expect == EXPECT_POSSIBLE]
    safe_seeds = [s for s in seeds if s.expect == EXPECT_SAFE]

    caught_vuln = sum(1 for s in vuln_seeds if any(_matches(s, d) and d.is_alarm for d in deduped))
    alarms_on_safe = sum(
        1 for s in safe_seeds if any(_matches(s, d) and d.is_alarm for d in deduped)
    )

    top_on_real = 0
    top_on_safe = 0
    matched_locations: set[tuple[str, int]] = set()
    for detection in deduped:
        hit_real = any(_matches(s, detection) for s in seeds if s.is_real)
        hit_safe = any(_matches(s, detection) for s in safe_seeds)
        if hit_real or hit_safe:
            matched_locations.add((detection.file, detection.line))
        if detection.is_top:
            if hit_real:
                top_on_real += 1
            elif hit_safe:
                top_on_safe += 1
    unmatched = sum(1 for d in deduped if (d.file, d.line) not in matched_locations)

    return ToolMetrics(
        tool=tool,
        vuln_total=len(vuln_seeds),
        caught_vuln=caught_vuln,
        possible_total=len(possible_seeds),
        safe_total=len(safe_seeds),
        top_on_real=top_on_real,
        top_on_safe=top_on_safe,
        alarms_on_safe=alarms_on_safe,
        unmatched_findings=unmatched,
    )


@dataclass(frozen=True)
class CweRecall:
    """Per-CWE recall on real vulnerabilities: how many each tool caught, by CWE."""

    cwe: str
    vuln_total: int
    caught: tuple[tuple[str, int], ...]  # (tool, caught_count) pairs, tool-ordered

    def caught_for(self, tool: str) -> int:
        """Return how many of this CWE's real vulns ``tool`` surfaced."""
        for name, count in self.caught:
            if name == tool:
                return count
        return 0


def compute_cwe_recall(
    tools: Sequence[str], seeds: Sequence[Seed], detections: Sequence[Detection]
) -> tuple[CweRecall, ...]:
    """Per-CWE recall on the real (``vuln``) seeds for each tool (deterministic, CWE-ordered)."""
    vuln_seeds = [s for s in seeds if s.expect == EXPECT_VULN]
    cwes = sorted({s.cwe for s in vuln_seeds})
    rows: list[CweRecall] = []
    for cwe in cwes:
        cwe_seeds = [s for s in vuln_seeds if s.cwe == cwe]
        caught = tuple(
            (
                tool,
                sum(
                    1
                    for s in cwe_seeds
                    if any(_matches(s, d) and d.is_alarm for d in detections if d.tool == tool)
                ),
            )
            for tool in tools
        )
        rows.append(CweRecall(cwe=cwe, vuln_total=len(cwe_seeds), caught=caught))
    return tuple(rows)


@dataclass(frozen=True)
class SastBenchmarkReport:
    """The full SAST benchmark result: seeds, per-tool metrics, and which comparators ran."""

    seeds: tuple[Seed, ...]
    metrics: tuple[ToolMetrics, ...]
    cwe_recall: tuple[CweRecall, ...]
    bandit_available: bool
    semgrep_available: bool = False

    def for_tool(self, tool: str) -> ToolMetrics | None:
        """Return the metrics for ``tool``, or ``None`` if that tool was not run."""
        for metric in self.metrics:
            if metric.tool == tool:
                return metric
        return None

    @property
    def missed_seeded_vulns(self) -> int:
        """VulnAdvisor's missed real vulns — the release-blocking number (must be zero)."""
        va = self.for_tool(TOOL_VULNADVISOR)
        return va.missed_vuln if va is not None else 0


def build_sast_report(
    seeds: Iterable[Seed],
    detections: Sequence[Detection],
    *,
    bandit_available: bool,
    semgrep_available: bool = False,
) -> SastBenchmarkReport:
    """Assemble the report: VulnAdvisor always; a comparator only when it was available to run."""
    ordered_seeds = tuple(sorted(seeds, key=lambda s: (s.file, s.line, s.cwe)))
    tools = (
        [TOOL_VULNADVISOR]
        + ([TOOL_BANDIT] if bandit_available else [])
        + ([TOOL_SEMGREP] if semgrep_available else [])
    )
    metrics = tuple(compute_tool_metrics(tool, ordered_seeds, detections) for tool in tools)
    cwe_recall = compute_cwe_recall(tools, ordered_seeds, detections)
    return SastBenchmarkReport(
        ordered_seeds, metrics, cwe_recall, bandit_available, semgrep_available
    )
