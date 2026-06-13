"""Run the benchmark and write the Markdown report.

``python -m benchmarks``          -> hermetic SCA corpus (no network)   -> benchmarks/REPORT.md
``python -m benchmarks --live``   -> pinned public repos (needs network) -> benchmarks/REPORT.md
``python -m benchmarks --sast``   -> seeded SAST corpus vs Bandit       -> SAST-REPORT.md
``python -m benchmarks --sast --perf`` -> also measure SAST wall time (offline)
``python -m benchmarks --out X``  -> write the report to path X
"""

import argparse
import sys
import tempfile
from pathlib import Path

from benchmarks.corpus import run_corpus
from benchmarks.manifest import MANIFEST, run_live
from benchmarks.metrics import build_report
from benchmarks.report import render_markdown
from benchmarks.sast_corpus import run_sast_corpus
from benchmarks.sast_report import render_sast_markdown

_DEFAULT_OUT = Path(__file__).resolve().parent / "REPORT.md"
_DEFAULT_SAST_OUT = Path(__file__).resolve().parent / "SAST-REPORT.md"


def _print_safe(text: str) -> None:
    """Print to a console whose encoding may not be UTF-8 (Windows cp1252) without crashing.

    The report is always written to disk as UTF-8; the console echo must never turn a successful
    run into a non-zero exit (the Task 14.1 lesson).
    """
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="replace").decode(encoding))


def _run_live_all() -> list:  # type: ignore[type-arg]
    """Run every manifest repo live, printing per-repo progress (the run is long)."""
    from benchmarks.manifest import _wheel_path

    wheel = _wheel_path()
    rows = []
    with tempfile.TemporaryDirectory(prefix="vulnadvisor-bench-live-") as tmp:
        for index, spec in enumerate(MANIFEST, start=1):
            print(f"[{index}/{len(MANIFEST)}] {spec.name} @ {spec.ref} ...", flush=True)
            row = run_live(spec, Path(tmp), wheel)
            print(
                f"    baseline={row.baseline_total} actionable={row.actionable} "
                f"deprioritized={row.deprioritized} noise={row.noise_reduction_pct:.0f}% "
                f"fn={row.false_negatives}",
                flush=True,
            )
            rows.append(row)
    return rows


def main() -> int:
    """Parse arguments, run the selected benchmark mode, and write the report."""
    parser = argparse.ArgumentParser(
        prog="benchmarks", description="VulnAdvisor noise-reduction benchmark"
    )
    parser.add_argument(
        "--live", action="store_true", help="Run pinned public repos (needs network)."
    )
    parser.add_argument("--sast", action="store_true", help="Run the seeded SAST corpus vs Bandit.")
    parser.add_argument(
        "--perf",
        action="store_true",
        help="With --sast: also measure SAST wall time (offline).",
    )
    parser.add_argument("--out", type=Path, default=None, help="Where to write the report.")
    args = parser.parse_args()

    if args.sast:
        return _run_sast(args.out, measure_perf=args.perf)

    out = args.out or _DEFAULT_OUT
    if args.live:
        rows = _run_live_all()
        report = build_report([r for r in rows if r.baseline_total > 0])
        title, mode, kind = (
            "VulnAdvisor Benchmark (live)",
            "live (pinned public repos)",
            "soundness",
        )
    else:
        report = run_corpus()
        title, mode, kind = (
            "VulnAdvisor Benchmark (hermetic)",
            "hermetic (synthetic corpus)",
            "noise",
        )

    markdown = render_markdown(report, title=title, mode=mode, kind=kind)
    out.write_text(markdown, encoding="utf-8")
    _print_safe(markdown)
    print(f"\nWrote {out}")
    return 0 if report.missed_criticals == 0 and report.false_negatives == 0 else 1


def _run_sast(out: Path | None, *, measure_perf: bool) -> int:
    """Run the seeded SAST corpus vs Bandit, write SAST-REPORT.md, return the gate exit code."""
    report = run_sast_corpus()
    perf = None
    if measure_perf:
        from benchmarks.sast_perf import measure_sast_perf

        perf = measure_sast_perf()
    markdown = render_sast_markdown(report, perf=perf)
    target = out or _DEFAULT_SAST_OUT
    target.write_text(markdown, encoding="utf-8")
    _print_safe(markdown)
    print(f"\nWrote {target}")
    if not report.bandit_available:
        print("NOTE: Bandit was not available - comparison columns omitted.")
    # Release-blocking: VulnAdvisor must miss zero seeded, entry-point-reachable vulnerabilities.
    return 0 if report.missed_seeded_vulns == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
