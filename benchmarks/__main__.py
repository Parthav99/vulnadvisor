"""Run the benchmark and write the Markdown report.

``python -m benchmarks``         -> hermetic corpus (default, no network) -> benchmarks/REPORT.md
``python -m benchmarks --live``  -> pinned public repos via OSV + VulnAdvisor (needs network)
``python -m benchmarks --out X`` -> write the report to path X
"""

import argparse
import tempfile
from pathlib import Path

from benchmarks.corpus import run_corpus
from benchmarks.manifest import MANIFEST, run_live
from benchmarks.metrics import build_report
from benchmarks.report import render_markdown

_DEFAULT_OUT = Path(__file__).resolve().parent / "REPORT.md"


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
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT, help="Where to write the report.")
    args = parser.parse_args()

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
    args.out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"\nWrote {args.out}")
    return 0 if report.missed_criticals == 0 and report.false_negatives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
