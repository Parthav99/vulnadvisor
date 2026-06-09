"""Run the benchmark and write the Markdown report.

``python -m benchmarks``         -> hermetic corpus (default, no network) -> benchmarks/REPORT.md
``python -m benchmarks --live``  -> pinned public repos via pip-audit + VulnAdvisor (needs network)
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
        with tempfile.TemporaryDirectory(prefix="vulnadvisor-bench-live-") as tmp:
            rows = [run_live(spec, Path(tmp)) for spec in MANIFEST]
        report = build_report(rows)
        title, mode = "VulnAdvisor Benchmark (live)", "live (pinned public repos)"
    else:
        report = run_corpus()
        title, mode = "VulnAdvisor Benchmark (hermetic)", "hermetic (synthetic corpus)"

    markdown = render_markdown(report, title=title, mode=mode)
    args.out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"\nWrote {args.out}")
    return 0 if report.missed_criticals == 0 and report.false_negatives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
