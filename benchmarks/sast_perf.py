"""Wall-time measurement for the SAST benchmark's Performance section.

The reproducible *accuracy* benchmark lives in :mod:`benchmarks.sast_corpus`; this module measures
*speed*. Two parts:

* :func:`measure_sast_perf` — fully offline and runnable in the gate: it times the real
  :func:`~vulnadvisor.sast.analyze_taint` pass over the seeded corpus and over VulnAdvisor's own
  ``src/`` tree (the largest analyzable repo on hand). These are the numbers the report publishes
  for the SAST half of the budget.
* :func:`pyscan_wall_time` — best-effort: runs the ``pyscan`` binary if it is on ``PATH`` (the
  Rust-rival comparison the task asks for), else returns ``None`` so the row reads "n/a". The full
  SCA + SAST warm/cold split over real OSS apps is the live perf run (network + tool-gated),
  documented as a deferred follow-up rather than executed in the gate.

Wall times are inherently non-deterministic, so nothing here feeds the reproducible accuracy table;
they are rendered in a clearly separated section of the report.
"""

import shutil
import subprocess  # noqa: S404 - fixed argv, never shell=True; invokes pyscan only
import tempfile
import time
from pathlib import Path

from benchmarks.sast_corpus import CORPUS
from benchmarks.sast_report import PerfRow
from vulnadvisor.sast import analyze_taint

__all__ = ["measure_sast_perf", "pyscan_available", "pyscan_wall_time"]

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "vulnadvisor"


def _time_analyze(root: Path) -> float:
    """Return the wall-clock seconds for one :func:`analyze_taint` pass over ``root``."""
    start = time.perf_counter()
    analyze_taint(root)
    return time.perf_counter() - start


def measure_sast_perf() -> list[PerfRow]:
    """Time the offline SAST pass over the seeded corpus and over VulnAdvisor's own ``src/``."""
    rows: list[PerfRow] = []
    with tempfile.TemporaryDirectory(prefix="vulnadvisor-sast-perf-") as tmp:
        root = Path(tmp)
        files = 0
        for case in CORPUS:
            for rel, source in case.files.items():
                target = root / case.name / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
                files += 1
        rows.append(PerfRow("SAST over the seeded corpus", _time_analyze(root), f"{files} files"))
    if _SRC_DIR.is_dir():
        src_files = sum(1 for _ in _SRC_DIR.rglob("*.py"))
        rows.append(
            PerfRow(
                "SAST over VulnAdvisor's own src/", _time_analyze(_SRC_DIR), f"{src_files} files"
            )
        )
    return rows


def pyscan_available() -> bool:
    """Whether the ``pyscan`` binary is on ``PATH`` (the optional Rust-rival comparison)."""
    return shutil.which("pyscan") is not None


def pyscan_wall_time(path: Path, *, timeout: int = 300) -> float | None:
    """Return ``pyscan``'s wall time scanning ``path``, or ``None`` if it is unavailable/failed."""
    if not pyscan_available():
        return None
    start = time.perf_counter()
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["pyscan", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode not in (0, 1):  # 1 = findings present, still a successful scan
        return None
    return time.perf_counter() - start
