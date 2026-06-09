"""Benchmark harness: prove the core claim — less noise, zero missed reachable criticals.

A naive scanner (``pip-audit``) flags *every* advisory affecting a declared dependency. VulnAdvisor
adds reachability triage: advisories whose package is never imported are deprioritized
(``NOT_IMPORTED``), the rest stay actionable. The harness quantifies the gap as a **% noise
reduction** and, critically, verifies **zero reachable criticals were dropped** (a false negative is
release-blocking).

Two modes share one report:

* **hermetic** (:mod:`benchmarks.corpus`) — a deterministic synthetic corpus exercised through the
  real reachability engine; no network, runs in CI, ground-truth labels make the false-negative
  check exact.
* **live** (:mod:`benchmarks.manifest`) — pinned-commit public repos scanned with real ``pip-audit``
  and VulnAdvisor to produce the published artifact.
"""

from benchmarks.metrics import AdvisoryOutcome, BenchmarkReport, RepoResult, is_actionable

__all__ = ["AdvisoryOutcome", "BenchmarkReport", "RepoResult", "is_actionable"]
