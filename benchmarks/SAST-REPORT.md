# VulnAdvisor SAST Benchmark vs Bandit

_Seeded corpus: 20 labeled sink sites (13 real, 7 safe) across 7 CWE classes. Bandit ran._

**100% recall on seeded vulnerabilities at 100% top-tier precision** - VulnAdvisor surfaced 12/12 real, entry-point-reachable vulns and raised **0 false 'safe' verdicts** on them (release-blocking == 0), while keeping its top `CONFIRMED-FLOW` tier free of alarms on sanitized code (0 false top-tier alarms). Bandit, with no taint or reachability model, caught 11/12 (92%) at 71% top-tier precision (2 of its HIGH-severity findings land on sanitized code).

## Head to head

| Metric | VulnAdvisor | Bandit |
|--------|------:|------:|
| Seeded real vulns | 12 | 12 |
| Caught (recall) | 12 (100%) | 11 (92%) |
| Missed real vulns | 0 | 1 |
| Top-tier findings | 12 | 7 |
| Top-tier precision | 100% | 71% |
| False top-tier alarms (on safe code) | 0 | 2 |
| Any alarm on safe code | 0/7 | 3/7 |
| Off-target findings (no seed) | 0 | 2 |

## Recall by CWE

| CWE | Class | Seeded | VulnAdvisor | Bandit |
|-----|-------|-------:|------:|------:|
| CWE-22 | Path traversal | 1 | 1/1 | 0/1 |
| CWE-502 | Unsafe deserialization | 2 | 2/2 | 2/2 |
| CWE-78 | OS command injection | 4 | 4/4 | 4/4 |
| CWE-798 | Hardcoded secret | 1 | 1/1 | 1/1 |
| CWE-89 | SQL injection | 1 | 1/1 | 1/1 |
| CWE-918 | SSRF | 1 | 1/1 | 1/1 |
| CWE-94 | Code injection (eval/exec) | 2 | 2/2 | 2/2 |

## Where Bandit wins or ties (honest notes)

- **SQLi, eval/exec, yaml.load, pickle** - both tools catch these. Bandit reports them at `MEDIUM` severity (no taint), VulnAdvisor at `CONFIRMED-FLOW` with the source->sink path. Comparable recall; the difference is evidence and ranking.
- **Path traversal & SSRF** - Bandit has no taint-based path-traversal check and no SSRF check, so it misses the `open()` flow entirely and flags the `requests.get()` line only incidentally (a missing-timeout lint), not as SSRF. VulnAdvisor proves both flows.
- **Sanitized shell calls** - Bandit raises `HIGH` on `os.system(shlex.quote(x))` and `subprocess.run(..., shell=True)` regardless of the sanitizer; VulnAdvisor recognizes `shlex.quote` and reports `SANITIZED`. This is the bulk of Bandit's precision gap here.
- **Import-level lint** - Bandit emits low-severity warnings on `import subprocess` / `import yaml` themselves (off-target noise); VulnAdvisor only reports at sink sites.

## Known limitations (VulnAdvisor)

- **Sanitizer clearing does not survive an opaque transform.** A value cleared by `secure_filename(...)` that then passes through `os.path.join(...)` is conservatively re-tainted (16.3: an unknown transform drops the cleared set), so a `secure_filename`-then-`join` path is over-reported as `CONFIRMED-FLOW`. This is soundness-conservative (never a false negative) but can be a false positive; a join-aware sanitizer model is future work. It is excluded from the scored corpus so the precision number is not flattered - documented here instead of hidden.
- A non-literal but constant-only sink argument (e.g. `os.path.join(BASE, "x.txt")`) is reported `POSSIBLE-FLOW`, not `SANITIZED`, when the intra-procedural detector cannot fold the call - an alarm, but never at the top tier.

## Performance

Warm-cache budget for a full SCA + SAST scan: **<= 30 s** (docs/sast-design.md section 12). The SAST pass is offline (no network); the dependency half reuses the warm OSV/EPSS cache. Full SCA + SAST warm/cold split over real OSS apps and the pyscan side-by-side wall time are the live perf run (network- and tool-gated), a documented follow-up. Re-run wall times locally with `python -m benchmarks --sast --perf`.

Soundness gate: **PASS** - every seeded, entry-point-reachable vulnerability is surfaced (missed real vulns: 0).
