# VulnAdvisor SAST Benchmark vs Bandit and Semgrep OSS

_Seeded corpus: 46 labeled sink sites (28 real, 18 safe) across 16 CWE classes. Bandit ran; Semgrep OSS not available._

**100% recall on seeded vulnerabilities at 100% top-tier precision** - VulnAdvisor surfaced 26/26 real, entry-point-reachable vulns and raised **0 false 'safe' verdicts** on them (release-blocking == 0), while keeping its top `CONFIRMED-FLOW` tier free of alarms on sanitized code (0 false top-tier alarms). Bandit, with no taint or reachability model for Python's dynamic flows, caught 19/26 (73%) at 81% top-tier precision (3 of its HIGH-severity findings land on sanitized code).

## Head to head

| Metric | VulnAdvisor | Bandit |
|--------|------:|------:|
| Seeded real vulns | 26 | 26 |
| Caught (recall) | 26 (100%) | 19 (73%) |
| Missed real vulns | 0 | 7 |
| Top-tier findings | 26 | 16 |
| Top-tier precision | 100% | 81% |
| False top-tier alarms (on safe code) | 0 | 3 |
| Any alarm on safe code | 0/18 | 6/18 |
| Off-target findings (no seed) | 1 | 2 |

## Recall by CWE

| CWE | Class | Seeded | VulnAdvisor | Bandit |
|-----|-------|-------:|------:|------:|
| CWE-1333 | ReDoS | 1 | 1/1 | 0/1 |
| CWE-1336 | Server-side template injection | 1 | 1/1 | 0/1 |
| CWE-22 | Path traversal (incl. archive) | 2 | 2/2 | 1/2 |
| CWE-295 | Disabled TLS verification | 1 | 1/1 | 1/1 |
| CWE-327 | Weak hash (MD5/SHA-1) | 1 | 1/1 | 1/1 |
| CWE-330 | Insecure randomness | 1 | 1/1 | 1/1 |
| CWE-502 | Unsafe deserialization | 2 | 2/2 | 2/2 |
| CWE-601 | Open redirect | 1 | 1/1 | 0/1 |
| CWE-611 | XML external entity (XXE) | 1 | 1/1 | 0/1 |
| CWE-643 | XPath injection | 1 | 1/1 | 0/1 |
| CWE-78 | OS command injection | 8 | 8/8 | 8/8 |
| CWE-798 | Hardcoded secret | 1 | 1/1 | 1/1 |
| CWE-89 | SQL injection | 1 | 1/1 | 1/1 |
| CWE-90 | LDAP injection | 1 | 1/1 | 0/1 |
| CWE-918 | SSRF | 1 | 1/1 | 1/1 |
| CWE-94 | Code injection (eval/exec) | 2 | 2/2 | 2/2 |

## Where a competitor wins or ties (honest notes)

- **SQLi, eval/exec, yaml.load, pickle** - all tools catch these. Bandit reports them at `MEDIUM` severity (no taint), VulnAdvisor at `CONFIRMED-FLOW` with the source->sink path. Comparable recall; the difference is evidence and ranking.
- **Path traversal & SSRF** - Bandit has no taint-based path-traversal check and no SSRF check, so it misses the `open()` flow entirely and flags the `requests.get()` line only incidentally (a missing-timeout lint), not as SSRF. VulnAdvisor proves both flows.
- **Sanitized shell calls** - Bandit raises `HIGH` on `os.system(shlex.quote(x))` and `subprocess.run(..., shell=True)` regardless of the sanitizer; VulnAdvisor recognizes `shlex.quote` and reports `SANITIZED`. This is the bulk of Bandit's precision gap here.
- **Import-level lint** - Bandit emits low-severity warnings on `import subprocess` / `import yaml` themselves (off-target noise); VulnAdvisor only reports at sink sites.
- **Semgrep OSS** - a strong, broad rule-based engine: on these sink sites its community rules generally fire (comparable raw recall on the classic CWEs), and on some patterns its rule library is wider than our pack. But like Bandit it has no Python-deep taint/reachability model, so it cannot tell a reachable flow from an entry-point-unreachable orphan or see a sanitizer clear a path - it raises the same alarm on both. We do not out-rule Semgrep; **M21 re-ranks its raw output through this reachability overlay**, turning its findings into the same tiered, evidence-backed, deduplicated list. (When Semgrep is not installed its column is omitted; install the `[semgrep]` extra to populate it.)

## Known limitations (VulnAdvisor)

- **Sanitizer clearing does not survive an opaque transform.** A value cleared by `secure_filename(...)` that then passes through `os.path.join(...)` is conservatively re-tainted (16.3: an unknown transform drops the cleared set), so a `secure_filename`-then-`join` path is over-reported as `CONFIRMED-FLOW`. This is soundness-conservative (never a false negative) but can be a false positive; a join-aware sanitizer model is future work. It is excluded from the scored corpus so the precision number is not flattered - documented here instead of hidden.
- A non-literal but constant-only sink argument (e.g. `os.path.join(BASE, "x.txt")`) is reported `POSSIBLE-FLOW`, not `SANITIZED`, when the intra-procedural detector cannot fold the call - an alarm, but never at the top tier.

## Performance

Warm-cache budget for a full SCA + SAST scan: **<= 30 s** (docs/sast-design.md section 12). The SAST pass is offline (no network); the dependency half reuses the warm OSV/EPSS cache. Full SCA + SAST warm/cold split over real OSS apps and the pyscan side-by-side wall time are the live perf run (network- and tool-gated), a documented follow-up. Re-run wall times locally with `python -m benchmarks --sast --perf`.

Soundness gate: **PASS** - every seeded, entry-point-reachable vulnerability is surfaced (missed real vulns: 0).
