# VulnAdvisor

> **Stop scanning, start triaging.**

VulnAdvisor is an open-source CLI that tells you which of your Python dependency
vulnerabilities are *actually reachable from your own code* — ranked by real-world exploit
likelihood (EPSS + CISA KEV) and explained in plain English.

It runs **locally**. Your source code never leaves your machine, and there is **no telemetry**.
Network calls are only to public vulnerability/risk APIs (OSV, GitHub Advisory, EPSS, CISA KEV)
and, optionally, your own LLM key.

## Status

Early scaffolding (milestone **M0**). Not yet usable — see [`task.md`](task.md) for the build
plan and [`PROGRESS.md`](PROGRESS.md) for current state.

## Requirements

- Python **3.12+**
- [uv](https://docs.astral.sh/uv/) for environment and dependency management

## Develop

```bash
uv sync                 # create the environment and install dev tooling
uv run ruff check       # lint
uv run ruff format --check
uv run mypy --strict src
uv run pytest
```

## Reachability tiers (the noise-killer)

Every finding carries a **confidence tier** — VulnAdvisor never gives a binary "reachable / not":

- `IMPORTED-AND-CALLED` — a concrete call path to the vulnerable symbol exists (function-level, coming in M6).
- `IMPORTED` — the package is imported by your code (evidence: the import site, `file:line`).
- `DYNAMIC-UNKNOWN` — dynamic import/exec, unreadable files, or an uncertain import-name mapping
  mean usage **cannot be ruled out**. Never treated as safe.
- `NOT-IMPORTED` — the package is never imported. The **only** confidently-safe tier; these are
  deprioritized and labeled "No path from your code".

Soundness is the rule: a false "you're safe" can cause a breach, so anything uncertain escalates
to `DYNAMIC-UNKNOWN` rather than being silently downgraded.

## Priority scoring (deterministic)

Priority is computed by code and is fully reproducible — no randomness, no clock, no I/O. The
optional LLM layer only *explains* a finding; it never changes the number.

Given a CVSS base severity (0–10), an EPSS exploit probability (0–1), and CISA KEV membership:

```
sev  = severity / 10
risk = 0.6 * epss + 0.4 * sev      # when EPSS is known
risk = sev                         # when EPSS is unknown (severity is not zeroed out)
value = round(100 * risk, 1)       # 0–100 priority
```

EPSS is weighted above severity because triage is about *real-world exploit likelihood* — that
is what removes the noise a severity-only scanner produces.

Soundness guards:

- **KEV dominates** — a vuln known-exploited in the wild is floored to **90** (CRITICAL),
  whatever the other signals say.
- **Unknown CVSS never means "ignore"** — it falls back to a moderate default severity (5.0),
  flagged as assumed, rather than being scored as 0.

Bands → verdicts:

| Score   | Band     | Verdict          |
|---------|----------|------------------|
| ≥ 90    | CRITICAL | Fix now          |
| 70–89.9 | HIGH     | Fix this sprint  |
| 40–69.9 | MEDIUM   | Plan a fix       |
| 15–39.9 | LOW      | Monitor          |
| < 15    | INFO     | Deprioritize     |

CVSS base scores are computed from the advisory's CVSS v3.x vector per the official
[CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document).

## Output formats & CI gating

`vulnadvisor scan PATH --format {terminal,json,sarif}`:

- **terminal** (default) — the three-card view.
- **json** — a stable machine report (`schema_version` 1.0). Top-level: `tool`,
  `degraded_sources`, `summary` (`total` + `by_band`), and `findings[]` (each with
  `dependency`, `advisory` incl. `cve_ids`/`cvss_base`, `epss`, `in_kev`, `score`, and `fix`
  with the minimal safe `fixed_version`, the exact `command`, and an `is_major_jump` flag).
  Findings are ordered by descending priority.
- **sarif** — valid **SARIF 2.1.0**, so results show up in the GitHub Security tab. Band maps to
  SARIF `level` (error/warning/note) and `security-severity` is set so GitHub orders by our
  triage priority.

`--fail-on <band|score>` sets the exit code: the scan exits **1** when any finding meets or
exceeds the threshold (a band name like `high`, or a number `0`–`100`), else **0**. Invalid
values are a usage error (exit 2). Example CI gate:

```bash
vulnadvisor scan . --format sarif --fail-on high > results.sarif
```

## License

Apache-2.0 (planned for the open-core engine).
