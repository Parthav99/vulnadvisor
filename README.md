# VulnAdvisor

> **Stop scanning, start triaging.**

VulnAdvisor is an open-source CLI that tells you which of your Python dependency vulnerabilities
are *actually reachable from your own code* — ranked by real-world exploit likelihood (EPSS + CISA
KEV) and explained in plain English.

It runs **locally**. Your source code never leaves your machine, and there is **no telemetry**.
Network calls are only to public vulnerability/risk APIs (OSV, GitHub Advisory, EPSS, CISA KEV)
and, optionally, your own LLM key.

In our reproducible benchmark, reachability triage cuts a naive scanner's findings by **~54%** with
**zero missed reachable criticals** — see [`benchmarks/REPORT.md`](benchmarks/REPORT.md).

## Install

```bash
pip install vulnadvisor
# or run without installing:
uvx vulnadvisor --help
```

Requires **Python 3.12+**.

## Quickstart (under 5 minutes)

Point it at any Python project that has a `requirements.txt` (or a lockfile):

```bash
uvx vulnadvisor scan examples/quickstart
```

You'll get one **three-card** finding per vulnerability, highest priority first:

- **Card A — Attack story**: plain-English explanation specific to the finding.
- **Card B — Risk**: a Red/Yellow/Green badge from the EPSS+KEV-driven priority.
- **Card C — Action**: the verdict, the deterministic priority, the exact upgrade command, and the
  reachability tier with its evidence (the import site or, when known, the call path).

In the bundled [`examples/quickstart`](examples/quickstart), PyYAML is **imported and used**, so its
advisories are surfaced as `IMPORTED` with the import site — actionable. The declared-but-unused
`requests` is **deprioritized** (no path from your code). That split — flag what you use, demote
what you don't — is the triage.

> **Tip:** for the most precise `NOT-IMPORTED` verdicts, install VulnAdvisor into the *same*
> environment as your project (`pip install vulnadvisor` in your project venv) so it can read
> installed package metadata to map distributions to import names with high confidence. Run in
> isolation (`uvx`) and a dependency it can't confidently map stays the cautious `DYNAMIC-UNKNOWN`.

### Function-level call paths (`IMPORTED-AND-CALLED`)

The strongest tier — a concrete path from your code to the vulnerable symbol — needs the
advisory→vulnerable-symbol dataset. Build it once (queries OSV fix commits locally):

```bash
vulnadvisor backfill --top 50      # or: vulnadvisor backfill pyyaml jinja2 ...
```

When the symbol an advisory patched is one your code calls directly, the next scan upgrades the
finding to `IMPORTED-AND-CALLED` and prints the path (e.g. `main -> parse -> yaml.load`). Advisories
whose fix touches only library-*internal* symbols reached via a public API stay at `IMPORTED`
(sound: we never claim a call we can't prove) — improving that linkage is on the roadmap.

### Plain-English explanations (optional)

Card A uses a deterministic template by default. Export an Anthropic key to get an LLM-written
"attack story" (priority stays deterministic — the model only explains, it never changes the
number):

```bash
export ANTHROPIC_API_KEY=sk-...
vulnadvisor scan .            # Card A now reads like a senior engineer wrote it
vulnadvisor scan . --no-explain   # turn it off
```

## Reachability tiers (the noise-killer)

Every finding carries a **confidence tier** — VulnAdvisor never gives a binary "reachable / not":

- `IMPORTED-AND-CALLED` — a concrete call path to the vulnerable symbol exists (function-level).
- `IMPORTED` — the package is imported by your code (evidence: the import site, `file:line`).
- `DYNAMIC-UNKNOWN` — dynamic import/exec, reflection, unreadable files, or an uncertain
  import-name mapping mean usage **cannot be ruled out**. Never treated as safe.
- `NOT-IMPORTED` — the package is never imported. The **only** confidently-safe tier; these are
  deprioritized and labeled "No path from your code".

Soundness is the rule: a false "you're safe" can cause a breach, so anything uncertain escalates
to `DYNAMIC-UNKNOWN` rather than being silently downgraded. Reflective `getattr` dispatch is
resolved with optional Pyright type info, and framework-routed handlers (FastAPI routes, Django
URLconf views and `@receiver` signals) are recognized as entry points so the call path is rooted
at the real handler.

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

EPSS is weighted above severity because triage is about *real-world exploit likelihood*. Soundness
guards: **KEV dominates** (a known-exploited vuln is floored to **90/CRITICAL**), and an **unknown
CVSS** falls back to a moderate default (5.0, flagged) rather than being scored as 0.

Bands → verdicts:

| Score   | Band     | Verdict          |
|---------|----------|------------------|
| ≥ 90    | CRITICAL | Fix now          |
| 70–89.9 | HIGH     | Fix this sprint  |
| 40–69.9 | MEDIUM   | Plan a fix       |
| 15–39.9 | LOW      | Monitor          |
| < 15    | INFO     | Deprioritize     |

## Output formats & CI gating

`vulnadvisor scan PATH --format {terminal,json,sarif}`:

- **terminal** (default) — the three-card view.
- **json** — a stable machine report (`schema_version` 1.1): `tool`, `degraded_sources`, `summary`,
  and `findings[]` ordered by descending priority (each with dependency, advisory, EPSS, KEV,
  score, reachability + call paths, and the minimal safe fix command).
- **sarif** — valid **SARIF 2.1.0**, so results show up in the GitHub Security tab, ordered by our
  triage priority.

`--fail-on <band|score>` sets the exit code: the scan exits **1** when any finding meets or exceeds
the threshold (a band name like `high`, or a number `0`–`100`), else **0**. Invalid values are a
usage error (exit 2).

### GitHub Actions

```yaml
- name: VulnAdvisor reachability triage
  run: |
    pipx install vulnadvisor
    vulnadvisor scan . --format sarif --fail-on high > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Privacy

VulnAdvisor is built for environments where source code must not leave the machine:

- **No telemetry, no analytics, no phone-home.** Ever.
- Source code is analyzed **locally**; only dependency names/versions are sent to public advisory
  APIs (OSV, GitHub Advisory, EPSS, CISA KEV), cached in a local SQLite database.
- The optional LLM layer is the only call to a non-public service, uses **your own**
  `ANTHROPIC_API_KEY`, and sends only the finding metadata it needs to write the explanation. It is
  off unless you set the key, and `--no-explain` disables it entirely.

## Develop

```bash
uv sync
uv run ruff check && uv run ruff format --check
uv run mypy --strict src
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Run the noise-reduction benchmark with
`uv run python -m benchmarks`.

## License

[Apache-2.0](LICENSE). © VulnAdvisor contributors.
