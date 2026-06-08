# VulnAdvisor — Instructions (standing rules for Claude Code)

> **What this file is:** the rules Claude Code follows on every session. It is paired with
> `task.md` (the sequential build plan). Read both at the start of each session.
>
> **Tip:** if you rename this file to `CLAUDE.md`, Claude Code loads it automatically every
> session. Either name is fine — your workflow already tells Claude Code to read it.

---

## How we work (the loop)
You build this product **one task at a time** with a validation gate after each task. The loop:

1. I say: *"Read instructions.md and task.md. Do Task X.Y only."*
2. You acknowledge with a 2–3 line plan, then implement **only that task** as complete files.
3. You run that task's **Validation Gate** yourself (the exact commands listed) and paste the results.
4. You update `PROGRESS.md` (what changed, why, open questions) and **stop**.
5. I review and say *"validated, next"* or *"fix X and re-validate."* You never start the next
   task until I confirm.

Do not jump ahead, batch multiple tasks, or start a later layer early. If a task is ambiguous,
ask 1–3 questions **before** coding.

---

## Mission & why we win
**Product:** the best **reachability engine for Python** — an open-source CLI that tells
developers which dependency vulnerabilities are *actually reachable from their own code*,
ranked by real-world exploit likelihood, explained in plain English.
**Motto:** stop scanning, start triaging.

The ASPM market is crowded (Snyk, Apiiro, Endor, Semgrep, etc.) and they all do "EPSS +
reachability." We do **not** win by having those features. We win on three things — protect
them in every decision:

1. **Python depth.** One ecosystem, understood better than any generalist tool.
2. **Developer trust.** Open-source, runs **locally** (source code never leaves the machine),
   **no telemetry**. This is a feature, not an afterthought.
3. **A compounding data moat** — our advisory→vulnerable-symbol dataset (see below).

## Product principles (non-negotiable)
- **Soundness over precision.** A false negative ("you're safe") can cause a breach. When
  uncertain, escalate — never silently downgrade a finding.
- **Never a binary "reachable / not."** Every finding carries a confidence tier:
  - `IMPORTED-AND-CALLED` — a concrete call path to the vulnerable symbol exists (highest concern)
  - `IMPORTED` — the vulnerable module/symbol is imported, no confirmed call
  - `DYNAMIC-UNKNOWN` — reflection / eval / dynamic import / framework magic blocks certainty
  - `NOT-IMPORTED` — the package is never imported (the only "confidently safe" tier)
- **Deterministic ranking.** Priority is computed by code and is reproducible. The LLM only
  *explains* a result; it never decides priority.
- **Show the evidence.** Always show *why* — the import site or the actual call path. Most
  competitors hide this; we make it the demo.
- **CI-native.** Machine-readable output (JSON + **SARIF** so it plugs into GitHub code
  scanning), meaningful exit codes, and `--fail-on <tier/score>` thresholds.
- **Privacy-first.** No analytics, no phoning home. Network calls are only to public vuln/risk
  APIs (OSV, EPSS, GHSA, KEV) and the user's own LLM key, and are clearly documented.

## Tech stack (all free / open source)
- **Python 3.12+** — we analyze Python, so we use its native `ast`, `importlib.metadata`, and
  the richest Python-analysis ecosystem. (Reach for Go/Rust later *only* if profiling demands it.)
- **uv** (env + deps), **Ruff** (lint + format), **mypy --strict**, **pytest** — all must pass to be "done."
- **Typer** (CLI) + **Rich** (the 3-card terminal output).
- **pydantic v2** for all structured models.
- Analysis: stdlib `ast` + import graph; **PyCG**-style call graphs; **Pyright** (`--outputjson`)
  for type-informed resolution (later).
- Free data APIs (cache locally): **OSV.dev**, **GitHub Advisory Database**, **EPSS** (FIRST.org),
  **CISA KEV**.
- **SQLite** for local cache/dataset. No Postgres until the hosted platform.
- **Anthropic API** for the plain-English layer only (key via `ANTHROPIC_API_KEY`).
- Distribution: **PyPI** (`pip install vulnadvisor` / `uvx vulnadvisor`), CI on **GitHub Actions**.
- Platform tier (post-traction only): **FastAPI** + **Postgres** + **Next.js/Tailwind/shadcn**
  (dark `#0d1117`). No Redis/K8s until load profiling proves the need.

## Repo structure (do not deviate without asking)
```
vulnadvisor/
  pyproject.toml          # uv-managed; Ruff + mypy + pytest config
  uv.lock
  README.md
  instructions.md         # this file (or CLAUDE.md)
  task.md                 # the build plan
  PROGRESS.md             # running log of state + decisions (update every task)
  src/vulnadvisor/
    __init__.py
    cli/                  # Typer app + Rich rendering of the 3 cards
    deps/                 # manifest parsing, dep resolution, package->import mapping
    advisories/           # OSV / GitHub Advisory / EPSS / KEV clients + cache
    symbols/              # patch -> vulnerable-symbol extraction (the data moat)
    callgraph/            # AST + import graph + (later) type-informed call graph
    reachability/         # demand-driven path search + confidence tiers
    engine/               # deterministic scoring + triage verdict
    output/               # JSON + SARIF + exit-code logic
    llm/                  # Anthropic explanation layer (optional enrichment)
    model/                # pydantic models shared across packages
    store/                # SQLite cache + dataset
  tests/                  # mirrors src/; table-driven where possible
  fixtures/               # tiny sample repos used as reachability test cases
  benchmarks/             # noise-reduction benchmarks vs naive scanners
```
## Git workflow and version control

### Push discipline (every session)
- **After every completed task** (when the Validation Gate passes and `PROGRESS.md` is updated):
  - Stage and commit: `git add -A && git commit -m "Task X.Y: <brief description>"`
  - Push to main: `git push origin main`
- This ensures:
  - Continuous snapshot of progress (no lost work if a session fails)
  - Real-time visibility into what changed and why (commit message = evidence)
  - Clean history for handoff between sessions or if you need to revert a task
- **Before starting a new session**, pull latest: `git pull origin main`

## Communication rules
- Acknowledge + short plan before a large unit; ask permission to proceed.
- **Complete files only** — no diffs / "# ...existing code..." unless I explicitly ask for a patch.
- First line of every code block is the exact path, e.g. `# File: src/vulnadvisor/epss/client.py`.
- Briefly explain non-obvious design choices (especially in `callgraph/` and `reachability/`).
- One task per turn. Don't switch layers (engine ↔ dashboard) unless I say so.

## Engineering standards
- No hardcoded secrets — `os.environ` only.
- No bare `except:`; no swallowed errors. Raise/return typed errors with context.
- **Defensive parsing** of ALL external data (OSV/EPSS JSON, fix-commit diffs, LLM output):
  validate, fall back to safe defaults, never crash on malformed input.
- Full type hints; `mypy --strict` clean. Docstrings on all public symbols.
- Core analysis is **pure and testable** — no hidden I/O inside parsing/graph/scoring.
- No new dependency without asking me to `uv add` it first. Pin versions.

## Definition of Done + validation gates
A task is **not done** until its specific Validation Gate in `task.md` passes **and** these global checks pass:
- `ruff check` and `ruff format --check` — clean
- `mypy --strict src` — clean
- `pytest` — green (incl. any new table-driven tests)
- For reachability/security tasks: the fixture suite shows **zero missed reachable findings**
  (false negatives are release-blocking) and the expected true-negatives are deprioritized.
- `PROGRESS.md` updated.
- **Git:** after Validation Gate passes, commit and push to the remote repo
  (this serves as the single source of truth for current state across sessions)

Run the gate commands yourself and paste the output. Don't claim done without showing the run.

## Session start
Read `instructions.md`, `task.md`, and `PROGRESS.md`, then reply exactly:
"VulnAdvisor protocol locked. PROGRESS.md read — current state: <one line>. Which task are we doing?"
