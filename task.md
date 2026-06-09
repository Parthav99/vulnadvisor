# VulnAdvisor — Build Plan (task.md)

The sequential plan to build VulnAdvisor from empty repo to a fundable open-source product.
Read `Claude.md` first — it holds the rules, stack, and the confidence-tier definitions
referenced throughout.

## How to drive this with Claude Code
Work **one task at a time**:
1. `Read Claude.md and task.md. Do Task X.Y only.`
2. Claude builds it as complete files, then runs the task's **Validation Gate** and pastes the output.
3. You review. If green → `validated, next`. If not → `fix <X> and re-validate`.
4. Repeat until the milestone's release tag is reached, then move to the next milestone.

Each task has: **Goal** (why), **Build** (what to make), **Validate** (the gate that must pass
before moving on), **Done when** (exit condition). The global Definition of Done in
`Claude.md` also applies to every task (ruff + mypy + pytest clean, PROGRESS.md updated).

## Release map (value ships early, moat builds over time)
- **M0** Scaffolding
- **M1** Dependency inventory
- **M2** Vuln matching + deterministic ranking + 3-card output → **v0.1 (beats Dependabot)**
- **M3** CI-native output: JSON + SARIF + exit codes + safe-fix suggestion → **v0.2 (adoptable in CI)**
- **M4** Reachability v1 (package + import level, tiered) → **v0.3 (the noise-killer)**
- **M5** Vulnerable-symbol dataset (the moat)
- **M6** Reachability v2 (function-level, demand-driven, show the call path)
- **M7** Precision: Pyright type inference + framework plugins
- **M8** Benchmark harness + published report (the fundraising proof)
- **M9** LLM "attack story" layer → **v1.0**
- **M10** Launch — package/docs ✅ · live benchmark ✅ → **dynamic-import fix (real-app noise unlock)** → publish to PyPI → post (HN/r/Python)
- **M11** Platform (FastAPI + Postgres + Next.js, free-hostable) — **gated: only after M10 launch + real CLI traction**

---

## M0 — Scaffolding

### Task 0.1 — Repo + toolchain
**Goal:** a clean, enforced foundation so every later task is auto-checked.
**Build:** `pyproject.toml` (uv-managed) with Ruff, mypy strict, pytest configured; the full
empty package tree from `Claude.md` (each module has `__init__.py` + one-line docstring);
`README.md` (one-liner + run instructions); `PROGRESS.md` initialized; `.gitignore`.
**Validate:**
- [ ] `uv sync` succeeds
- [ ] `ruff check` and `ruff format --check` clean
- [ ] `mypy --strict src` clean
- [ ] `uv run pytest` runs (0 tests OK)
**Done when:** repo builds clean and the tree matches `Claude.md`.

### Task 0.2 — CLI skeleton + CI
**Goal:** a runnable entrypoint and automated checks from day one.
**Build:** Typer app exposing `vulnadvisor scan PATH [--public/--internal] [--fail-on ...]`
that prints a stub; `--version`; a GitHub Actions workflow running ruff + mypy + pytest on push.
**Validate:**
- [ ] `uv run vulnadvisor scan . ` prints the stub and exits 0
- [ ] `uv run vulnadvisor --version` works
- [ ] CI workflow file is valid YAML and mirrors local checks
**Done when:** the CLI runs and CI is wired.

---

## M1 — Dependency inventory

### Task 1.1 — Manifest parsers
**Goal:** know exactly which packages+versions a project uses.
**Build:** `deps/` parsers for `requirements.txt`, `pyproject.toml`, `poetry.lock`,
`Pipfile.lock`; normalize to `Dependency(name, version, source, is_direct)` pydantic models.
Fall back to the installed environment via `importlib.metadata` when no lockfile exists.
**Validate:**
- [ ] Table-driven tests with a fixture for each manifest format pass
- [ ] Handles missing/duplicate/pinned-vs-range entries without crashing (tested)
**Done when:** all four formats parse to a normalized list.

### Task 1.2 — Package → import-name mapping
**Goal:** avoid missing vulnerabilities because the install name ≠ import name.
**Build:** resolver mapping distribution names to import names using `importlib.metadata`
(`top_level.txt`/RECORD) plus a curated fallback table (e.g. `PyYAML→yaml`,
`beautifulsoup4→bs4`, `scikit-learn→sklearn`, `Pillow→PIL`). Record confidence per mapping.
**Validate:**
- [ ] Tests cover ≥10 tricky real-world name mappings
- [ ] Unknown packages degrade gracefully (best-guess + low-confidence flag), no crash
**Done when:** each dependency resolves to its import name(s) with a confidence flag.

---

## M2 — Vuln matching + deterministic ranking → v0.1

### Task 2.1 — Advisory clients (OSV, EPSS, KEV) with cache
**Goal:** pull the same risk data the incumbents use, for free.
**Build:** `advisories/` clients — OSV batch query by package+version; EPSS lookup; CISA KEV
membership. SQLite cache in `store/` with TTL. Strict defensive parsing; safe fallbacks if an
API is down (degraded mode, clearly flagged).
**Validate:**
- [ ] Tests run against recorded fixture responses (no live network in tests)
- [ ] Malformed/empty payloads handled without crashing (tested)
- [ ] Second run hits cache (assert no network call)
**Done when:** a dependency list yields matched advisories + EPSS + KEV flags.

### Task 2.2 — Deterministic scoring engine
**Goal:** a reproducible priority — the heart of "triage, not scan."
**Build:** `engine/` pure function combining base severity (CVSS), EPSS probability, and KEV
membership into a documented, reproducible priority + verdict label ("Fix this sprint", etc.).
Document the formula in code and README.
**Validate:**
- [ ] Same inputs always produce the same score (property test)
- [ ] Table-driven tests cover boundary cases (KEV present, EPSS high/low, no CVSS)
**Done when:** findings are sorted by a deterministic, explained priority.

### Task 2.3 — 3-card terminal output (Rich)
**Goal:** the signature UX, even before reachability.
**Build:** `cli/` renders each finding as Card A (attack summary — templated for now),
Card B (Red/Yellow/Green badge from EPSS+KEV), Card C (verdict + exact fix command).
**Validate:**
- [ ] `vulnadvisor scan <fixture-project>` shows ranked 3-card output
- [ ] Snapshot test of rendered output for a fixture project
**Done when (release v0.1):** the CLI ranks real vulns by EPSS+KEV with plain verdicts —
already more useful than Dependabot. Tag v0.1.

---

## M3 — CI-native output → v0.2

### Task 3.1 — JSON + SARIF output and exit codes
**Goal:** drop into existing pipelines and GitHub code scanning (a real adoption lever).
**Build:** `output/` emitters for `--format json` and `--format sarif` (valid SARIF 2.1.0 so
results show in GitHub Security tab); `--fail-on <tier|score>` controlling exit code.
**Validate:**
- [ ] Emitted SARIF validates against the SARIF 2.1.0 schema (tested)
- [ ] JSON schema is stable + documented; snapshot tested
- [ ] Exit code is non-zero exactly when findings exceed `--fail-on` (tested)
**Done when:** output is machine-consumable and CI-gating works.

### Task 3.2 — Safe-fix version resolution
**Goal:** tell users the *minimal* upgrade that fixes it, not just "upgrade."
**Build:** for each finding, compute the nearest non-vulnerable version from the advisory's
fixed ranges and produce the exact `pip`/`uv`/`poetry` command. Flag when no fix exists yet.
**Validate:**
- [ ] Tests cover: fix available, no fix yet, and major-version-jump cases
- [ ] Suggested command is copy-pasteable and correct for the detected manifest type
**Done when (release v0.2):** Card C gives a concrete, minimal remediation. Tag v0.2.

---

## M4 — Reachability v1 (package + import level) → v0.3

### Task 4.1 — Import graph of first-party code
**Goal:** the foundation of all reachability.
**Build:** `callgraph/` walks the project with `ast`, collecting every import (aliases,
`from` imports, relative imports) mapped back to distributions via M1.2. Detect dynamic-import
constructs (`importlib`, `__import__`, `eval`/`exec`) and record their locations.
**Validate:**
- [ ] Tests assert correct imports for fixtures using aliases + relative + dynamic imports
- [ ] Dynamic-import sites are detected and recorded (tested)
**Done when:** we have a reliable import map with dynamic-usage flags.

### Task 4.2 — Tiering (NOT-IMPORTED / IMPORTED / DYNAMIC-UNKNOWN)
**Goal:** kill the bulk of the noise, soundly.
**Build:** `reachability/` assigns each finding a tier per `Claude.md`:
`NOT-IMPORTED` (confidently safe) → `IMPORTED` → `DYNAMIC-UNKNOWN` (when dynamic-import sites
could hide usage). Wire tiers into `engine/` so NOT-IMPORTED is deprioritized and labeled
"no path from your code." Show the import site (file:line) as evidence.
**Validate (security-critical gate):**
- [ ] Fixture A (imports a vulnerable pkg) → `IMPORTED`, stays high priority
- [ ] Fixture B (declares dep, never imports) → `NOT-IMPORTED`, deprioritized
- [ ] Fixture C (dynamic import) → `DYNAMIC-UNKNOWN`, **not** silently downgraded
- [ ] **Zero false negatives** across the fixture suite (release-blocking)
**Done when (release v0.3):** noise is cut at package/import level with sound tiers and shown
evidence. Tag v0.3 — this is the first version that delivers the core promise.

---

## M5 — Vulnerable-symbol dataset (the moat)

### Task 5.1 — Fix-commit → vulnerable-symbol extraction
**Goal:** the proprietary data needed for function-level reachability.
**Build:** `symbols/` fetches an advisory's linked fix commit(s) from OSV/GHSA, diffs the patch,
and extracts the changed functions/classes/methods as candidate vulnerable symbols. Record
provenance + a confidence score. Degrade gracefully when no fix link exists.
**Validate:**
- [ ] On ≥5 hand-verified real advisories, extracted symbols match the known fix
- [ ] Advisories without clean fix links are handled (recorded as symbol-unknown), no crash
**Done when:** we can produce `advisory → [symbols]` with confidence.

### Task 5.2 — Dataset store + backfill
**Goal:** make the dataset reusable and growing.
**Build:** persist `advisory_id → symbols (+provenance)` in SQLite; a `backfill` command to
populate the top-N PyPI packages; a refresh path for new advisories.
**Validate:**
- [ ] Backfill on a small package set populates the store; re-runs are idempotent (tested)
- [ ] Lookups by advisory are fast and covered by tests
**Done when:** the symbol dataset exists and can grow over time.

---

## M6 — Reachability v2 (function-level, demand-driven)

### Task 6.1 — Demand-driven call-graph + path search
**Goal:** the differentiating "is the vulnerable function actually called?" answer.
**Build:** `callgraph/` builds a PyCG-style graph **lazily**, seeded from the vulnerable
symbols (M5) and the project's entry points, searching for a path between them — never a whole-
program graph. `reachability/` emits `IMPORTED-AND-CALLED` when a concrete path exists and
**records the path** for display. Crossing a dynamic feature downgrades to `DYNAMIC-UNKNOWN`,
never drops the finding.
**Validate (security-critical gate):**
- [ ] Fixture with a real call path → `IMPORTED-AND-CALLED` + correct path shown
- [ ] Fixture importing but never calling the symbol → `IMPORTED` (not escalated)
- [ ] Dynamic-dispatch / decorator fixtures → `DYNAMIC-UNKNOWN`, never silently dropped
- [ ] **Zero false negatives** on the expanded fixture suite (release-blocking)
**Done when:** function-level reachability works and shows the call path as evidence.

### Task 6.2 — Incremental caching
**Goal:** fast CI re-runs.
**Build:** cache analysis keyed on file content hashes so unchanged files aren't re-analyzed.
**Validate:**
- [ ] Re-run with no code change is materially faster (assert cache hits)
- [ ] Editing one file invalidates only the affected slice (tested)
**Done when:** repeat scans are fast enough for CI on every PR.

---

## M7 — Precision: types + frameworks

### Task 7.1 — Pyright type-informed resolution
**Goal:** cut false positives from dynamic dispatch without sacrificing soundness.
**Build:** optionally run `pyright --outputjson`; use inferred types to resolve which method is
actually called instead of over-approximating all same-named methods. Degrade cleanly if
Pyright isn't installed.
**Validate:**
- [ ] On dynamic-dispatch fixtures, false positives drop vs M6 (measured, tested)
- [ ] With Pyright absent, behavior falls back to the sound over-approximation (tested)
**Done when:** precision improves measurably with no new false negatives.

### Task 7.2 — Framework plugins (start with two)
**Goal:** handle calls routed through frameworks, where naive tools fail. (Confirm which two
with me first — likely Django + FastAPI.)
**Build:** a framework-plugin interface + two implementations that teach the engine how the
framework registers/dispatches code (routes, views, signals, tasks).
**Validate:**
- [ ] A framework-routed reachable vuln is detected for each supported framework (fixtures)
- [ ] Plugins are isolated (disabling one doesn't affect the other), tested
**Done when:** framework-routed reachability is covered for the first two frameworks.

---

## M8 — Benchmark (the fundraising proof)

### Task 8.1 — Benchmark harness + published report
**Goal:** prove the core claim with numbers — this becomes the launch post and the pitch slide.
**Build:** `benchmarks/` runs VulnAdvisor and a baseline (`pip-audit`) over a set of public
Python repos and reports: total findings, findings after triage, **% noise reduction**, true
positives, and **any false negatives**. Output a reproducible markdown report.
**Validate:**
- [ ] Harness runs end-to-end on ≥10 public repos and produces the report
- [ ] Report is reproducible (pinned repo commits) and shows zero missed reachable criticals
**Done when:** you have a credible, reproducible "X% less noise, zero missed criticals" artifact.

---

## M9 — LLM "attack story" layer → v1.0

### Task 9.1 — Plain-English explanation (deterministic priority preserved)
**Goal:** Card A that reads like a senior engineer explained it — specific to the found path.
**Build:** `llm/` takes the already-computed finding + tier + call path + EPSS/KEV and calls the
Anthropic API to produce the attack story + a one-line verdict rationale. Priority stays
deterministic from `engine/`. Strict output validation; templated fallback on API failure;
cache by finding hash; key from `ANTHROPIC_API_KEY`.
**Validate:**
- [ ] Tests use a mocked client; malformed LLM output falls back to the template (tested)
- [ ] The LLM never changes the numeric priority (asserted)
**Done when (release v1.0):** the full 3-card experience is live and trustworthy. Tag v1.0.

---

## M10 — Launch

### Task 10.1 — Package, document, publish  ✅ done (2026-06-09)
**Goal:** make adoption frictionless (the open-core engine).
**Build:** PyPI packaging (`pip install vulnadvisor` / `uvx vulnadvisor`); a docs site or rich
README (quickstart, CI snippet, output formats, privacy statement); CONTRIBUTING + license
(permissive core, e.g. Apache-2.0); a launch blog post built around the M8 benchmark.
**Validate:**
- [ ] Clean install in a fresh environment works end-to-end (tested in CI)
- [ ] Docs quickstart reproduces a real scan in under 5 minutes
**Done when:** it's installable, documented, and ready to post to HN / r/Python.

> **M10.1 status:** ✅ done — packaging, Apache-2.0, README/CONTRIBUTING/CHANGELOG, launch post draft,
> `release.yml` (PyPI Trusted Publishing on `v*` tags). NOT yet published to PyPI (that's 10.5).

### Task 10.2 — Live benchmark on real public repos  ✅ done (2026-06-09)
**Goal:** replace the synthetic 54% with real numbers we can publish. The hermetic corpus proves
*correctness*; a launch/fundraising claim needs *real repos*.
**Build:** run the existing `python -m benchmarks --live` over the pinned-commit manifest of real
public repos (confirm each repo's manifest path first — many use `pyproject.toml`). Record
VulnAdvisor vs `pip-audit`: total findings, post-triage, % noise reduction, reachable-called, and any
false negatives. Regenerate `benchmarks/REPORT.md` and update `docs/launch-post.md` with the real
figures; keep the hermetic run as the soundness proof.
**Validate:**
- [ ] `--live` runs end-to-end on ≥10 real repos and writes a real-data REPORT.md
- [ ] The launch post quotes the *live* numbers, not the synthetic ones
- [ ] Any false negative on real repos is investigated before publishing (release-blocking)
**Done when:** the headline claim is backed by a reproducible run on real public code.

> **M10.2 status:** ✅ done (commit `7200b3d`) — live run over 10 real apps, **996 OSV advisories, 0
> false negatives, 0 missed criticals**. Baseline switched to OSV-direct (pip-audit can't build
> decade-old wheels). Key finding: **0% deprioritization on real apps** (dynamic plugin loaders poison
> every verdict) and **0 IMPORTED-AND-CALLED** across all 996 — so 10.3 below is the gate before
> launch. See `benchmarks/REPORT.live.md`.

### Task 10.3 — First-party dynamic-import resolution (the real-app noise unlock)
**Goal:** make noise reduction real on real code. The live run deprioritized **0%** because a single
dynamic-import site (a plugin loader) forces the engine to treat every package as possibly-used. But
most loaders only import *first-party* modules (redash's loaders reach `redash.*`), so unused
third-party deps should still be NOT-IMPORTED.
**Build:** in `callgraph`/`reachability`, classify each dynamic-import site by whether it can be
*proven* to target only first-party modules (e.g. `import_module(f"redash.{x}")`, package-relative
loaders, `__path__`-based plugin discovery inside the project). A provably first-party-only site no
longer escalates third-party deps to DYNAMIC-UNKNOWN — genuinely-unimported third-party packages
return to NOT-IMPORTED. Any site whose target can't be proven first-party-only stays conservative, as
today. Soundness rule unchanged: when in doubt, escalate.
**Validate (security-critical gate):**
- [ ] New fixtures: a first-party-only loader → unused third-party dep is NOT-IMPORTED; a loader with
  a non-first-party / uncertain target → still DYNAMIC-UNKNOWN.
- [ ] Re-run `python -m benchmarks --live`: real apps now show meaningful deprioritization, with
  **false negatives still 0 and missed criticals still 0** (release-blocking).
- [ ] Hermetic benchmark unchanged; ruff / format / `mypy --strict src` / pytest all green.
**Done when:** the live benchmark shows real noise reduction on real apps with zero false negatives —
the 'noise-killer' headline holds on real code, not just the synthetic corpus.

### Task 10.4 — (optional, recommended) Strengthen the IMPORTED-AND-CALLED demo
**Goal:** make the call-path demo fire on real advisories, not only when the user calls the patched
symbol directly. (The live run produced **0** IMPORTED-AND-CALLED across 996 real advisories — closing
this is what makes the marquee call-path demo actually fire on real code.)
**Build:** connect public-API entry → library-internal vulnerable symbol (the Task 6.1 limitation:
e.g. PyYAML `yaml.load` → `construct_python_object_new`). Either a small per-library
public-API→internal-symbol map for the top advisories, or a shallow intra-library call graph seeded
from the public entry. Stay sound — never emit AND-CALLED without a real path.
**Validate:**
- [ ] On ≥3 real advisories reached via a public API, the scan shows the full call path
- [ ] Zero new false AND-CALLED (soundness gate)
**Done when:** the marquee demo works on common real-world cases. *Recommended before launch for a
stronger demo, but not release-blocking — the tool is honest about this gap today.*

### Task 10.5 — Publish to PyPI + go live
**Goal:** real traction — the thing M11 is gated on. **Gated on 10.3** (don't post the 'noise-killer'
message until real-app noise reduction holds).
**Build:** reserve the `vulnadvisor` name on PyPI; configure Trusted Publishing for the `pypi`
environment; confirm the final GitHub repo slug in `pyproject.toml` URLs; push a `v1.0` tag to trigger
`release.yml`. Add GitHub issue/PR templates + a lightweight feedback path (a `feedback` label /
Discussions). Post to r/Python and Hacker News linking the live benchmark.
**Validate:**
- [ ] The post-10.3 live benchmark shows real noise reduction with 0 false negatives (launch-blocking)
- [ ] The launch post leads with the *real* live numbers (and only then the hermetic figure)
- [ ] `pip install vulnadvisor` / `uvx vulnadvisor` works from PyPI on a fresh machine
- [ ] The release workflow published the wheel + sdist on the tag
- [ ] Launch posts are live and point to the repo + live benchmark
**Done when:** anyone can install it and the launch is public. (Publishing is irreversible — the
maintainer pushes the tag.)

---

## M11 — Platform (GATED: only after M10 launch + real CLI traction)

> **Gate:** do not start Task 11.2 until M10 (live benchmark + publish + launch) is done and there is
> demonstrated CLI adoption. The platform monetizes *teams* after developers already use the CLI.
> **Core stance:** source never leaves customer infra by default — the CI/CLI/self-hosted runner
> uploads the `scan --format json` report; the platform stores findings + metadata, **never source**.
> Cloud-side scanning is explicit opt-in. Full design: `docs/platform-design.md` (APPROVED 2026-06-09).
>
> **Free to build and host:** Next.js on **Vercel** (free), Postgres on **Neon/Supabase** (free tier),
> backend on **Fly.io/Render** free tier, dev via **docker-compose**. No paid infra until load demands it.

### Task 11.1 — API surface design (plan-first)  ✅ approved
**Done:** `docs/platform-design.md` — the `/v1` REST surface, Postgres data model,
bring-your-own-analysis default, and the 11.2–11.8 breakdown. Approved 2026-06-09; build gated behind launch.

### Task 11.2 — Backend skeleton + data model
**Build:** FastAPI app; SQLAlchemy 2.x models + Alembic migration for
`orgs/users/memberships/repositories/api_keys/installations/scans/findings`; `/healthz`, `/v1/me`;
Postgres via docker-compose for dev (free Neon/Supabase for deploy).
**Validate:** migrations apply on a clean DB; health + auth round-trip tested; ruff/mypy/pytest green.
**Done when:** the backend boots against a clean Postgres and the schema is in place.

### Task 11.3 — Ingest API + diff (the value spine)
**Build:** `POST /v1/orgs/{org}/repos/{repo}/scans` — body is the core `scan --format json` report;
validate against `schema_version`, denormalize into `findings`, diff vs the previous scan on that ref.
**Validate:** a real `vulnadvisor --format json` report persists findings and returns the correct diff
(fixture-tested); malformed/old-schema reports rejected.
**Done when:** CI/CLI can publish results without sending source, and scan-to-scan diff works.

### Task 11.4 — Read API + trends
**Build:** orgs/repos/scans/findings/trend endpoints; pagination; strict org-scoping. Findings are the
existing JSON-report finding object so dashboard and CLI never diverge.
**Validate:** tenant isolation tested (no cross-org reads); trend math verified.
**Done when:** the dashboard has a complete read API over stored scans.

### Task 11.5 — Auth: GitHub OAuth + API keys
**Build:** GitHub OAuth session login for the dashboard; hashed, revocable, org-scoped API keys for
CI/CLI uploads (GitHub OAuth only to start, per the approved design).
**Validate:** key hashing + revocation tested; unauthorized requests rejected.
**Done when:** dashboard login and CI key issuance/revocation work.

### Task 11.6 — GitHub App + PR comments
**Build:** HMAC-verified `POST /v1/github/webhook`; installation sync; on PRs, post/update a 3-card
diff comment (new reachable findings).
**Validate:** signed webhook fixtures drive a PR comment; bad signatures rejected.
**Done when:** opening a PR yields a reachability-triage comment.

### Task 11.7 — Next.js dashboard (dark `#0d1117`)
**Build:** read-only UI over the API — org overview, repo trend chart, scan detail (the 3 cards with
call-path evidence + tier), PR diff, settings (members, API keys, App install, cloud-scan opt-in).
Tailwind + shadcn/ui. Deploy free on Vercel.
**Validate:** renders a seeded org end-to-end; a11y/contrast pass on the dark theme.
**Done when:** a team can see their trends + 3 cards in a browser.

### Task 11.8 — (conditional) Background processing
**Build:** Redis + RQ — **only** if 11.3/11.6 profiling shows the API blocking. No queue/Redis/K8s
until measured.
**Validate:** the blocking path is measurably non-blocking; failure/retry tested.
**Done when:** ingest/webhook handling stays responsive under load. *Skip unless profiling proves it.*

---

## Post-launch roadmap (after M10, before/with M11)
- More framework plugins (Celery, DRF, Flask) — breadth of routed reachability.
- Grow the symbol dataset (`backfill --top N` on a schedule) — more `IMPORTED-AND-CALLED` hits.
- Per-method precision for Django class-based views; fold `collect_entry_points` into the analysis cache.
- Verify the live Pyright path end-to-end on a machine with node + pyright (Task 7.1 open item).

## Definition of a complete product (v1.0)
You're "done" with the fundable core when: the CLI installs from PyPI; scans a Python repo;
matches OSV/EPSS/KEV; assigns sound, tiered reachability (package → import → function) with the
call path shown as evidence; ranks deterministically; explains each finding in plain English;
outputs JSON + SARIF with CI exit codes; and you have a published benchmark proving the noise
reduction with zero missed reachable criticals. Everything after that (frameworks breadth,
platform, autofix PRs) is expansion.
