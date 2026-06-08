# PROGRESS

Running log of state + decisions. Newest entry on top. Updated after every task.

---

## Task 4.2 — Tiering (NOT-IMPORTED / IMPORTED / DYNAMIC-UNKNOWN)  →  release v0.3  (2026-06-08)

**Status:** complete, security-critical Validation Gate passing. **M4 done; tagged v0.3 — the
first version that delivers the core promise.**

**What changed**
- `model/reachability.py`: `ReachabilityTier` (IMPORTED_AND_CALLED / IMPORTED / DYNAMIC_UNKNOWN /
  NOT_IMPORTED) + `Reachability` (tier, reason, import-site evidence, dynamic evidence).
- `reachability/tiering.py`: `compute_reachability(dep, graph)` / `assign_tier`. IMPORTED when an
  import root matches (evidence = sites); DYNAMIC_UNKNOWN when no source analyzed / dynamic sites
  / parse errors / LOW-confidence import-name mapping; NOT_IMPORTED only when confidently safe.
- `model/imports.py`: added `analyzed_file_count` (so "no code scanned" can't masquerade as safe).
- `engine/scoring.py`: `apply_reachability` — NOT_IMPORTED scaled down + capped into INFO and
  relabeled "No path from your code"; every other tier keeps full priority (never downgraded),
  rationale annotated. `score_match(matched, reachability=None)`, `order_findings`. `ScoredFinding`
  gained an optional `reachability`.
- `cli/pipeline.py`: builds the import graph, computes reachability once per dependency, folds it
  into the score. Card C / JSON (`reachability` block with file:line evidence) / SARIF
  (`reachability_tier`) all surface the tier.
- Fixtures A/B/C (`fixtures/projects/reach_*`) + `tests/test_reachability.py` (18 tests).
  Bumped version to **0.3.0**; regenerated snapshots.

**Why these choices (soundness first)**
- A false "not imported" is a breach risk, so NOT_IMPORTED is gated hard: it requires real
  analyzed code, a static import-name match miss, no dynamic constructs, no parse errors, and a
  HIGH/MEDIUM-confidence import mapping. Anything else -> DYNAMIC_UNKNOWN (kept at full priority).
- DYNAMIC_UNKNOWN is **never** silently downgraded — it retains the full deterministic score.
- Evidence is shown (`file:line`) for IMPORTED, satisfying "show why".

**Validation evidence (release-blocking gate)**
- Fixture A (imports PyYAML) -> IMPORTED, stays high; Fixture B (declares, never imports) ->
  NOT_IMPORTED, deprioritized to INFO; Fixture C (dynamic import) -> DYNAMIC_UNKNOWN, not
  downgraded. **Zero false negatives** asserted across the suite (reachable/uncertain never
  marked safe), plus no-source/parse-error/low-confidence escalation safeguards.
- ruff + format clean; `mypy --strict src` clean (38 files); **pytest 170 passed**.
- **Live run** (real OSV, PyYAML 5.3.1): identical declared dep + 2 real CVEs ->
  A (imports yaml) IMPORTED with `app.py:1` evidence; B (never imports) all NOT-IMPORTED / INFO /
  "No path from your code". The noise reduction works end-to-end.

**Open questions**
- None blocking. v0.3 shipped. Next: M5 — vulnerable-symbol dataset (Task 5.1, the moat).

---

## Task 4.1 — Import graph of first-party code  (2026-06-08)

**Status:** complete, Validation Gate passing. (M4 reachability begins.)

**What changed**
- `model/imports.py`: `ImportSite` (file:line:col, kind, module, relative `level`, aliased
  `names`, `imported_roots()`), `DynamicImportSite` (kind + detail + location), `ImportedName`,
  `ImportParseError`, and `ImportGraph` (with `import_roots()` / `external_import_roots()`).
- `callgraph/import_graph.py`: `build_import_graph(project_dir)` — AST walk of every `.py`
  (skipping `.venv`/`build`/caches/etc.), capturing plain + from + relative imports and flagging
  dynamic constructs (`importlib`/`import_module`, `__import__`, `eval`, `exec`). Syntax errors
  are recorded as `parse_errors`, never raised. Plus `map_imports_to_distributions(graph, deps)`
  building a reverse index (import root -> distribution) via the Task 1.2 resolver.
- Fixture project `fixtures/projects/sample_imports/` (aliases + relative + dynamic + subpackage)
  and `tests/test_import_graph.py` (12 tests). Excluded `fixtures/` from Ruff (deliberate test
  inputs with odd ordering / intentional syntax errors).

**Why these choices**
- **Soundness:** an unparseable file is surfaced as a `parse_error` (a known gap) rather than
  silently dropped — reachability must stay cautious about files it could not read. Dynamic
  sites are recorded so Task 4.2 can mark possibly-hidden usage `DYNAMIC-UNKNOWN`.
- Relative imports contribute no external root (they are first-party); first-party top-level
  modules are inferred from the project root and `src/` so we can separate own-code from deps.
- The graph is pure/deterministic (sorted by file/line/col); distribution mapping is a separate
  function that reuses M1.2, keeping AST analysis free of dependency I/O.

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (36 files); **pytest 155 passed**.
- Tests assert aliases (`numpy as np`, `os.path as osp`), from-imports, relative levels
  (`.`, `.helper`, `..main`), all four dynamic-site kinds, excluded-dir skipping, and
  syntax-error recording. **Live run** on our own `src`: 134 import sites, first-party
  `vulnadvisor`, mapped distributions = packaging / pydantic / typer (stdlib correctly excluded).

**Open questions**
- Stdlib roots currently fall through as "unmapped" (fine — they're not distributions). If we
  later want to label them, we can add a stdlib set. Not needed for tiering.

---

## Task 3.2 — Safe-fix version resolution  →  release v0.2  (2026-06-08)

**Status:** complete, Validation Gate passing. **Milestone M3 done; tagged v0.2.**

**What changed**
- Added `packaging==26.2` (pinned, approved) for PEP 440 version math.
- `model/advisory.py`: `AffectedRange` + `AffectedPackage`; `Advisory.affected` now captures OSV
  affected ranges. `advisories/clients.py` parses `affected[].ranges[].events`
  (introduced/fixed/last_affected) defensively.
- `model/safe_fix.py`: `SafeFix` (current/fixed version, has_fix, is_major_jump, available_fixes,
  note). `engine/safe_fix.py`: `resolve_safe_fix(dep, advisory)` — picks the smallest fixed
  version greater than the installed one (the nearest non-vulnerable upgrade), flags no-fix and
  major-version jumps.
- `output/remediation.py`: `fix_command(dep, safe_fix)` now pins `>=<fixed_version>` and matches
  the manifest type (pip / poetry / pipenv); returns `None` when no fix exists.
- Card C, JSON `fix` block, and SARIF result properties all carry the resolved fix
  (`fixed_version`, `command`, `is_major_jump`, `available_fixes`, `note`).
- Bumped version to **0.2.0**. New `tests/test_safe_fix.py` (11 cases); updated fixtures,
  conftest advisories (with affected ranges), and regenerated snapshots.

**Why these choices**
- "Smallest fixed version > current" is the **minimal** upgrade and is correct for the common
  single-range case and sensible across multiple fixed branches (a test covers 2.1 -> 2.3, not
  1.5). Invalid/non-PEP440 fixed strings are skipped, not crashed on.
- We **flag** rather than hide the hard cases: no fix yet (monitor/mitigate) and major-version
  jumps (possibly breaking) — honest remediation beats a confident-but-wrong "just upgrade".
- `fix` computed in the emitters from `finding.matched` (advisory now has affected data), so the
  pipeline/`ScoredFinding` stayed unchanged.

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (34 files); **pytest 144 passed**.
- Tests cover fix-available, no-fix (last_affected only / nothing above current), major-jump,
  unpinned current, invalid versions; command is correct per manifest type (pip/poetry/pipenv).
- **Live run**: real OSV data gives `jinja2 2.10 -> 2.10.1` (minimal) and `-> 3.1.5` (major-jump
  flagged); `flask 0.12 -> 0.12.3` and `-> 1.0` (major-jump). JSON/SARIF carry the commands.

**Open questions**
- None blocking. M3 complete (v0.2). Next: M4 reachability — `callgraph/` import graph (Task 4.1).

---

## Task 3.1 — JSON + SARIF output and exit codes  (2026-06-08)

**Status:** complete, Validation Gate passing. (M3 in progress; v0.2 tag comes after Task 3.2.)

**What changed**
- Added dev-only dep `jsonschema==4.26.0` and vendored the official SARIF 2.1.0 schema at
  `fixtures/schemas/sarif-2.1.0.json` (fetched once) for offline schema validation in tests.
- `output/remediation.py`: moved `fix_command` here (neutral home shared by terminal/JSON/SARIF;
  avoids a cli<->output import cycle). `cli/render.py` now imports it.
- `output/json_report.py`: `build_report` / `to_json` — stable, documented `schema_version` 1.0
  report (tool, degraded_sources, summary.by_band, ordered findings). ASCII-safe.
- `output/sarif.py`: `build_sarif` / `to_sarif_json` — SARIF 2.1.0; one rule per advisory, one
  result per finding; band->level (error/warning/note); `security-severity` so GitHub orders by
  our priority; locations point at the manifest file.
- `output/gating.py`: `parse_fail_on` (band name or 0-100 score), `should_fail`, exit constants.
- `cli/main.py`: `scan` gains `--format terminal|json|sarif`; `--fail-on` now validated up-front
  and wired to exit code 1; JSON/SARIF printed as plain machine output (not Rich).
- Tests: `tests/test_output.py` (SARIF schema validation, JSON snapshot, fail-on table) +
  `fixtures/snapshots/report.json`; shared `sample_findings` fixture moved to `conftest.py`;
  CLI tests for json/sarif/exit-code paths.

**Why these choices**
- **SARIF validated against the real 2.1.0 schema** (not just shape asserts) using `jsonschema`
  + the vendored schema — exactly the gate, and it keeps the emitter honest as it evolves.
- JSON schema kept explicit/hand-built (not pydantic dump) so the public contract is stable and
  documented independent of internal model changes; snapshot-tested.
- `--fail-on` accepts a band *or* a numeric score; exits 1 if **any** finding meets/exceeds it.
  Validated before scanning so bad input fails fast (exit 2 usage error).

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (32 files); **pytest 132 passed**.
- SARIF output validates against SARIF 2.1.0 schema (test asserts zero schema errors).
- JSON snapshot stable; **live run**: `--format json` -> schema 1.0 / 15 findings; `--format
  sarif` -> version 2.1.0 / 15 results+rules; `--fail-on low` -> exit 1, `--fail-on critical`
  -> exit 0.

**Open questions / notes**
- Degraded sources are reported in JSON/SARIF but do **not** by themselves change the exit code
  (only findings-vs-threshold does). Flagging in case we want a `--fail-on-degraded` later for
  stricter CI soundness.
- Still pending: `uv add packaging` for Task 3.2 (safe-fix version-range math) — proposing now,
  since 3.2 is next and needs PEP 440 range handling.

---

## Task 2.3 — 3-card terminal output (Rich)  →  release v0.1  (2026-06-08)

**Status:** complete, Validation Gate passing. **Milestone M2 done; tagged v0.1.**

**What changed**
- `cli/render.py`: the signature three-card output. Per finding — Card A (templated attack
  summary), Card B (Red/Yellow/Green badge from the EPSS+KEV-driven band + scoring rationale),
  Card C (verdict + priority + templated fix command + evidence note). ASCII box art for
  snapshot stability and Windows-safe output. `render_to_string` for tests.
- `cli/pipeline.py`: `scan_project(path, matcher) -> ScanReport` wiring
  `collect_dependencies -> AdvisoryMatcher.match -> score_matches`. Matcher injected so the whole
  pipeline is testable offline.
- `cli/main.py`: `scan` now runs the real pipeline and renders; `build_matcher()` is a
  module-level seam tests monkeypatch. `--public/--internal` and `--fail-on` accepted but
  reserved (reachability M4 / exit-codes 3.1).
- `store/cache.py`: `default_cache_path()` (honors `VULNADVISOR_CACHE`; per-user dir; stays local).
- Bumped package version to **0.1.0**.
- Tests: `tests/conftest.py` (offline `RecordingTransport` + `fake_matcher` factory),
  `tests/test_render.py` (3-card + badge/fix helpers + **snapshot** `fixtures/snapshots/cards.txt`),
  `tests/test_pipeline.py`, rewritten `tests/test_cli.py` (end-to-end scan via fake matcher).

**Why these choices**
- The matcher is injected into the pipeline/CLI so "scan a fixture project -> ranked 3-card
  output" is proven **without network**; the live command builds the real OSV/EPSS/KEV matcher.
- Badge derives from the priority band (already an EPSS+KEV+CVSS function) so the visual signal
  is consistent with the deterministic score.
- ASCII box (`box.ASCII`) keeps rendered output pure-ASCII: stable snapshots and no Windows
  codepage mangling.

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (28 files); **pytest 105 passed**.
- Snapshot test renders the ranked cards (CRITICAL Jinja2/RED/"Fix now" above LOW Flask/GREEN/
  "Monitor"); CLI e2e test asserts the three cards + fix command + verdict.
- **Live run** `vulnadvisor scan` on `jinja2==2.10` + `flask==0.12` hit real OSV/EPSS/KEV and
  produced 15 ranked findings (real CVSS parsed from vectors, real EPSS), exit 0; second run
  served from cache.

**Open questions**
- All current findings rank LOW for these old CVEs (low EPSS, not KEV) — expected/by-design noise
  reduction. Still pending: `uv add packaging` for Task 3.2 (safe-fix version math).

---

## Task 2.2 — Deterministic scoring engine  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- `engine/cvss.py`: `cvss_base_score(vector)` — pure CVSS v3.0/3.1 base-score computation per the
  FIRST spec (correct Roundup); returns `None` for v2/v4/malformed so we never trust a wrong
  number.
- `model/score.py`: `PriorityBand` enum, `Score` (value/band/verdict/rationale + the inputs),
  `ScoredFinding(matched, score)`. Re-exported from `model/__init__.py`.
- `engine/scoring.py`: `compute_score`, `advisory_severity`, `score_match`, `score_matches`
  (deterministic descending sort with stable tie-breakers). Formula documented in the module
  docstring and the README.
- `tests/test_engine_scoring.py` (29 tests): CVSS values (9.8/8.8/10.0/3.3/0.0), unsupported
  vectors, determinism property, boundary band table, KEV floor, unknown-CVSS/EPSS handling,
  sorting determinism.
- README: added a "Priority scoring (deterministic)" section with the formula + verdict table.

**Why these choices (the formula)**
- `risk = 0.6*EPSS + 0.4*(CVSS/10)`, `value = 100*risk`. EPSS is weighted above severity because
  triage is about *real-world exploit likelihood* — that is the noise-reduction lever. A
  high-CVSS / near-zero-EPSS vuln is intentionally deprioritized (still reported, not dropped).
- **Soundness guards:** KEV membership floors the score to 90 (CRITICAL) regardless of other
  signals; unknown EPSS falls back to severity-only (not multiplied by 0); unknown CVSS uses a
  moderate 5.0 default flagged `cvss_known=False` (never scored as 0). These keep us from
  silently downgrading a finding when data is missing.
- Fully deterministic & pure: no clock/RNG/I/O; `score_matches` sorts by `(-value, advisory.id,
  dep.name, version)` so identical inputs always yield identical ordering (asserted).

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (26 files); **pytest 98 passed**.
- Determinism property holds; boundary table covers KEV / EPSS high+low / no-CVSS cases.

**Open questions**
- Still pending: `uv add packaging` for Task 3.2 (safe-fix version-range math).

---

## Task 2.1 — Advisory clients (OSV, EPSS, KEV) with cache  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- `model/advisory.py`: `Advisory` (with a `cve_ids` property), `EpssScore`, `MatchedAdvisory`,
  and `MatchResult` (carries `degraded_sources`). Re-exported from `model/__init__.py`.
- `store/cache.py`: `SqliteCache` — a TTL'd key/value store (negative TTL = never expires;
  `now` injectable for deterministic expiry tests). Re-exported from `store/__init__.py`.
- `advisories/transport.py`: `Transport` Protocol + stdlib `UrllibTransport` + `TransportError`
  (no new dependency — uses `urllib`).
- `advisories/parsing.py`: `safe_json` / `safe_str` / `safe_float` defensive helpers.
- `advisories/clients.py`: `OSVClient` (`/v1/query` by package+version), `EpssClient` (batched,
  caches misses too), `KevClient` (catalog membership). All cache-before-network.
- `advisories/matcher.py`: `AdvisoryMatcher.match(deps) -> MatchResult`, enriching each advisory
  with the best EPSS score across its CVEs and a KEV flag.
- Fixtures `fixtures/api/{osv_jinja2,epss,kev}.json`; `tests/test_advisories.py` (16 tests).

**Why these choices**
- **No live network in tests:** clients depend on an injectable `Transport`; tests use a
  counting `FakeTransport` that serves recorded fixtures and simulates outages.
- **Soundness / degraded mode:** a source outage surfaces as `TransportError`, which the matcher
  catches and records in `degraded_sources` — results are then explicitly *incomplete*, never
  silently treated as "safe". A malformed response body (vs. an outage) degrades to empty via the
  `safe_*` parsers and is **not** flagged degraded, since the HTTP call itself succeeded.
- **Cache correctness:** every client checks the cache first and stores raw JSON with a 24h TTL;
  EPSS caches *misses* as well so absent CVEs are not re-queried. A second `match()` makes zero
  network calls (asserted).
- Left `Advisory.cvss_score` as `None` for now; numeric CVSS will be derived from the vector by
  the scoring engine in Task 2.2 (kept the vector string).

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (23 files); **pytest 69 passed**.
- Match against fixtures yields advisory + EPSS (0.945) + KEV(true); 2nd run = 0 network calls
  (call count stays 3); malformed/empty payloads (5 variants) never crash; OSV/EPSS/KEV outages
  each flagged degraded without dropping the rest.

**Open questions**
- OSV `/v1/query` returns full vuln objects but not a numeric CVSS base score — Task 2.2 will
  parse the CVSS vector to a number. Still pending: `uv add packaging` for Task 3.2 range math.

---

## Task 1.2 — Package → import-name mapping  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- `model/import_mapping.py`: frozen `ImportMapping(distribution, import_names, confidence,
  source)` with `MappingConfidence` (HIGH/MEDIUM/LOW) and `MappingSource`
  (metadata/curated/guess) enums. Re-exported from `model/__init__.py`.
- `deps/import_mapping.py`: `resolve_import_names(distribution)` and
  `resolve_dependency(Dependency)`, plus the curated `CURATED_IMPORT_NAMES` table (17 entries:
  PyYAML→yaml, beautifulsoup4→bs4, scikit-learn→sklearn, Pillow→PIL, opencv-python→cv2, etc.).
- `tests/test_import_mapping.py`: 13 tricky real-world mappings (parametrized) + curated-table,
  metadata-HIGH, curated-MEDIUM, and unknown-LOW degrade tests.

**Why these choices**
- **Layered for soundness:** installed metadata (`top_level.txt`, else RECORD-derived top-level
  names) → HIGH; curated table → MEDIUM; best-guess `-`→`_` → LOW. We always return ≥1 import
  name with a confidence flag, so a wrong guess is *flagged low*, never silently trusted and
  never a crash — missing an import name would be a downstream false negative.
- Curated keys are stored PEP 503-canonical and looked up via `canonicalize_name`, so input
  casing/separators don't matter (a test asserts every key is already canonical).
- `resolve_dependency` prefers the raw manifest name for metadata lookup (importlib normalizes
  internally anyway), keeping behavior correct for either spelling.

**Validation evidence**
- ruff check / format clean; `mypy --strict src` clean (17 files); **pytest 53 passed**.
- ≥10 tricky mappings covered (13); unknown package → LOW/GUESS best-guess, no crash; installed
  `pydantic` → HIGH/METADATA.

**Open questions**
- Curated table is intentionally small; it will grow as we hit more real packages. The RECORD
  fallback covers most installed cases. Still pending: `uv add packaging` for Task 3.2.

---

## Task 1.1 — Manifest parsers  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- Added `pydantic==2.13.4` (pinned) and enabled the `pydantic.mypy` plugin.
- `model/dependency.py`: frozen `Dependency` model (`name`, `version`, `source`, `is_direct`,
  plus `raw_name`, `specifier`, `extras`) and a `DependencySource` str-enum. Re-exported from
  `model/__init__.py`.
- `deps/parsers.py`: pure, content-in parsers for all four formats —
  `parse_requirements_txt`, `parse_pyproject_toml` (PEP 621 `[project]` **and** Poetry tables),
  `parse_poetry_lock`, `parse_pipfile_lock` — plus `parse_manifest_file` (filename dispatch),
  `collect_dependencies` (merge all present manifests; env fallback when none), and
  `dependencies_from_environment` (via `importlib.metadata`). `canonicalize_name` does PEP 503.
- Fixtures for every format under `fixtures/manifests/`; 32 table-driven + edge tests in
  `tests/test_deps_parsers.py`.

**Why these choices**
- **Soundness:** structurally malformed TOML/JSON raises a typed `ManifestParseError` (caught,
  not a crash); but a malformed *entry* degrades to `version=None` and is still recorded — we
  never silently drop a dependency, since a lost dep becomes a downstream false negative.
- Parsers take **content strings, not paths**, keeping them pure/testable (the I/O lives only in
  `parse_manifest_file` / `collect_dependencies` / the env fallback).
- `version` holds an exact pin only (from `==`/lockfile/bare-Poetry-version); ranges/carets are
  preserved in `specifier` with `version=None`. This cleanly represents "pinned vs range".
- `is_direct=True` for declarative manifests (requirements.txt, pyproject), `False` for resolved
  lockfiles (poetry.lock, Pipfile.lock) and environment records.
- Avoided adding the `packaging` library for now (wrote a small PEP 503 + PEP 508-lite parser).
  See open question — we will likely want `packaging` for real version-range math in Task 3.2.

**Validation evidence**
- ruff check / format clean; `mypy --strict src` clean (15 files); **pytest 32 passed**.
- Table-driven test per format passes; duplicate Flask entries de-dupe to one; pinned-vs-range
  both retained; malformed TOML/JSON raise `ManifestParseError`; empty dir falls back to the
  environment.

**Open questions**
- Propose adding `packaging` (pinned) when we need correct version-range comparison and
  PEP 440 specifier handling (Task 3.2 safe-fix resolution). OK to `uv add packaging` then?

---

## Task 0.2 — CLI skeleton + CI  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- Added `typer==0.26.7` as the first runtime dependency (pinned; CLI framework from the stack).
- Built `src/vulnadvisor/cli/main.py`: a Typer app with a `scan PATH [--public/--internal]
  [--fail-on ...]` stub command (echoes the resolved invocation, exits 0) and a top-level
  `--version` callback. Registered the `vulnadvisor` console script via `[project.scripts]`.
- Added `.github/workflows/ci.yml`: runs `uv sync --frozen` + ruff check + ruff format --check +
  `mypy --strict src` + pytest on push and pull_request (mirrors the local gate exactly), using
  `astral-sh/setup-uv` pinned to 0.11.19 and Python 3.12.
- Added `tests/test_cli.py` (Typer `CliRunner`): `--version` exits 0, scan stub exits 0 for
  `--public`/`--internal`, and a missing path errors non-zero.

**Why these choices**
- Used Typer's `Annotated[...]` parameter style so the `typer.Option/Argument` calls live in
  annotation metadata, not default values — this keeps Ruff's `B008` (function-call-in-default)
  clean without a per-file ignore.
- Console-script entry points at `vulnadvisor.cli.main:app` (Typer instances are callable).
- Switched the scan stub's plain `typer.echo` line from an em-dash to an ASCII hyphen: the
  Windows console codepage mangled the em-dash. Help text (rendered via Rich) keeps Unicode.

**Validation evidence**
- `uv run vulnadvisor scan .` → stub printed, `exit=0`.
- `uv run vulnadvisor --version` → `vulnadvisor 0.0.0`, `exit=0`.
- CI YAML parses and contains all four local checks (verified with an ephemeral PyYAML parse).
- ruff check / ruff format --check clean; `mypy --strict src` clean (13 files); pytest 5 passed.

**Open questions**
- None blocking. First CI run will execute once this is pushed; will confirm green on GitHub.

---

## Task 0.1 — Repo + toolchain  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- Added `pyproject.toml` (uv-managed) configuring Ruff (lint + format), `mypy --strict`, and
  pytest. Dev tooling pinned: `ruff==0.14.4`, `mypy==1.18.2`, `pytest==8.4.2`.
- Created the full empty package tree under `src/vulnadvisor/` per `instructions.md`: `cli`,
  `deps`, `advisories`, `symbols`, `callgraph`, `reachability`, `engine`, `output`, `llm`,
  `model`, `store` — each with an `__init__.py` carrying a one-line docstring.
- Added `tests/` (mirrors `src/`) with one smoke test, plus `fixtures/` and `benchmarks/`
  placeholders.
- Added `README.md` (one-liner + run instructions), this `PROGRESS.md`, and `.gitignore`.

**Why these choices**
- `requires-python = ">=3.12"` per the stack rule (we analyze 3.12+ Python; local env is 3.13).
- `hatchling` build backend with an explicit `src/` layout so the package is importable and
  installable without extra config.
- Ruff rule set `E,F,I,UP,B,SIM,D` with the Google docstring convention enforces module
  docstrings from day one; `tests/*` is exempt from docstring (`D`) rules.
- Added one trivial smoke test so `pytest` exits 0 (an empty suite exits 5 = "no tests
  collected", which would read as a failed gate).

**Open questions**
- GitHub remote is not yet configured (`origin`). Push discipline can't run until the remote
  exists — flagging for setup before/at Task 0.2.
