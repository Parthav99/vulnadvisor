# PROGRESS

Running log of state + decisions. Newest entry on top. Updated after every task.

---

## Task 9.1 — Plain-English "attack story" LLM layer  (2026-06-09) -> RELEASE v1.0

**Status:** complete, Validation Gate passing. Version bumped 0.3.0 -> 1.0.0; tag `v1.0`.

**Decision (user):** talk to the Anthropic API **dependency-free** over the existing `Transport`
(no `anthropic` SDK), behind an injectable interface.

**What changed**
- `model/explanation.py`: `Explanation` (attack_story + verdict_rationale + `source`: llm/template).
  Carries no score — structurally cannot affect priority.
- `llm/client.py`: `LLMClient` Protocol + `AnthropicClient` (a documented POST to `/v1/messages`
  over `Transport`; key from `ANTHROPIC_API_KEY` only, model from `ANTHROPIC_MODEL` or
  `claude-haiku-4-5-20251001`). `LLMError` on any transport/parse failure. `build_anthropic_client`
  returns `None` when no key (-> template-only).
- `llm/prompt.py`: `build_messages` (hands the model the engine's facts + call path; system prompt
  forbids changing priority and demands strict JSON) and `templated_explanation` (the deterministic
  always-available fallback).
- `llm/explainer.py`: `Explainer` orchestrates cache -> LLM (strict-validated) -> template. Strict
  parser tolerates code fences / surrounding prose but only accepts a JSON object with non-empty
  string fields; otherwise falls back. `finding_hash` keys the cache by finding+model.
- `cli/render.py`: Card A shows the attack story ("(AI)" when from the model); Card C adds a one-line
  "Why". Priority shown always comes from the deterministic score.
- `cli/main.py`: `build_explainer()` (LLM when keyed, else template-only, cache-backed); terminal
  output explains by default; `--no-explain` flag. JSON/SARIF unchanged.
- `tests/test_llm.py` (20 tests); `test_cli.py` updated (hermetic, expects Card A "Attack story").

**Why these choices (trust + soundness)**
- The LLM is narrative-only: `Explanation` has no score field and the renderer reads priority solely
  from the deterministic `Score`, so the model **cannot** change priority (asserted, incl. a hostile
  response injecting a score).
- Every failure mode (no key, transport error, non-JSON, schema-invalid, empty) -> deterministic
  template, so Card A always renders offline. Successful results cached by content hash.
- No secrets in code; one documented endpoint; no SDK dependency.

**Validation evidence**
- Mocked-client tests: valid JSON -> LLM source; malformed/partial/garbled/empty + transport error
  -> template (parametrized); code-fenced and prose-wrapped JSON tolerated.
- Priority invariant asserted: a hostile response can't change `score.value`/`band`; `Explanation`
  exposes no score.
- Caching: identical finding served from cache (one call); changed finding/model re-calls.
- Dependency-free client: parses the text block and sends `x-api-key`/`anthropic-version`; raises on
  garbage. `build_anthropic_client` requires the key and honors `ANTHROPIC_MODEL`.
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (54 files),
  `pytest` 280 passed.

**Release:** the full 3-card experience (attack story + risk + action with deterministic priority)
is live and trustworthy. **Tagged v1.0.**

---

## Task 8.1 — Benchmark harness + report  (2026-06-09)

**Status:** complete, Validation Gate passing. (M8 — the fundraising/launch proof.)

**Decisions (user):** (1) add `pip-audit` as the naive baseline (`uv add --dev pip-audit`, pinned
`==2.10.0`). (2) Ship a **hermetic harness + synthetic corpus now** (tested, no network) plus a
**pinned-commit manifest of real public repos** for a live run triggered later.

**What changed**
- `benchmarks/` (new): `metrics.py` (pure: `AdvisoryOutcome`/`RepoResult`/`BenchmarkReport`,
  noise-reduction %, false-negative + missed-critical tallies; only NOT_IMPORTED counts as removed
  noise). `report.py` (deterministic ASCII Markdown). `corpus.py` (12 synthetic repos run through
  the **real** engine: `build_import_graph` + `collect_entry_points` + `refine_reachability`; roles
  `called`/`imported`/`unused` give exact ground-truth labels; source imports generated from the
  resolver so `pyyaml`->`yaml` stays correct; only confident-mapping packages so `unused` ->
  NOT_IMPORTED). `manifest.py` (12 real public repos pinned to genuine HEAD SHAs as of 2026-06-09 +
  a defensive `run_live` that clones, runs pip-audit, scans, maps tiers). `__main__.py`
  (`python -m benchmarks` hermetic; `--live`; `--out`). `REPORT.md` (the generated artifact).
- `tests/test_benchmarks.py` (12 tests): pure-metric tests + end-to-end hermetic run.

**Why these choices (soundness first)**
- The headline metric is computed against ground-truth labels we control, so the
  false-negative/missed-critical numbers are trustworthy — a labeled-reachable advisory placed in
  NOT_IMPORTED is a hard test failure.
- Live repos can't be fully labeled, so `reachable_truth=None` there is excluded from the FN tally;
  the soundness guarantee is proven by the hermetic corpus, the live mode reports noise reduction.
- The harness runs the actual product (not a mock), so the numbers reflect the real engine.

**Validation evidence (measured, hermetic)**
- Runs end-to-end over **12 repos** (>= 10) and writes `benchmarks/REPORT.md`.
- **54% less noise**: 39 naive findings -> 18 after triage; **10** reachable-called; **0 missed
  reachable criticals**, 0 false negatives -> Soundness gate **PASS**.
- Reproducible: deterministic corpus + ordering; ASCII-only report (Windows-safe).
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (50 files),
  `pytest` 260 passed.

**Open questions / for the live run**
- Manifest commits are real, but per-repo `requirements` paths are best-effort (many projects use
  pyproject.toml); confirm paths before the published live run. `run_live` is defensive but
  unexercised in CI (needs network + pip-audit). `benchmarks/` is not under the `mypy --strict src`
  gate (only an installed-package `py.typed` marker is missing — no real type errors).

---

## Task 7.2 — Framework plugins (FastAPI + Django)  (2026-06-09)

**Status:** complete, Validation Gate passing. (M7 — framework-routed reachability.)

**Decision (user):** start with **FastAPI + Django** — two genuinely different dispatch models
(decorator routes vs URLconf views + `@receiver` signals), so the plugin interface is proven
general rather than two near-identical decorator scanners.

**What changed**
- `callgraph/frameworks/` (new package): `FrameworkPlugin` Protocol + `EntryPoint` +
  `collect_entry_points` (runs plugins over every file, defensive — a bad file or a raising plugin
  is skipped, never crashes the scan). `FastAPIPlugin` (route/websocket decorators:
  get/post/put/patch/delete/head/options/trace/websocket/route/api_route). `DjangoPlugin` (URLconf
  `path`/`re_path`/`url` view references incl. `Views.as_view()` -> class name, and `@receiver`
  signal handlers). `DEFAULT_PLUGINS = (FastAPIPlugin(), DjangoPlugin())`.
- `callgraph/call_paths.py`: `find_vulnerable_call_paths(..., entry_points=())` seeds the BFS from
  the module scope **plus** framework entry-point functions (and a class-based view's
  `Class.method` nodes), so a vuln reached only through a handler is rooted at it.
- `reachability/tiering.py`: `refine_reachability(..., entry_points=())` threads them in.
- `cli/pipeline.py`: `scan_project(..., frameworks=None)` computes entry points once via the
  enabled plugins (default all; `[]` disables). `cli/main.py`: `--no-frameworks` flag.
- Fixtures `fastapi_app` (route -> helper -> yaml.load) and `django_app` (urls.py -> views.py view
  -> helper -> yaml.load); `tests/test_frameworks.py` (18 tests).

**Why these choices (soundness first)**
- Entry points only **add** BFS roots, never remove a path — over-detection costs precision, never
  soundness. The existing fallback still reports any vuln call, so disabling frameworks never
  introduces a false negative (verified: `--no-frameworks` still detects, just doesn't root at the
  handler).
- Plugins are independent: `collect_entry_points` takes the plugin list, so disabling one removes
  only its entries (isolation tested both directions).

**Validation evidence (measured)**
- FastAPI: `read_config -> _load -> yaml.load (app.py:20)` — rooted at the route handler.
- Django: `parse_config -> _load -> yaml.load (views.py:16)` — view resolved cross-file from
  urls.py. Both end-to-end -> IMPORTED_AND_CALLED.
- Isolation: FastAPI-only sees `{read_config}`/`{}`, Django-only sees `{}`/`{parse_config}` on the
  two fixtures — disabling one leaves the other unchanged.
- Without frameworks the FastAPI vuln is still detected (fallback) but not rooted at `read_config`,
  proving the plugin's contribution is correct attribution, not avoiding a false negative.
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (50 files),
  `pytest` 248 passed.

**Open questions / future**
- Django class-based views emit the class name and root all its HTTP-verb methods (sound
  over-approximation); per-method precision and Celery/DRF are later additions. `collect_entry_points`
  re-parses files (not via the analysis cache) — fold into the cache if profiling shows it matters.

---

## Task 7.1 — Pyright type-informed resolution  (2026-06-09)

**Status:** complete, Validation Gate passing. (M7 — precision, no new false negatives.)

**Decision (user):** Pyright is an *optional external tool* behind an injectable resolver. CI is
hermetic — the precision logic is proven with a deterministic fake runner; the live fallback
(Pyright absent) is verified on this machine. No new dependency added.

**What changed**
- `callgraph/call_paths.py`: `find_vulnerable_call_paths` now returns a structured
  `CallGraphResult` (`.paths`, `.reflections`, `.has_opaque_dynamic`, `.has_dynamic`). Reflective
  access `getattr(<pkg_alias>, name)` is recorded as a `PackageReflection` (resolvable later by
  type info) and split from genuinely opaque dynamic calls (`eval`/`exec`/`__import__`/computed
  callee) that no resolver can pin down.
- `callgraph/type_resolver.py` (new): `TypeResolver` Protocol, `NullResolver` (sound fallback ==
  M6), `PyrightResolver`. Pure, fully-tested parsers `literals_from_type_string` (only narrows on a
  clean string `Literal[...]`) and `parse_pyright_reveals` (matches `reveal_type` info diagnostics
  strictly by injected line number). `PyrightResolver` copies the project, injects `reveal_type`
  probes, runs `pyright --outputjson`, and parses inferred types — all behind an injectable
  `runner` seam; fail-safe (any error -> resolve nothing).
- `reachability/tiering.py`: `refine_reachability(..., resolver=None)`. A reflection that provably
  resolves to a *non-vulnerable* attribute no longer forces DYNAMIC_UNKNOWN (precision); one that
  resolves *to* a vulnerable attribute upgrades to IMPORTED_AND_CALLED; unresolved/opaque dispatch
  stays conservative.
- `cli/pipeline.py` + `cli/main.py`: `resolver` threaded through `scan_project`;
  `build_type_resolver()` returns a `PyrightResolver` (self-reports unavailable if pyright absent);
  new `--no-types` flag.
- Fixtures `reach_dynamic_resolved_safe` (getattr -> safe_load) and `reach_dynamic_resolved_vuln`
  (getattr -> load); `tests/test_type_resolution.py` (15 tests); `test_call_paths.py` updated to the
  `CallGraphResult` API.

**Why these choices (soundness first)**
- Precision never costs soundness: a reflection only stops forcing the conservative tier when the
  resolver returns a *concrete* attribute set that excludes every vulnerable name. No type info ->
  `None` -> stay DYNAMIC_UNKNOWN. The parser refuses to narrow on anything but a pure string
  `Literal`, and matches reveals strictly by line, so a parse slip yields "no resolution," never a
  wrong (unsound) one.
- Pyright absent -> resolver `available == False` -> behavior identical to M6.

**Validation evidence (measured)**
- `reach_dynamic_resolved_safe`: M6 `dynamic-unknown` -> M7 `imported` (false positive removed).
- `reach_dynamic_resolved_vuln`: M6 `dynamic-unknown` -> M7 `imported-and-called` (caught).
- `reach_dynamic_dispatch` (unannotated param): `dynamic-unknown` with and without the resolver
  (Pyright can't pin it -> no false negative).
- `Pyright present on PATH? False` on this box -> the live fallback path is exercised; precision
  results above use the injected runner.
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (46 files),
  `pytest` 235 passed.

**Open questions / known limitation**
- The live `pyright --outputjson` path (project copy + `reveal_type` injection + subprocess) is
  unverified on this machine (no node/pyright installed). The *logic and parsers* are fully
  unit-tested via the injected runner and synthetic Pyright JSON; the subprocess seam is
  fail-safe (errors -> resolve nothing -> M6). Verify end-to-end once Pyright is installed.

---

## Task 6.2 — Incremental caching  (2026-06-08)

**Status:** complete, Validation Gate passing. (M6 — fast CI re-runs.)

**What changed**
- `model/imports.py`: new `FileAnalysis` model (frozen, serializable) — the per-file analysis
  unit (imports, dynamic sites, optional parse error). `_analyze_source` now returns it.
- `store/analysis_cache.py`: `AnalysisCache` — a SQLite-backed, content-addressed store of
  `FileAnalysis` keyed on `cache_key(rel, text)` = `"{rel}\x00{sha256(content)}"`. Tracks
  `hits`/`misses` so re-analysis can be proven skipped. `content_hash`, `cache_key`,
  `default_analysis_cache_path()` (honors `VULNADVISOR_CACHE`, dir or file).
- `callgraph/import_graph.py`: `build_import_graph(..., cache=None)` looks up each file by content
  hash via `_analyze_cached` and only re-parses on a miss. Results are identical with/without it.
- `cli/pipeline.py`: `scan_project(..., analysis_cache=None)` threads the cache into the graph.
- `cli/main.py`: `scan` builds a default on-disk `AnalysisCache` and adds `--no-cache` to disable.
- `tests/test_analysis_cache.py` (9 tests).

**Why these choices (soundness-neutral speed)**
- Invalidation is content hashing, never a timer — a stale entry can never mask a current
  finding. An edited file's hash changes -> fresh key -> exactly that one file is re-analyzed;
  every other key still hits.
- The relative path is part of the key so identical-content files (e.g. empty `__init__.py`) never
  share an entry and get the wrong embedded `file=`.
- A corrupt/undeserializable entry is treated as a miss (re-analyze) — the cache never raises into
  a scan. Cache stays on-disk, per-user; no telemetry.

**Validation evidence**
- Unchanged re-run = all hits, zero re-analysis (`misses == 0`); editing one file -> exactly
  `misses == 1` (tested deterministically via hit/miss counters).
- Cached graph is byte-identical to the uncached graph (tested).
- Live benchmark, 300-file project: cold 2005.6 ms (301 misses) -> warm 41.9 ms (301 hits, 0
  misses) = 47.8x faster on an unchanged re-run.
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (45 files),
  `pytest` 220 passed.

**Open questions**
- Call-path search (`find_vulnerable_call_paths`) still re-parses on demand; it only runs for
  matched advisories (narrow), so it's left uncached for now. Candidate for caching if profiling
  shows it dominates on large matched sets.

## Task 6.1 — Demand-driven call-graph + path search  (2026-06-08)

**Status:** complete, security-critical Validation Gate passing. (M6 — function-level reachability.)

**What changed**
- `model/callpath.py`: `CallStep` / `CallPath` (with `render()`); `Reachability` gained
  `call_paths`.
- `callgraph/call_paths.py`: `find_vulnerable_call_paths(project_dir, import_names,
  vulnerable_names)` — builds a lazy per-module call graph seeded by the package's import names +
  the advisory's vulnerable symbol names, BFS from module entry to a vulnerable call site, returns
  the path(s) + a `has_dynamic_dispatch` flag. Never a whole-program graph; stops at first path.
- `reachability/tiering.py`: `refine_reachability` — concrete path -> IMPORTED_AND_CALLED (path
  shown); IMPORTED + dynamic dispatch (getattr/reflection/computed callee) + no path ->
  DYNAMIC_UNKNOWN; else unchanged.
- `cli/pipeline.py`: optional `symbol_names_for` callback threads vulnerable symbol names into
  per-finding refinement. `cli/main.py`: `build_symbol_names_for()` reads the local dataset (if
  backfilled) so `scan` automatically gets function-level reachability. JSON `reachability` block
  now carries `call_paths`.
- Fixtures `reach_called` / `reach_imported_only` / `reach_dynamic_dispatch` +
  `tests/test_call_paths.py` (13 tests).

**Why these choices (soundness first)**
- A static call to the vulnerable symbol -> IMPORTED_AND_CALLED, and the call site is never
  dropped even if not reachable from module top-level (library API entry). Dynamic dispatch with
  no concrete path -> DYNAMIC_UNKNOWN (a call could be hidden) — never "not called".
- We match the user's *direct* call to the vulnerable symbol name (``pkg.sym(...)`` or a name
  imported ``from pkg``). This is the demand-driven seed.

**Validation evidence (release-blocking gate)**
- reach_called -> IMPORTED_AND_CALLED with path `<module> -> main -> parse -> yaml.load`;
  reach_imported_only -> IMPORTED (not escalated); reach_dynamic_dispatch -> DYNAMIC_UNKNOWN
  (not dropped). Zero false negatives asserted (reachable/uncertain never IMPORTED-safe nor
  NOT_IMPORTED).
- ruff + format clean; `mypy --strict src` clean (44 files); **pytest 211 passed**.
- **Live run**: seeding the dataset with the called symbol, `scan` emits IMPORTED-AND-CALLED with
  the path `<module> -> main -> parse -> yaml.load (app.py:7)`.

**Open questions / known limitation**
- Matching is on the *exact* vulnerable symbol name the user calls. Real advisories often pin a
  library-*internal* symbol (e.g. PyYAML `construct_python_object_new`) reached via the public
  API (`yaml.load`); we don't yet connect public-entry -> internal-symbol (needs the library's
  own call graph or an entry-point map). So such cases currently stay IMPORTED (sound: no false
  AND-CALLED). Candidate refinement for M7 (Pyright) / a public-API map. Next: Task 6.2 caching.

---

## Task 5.2 — Dataset store + backfill  (2026-06-08)

**Status:** complete, Validation Gate passing. **M5 (the data moat) done.**

**What changed**
- `store/dataset.py`: `SymbolDataset` — SQLite store of `advisory_id -> SymbolExtraction` (one row
  per advisory, payload as JSON, PK lookup). `upsert` (idempotent `INSERT OR REPLACE`), `get`,
  `has`, `count`, `advisory_ids`, `close`. `default_dataset_path()` (honors
  `VULNADVISOR_DATASET`).
- `symbols/backfill.py`: `backfill(dataset, packages, *, osv, extractor, refresh)` — queries OSV
  per package, extracts + stores symbols; skips advisories already present unless `refresh`;
  degrades per-package on outage. `BackfillReport`, `TOP_PYPI_PACKAGES`, `top_packages`.
- `cli/main.py`: `backfill` command (`vulnadvisor backfill [PACKAGES...] [--top N] [--refresh]
  [--db PATH]`); `build_osv_client` / `build_symbol_extractor` seams for tests.
- `tests/test_dataset.py` (8) + `tests/test_backfill.py` (7) + 2 CLI tests.

**Why these choices**
- One JSON-payload row keyed by `advisory_id` PK keeps lookups O(1) and the schema stable as the
  symbol model evolves; round-trips via pydantic `model_dump_json` / `model_validate_json`.
- Idempotency is structural: `has()`-skip on re-run (no work), and `INSERT OR REPLACE` so even a
  forced `--refresh` never grows the row count. Backfill targets are injected (Protocols) so the
  whole flow is offline-testable; the CLI builds the live clients.
- `--top N` uses a built-in package list so choosing targets needs no network.

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (42 files); **pytest 198 passed**.
- Backfill populates the store; re-runs are idempotent (written=0, skipped=all, count stable);
  `--refresh` re-extracts without growing rows; outages recorded, not fatal. Lookups by advisory
  covered (round-trip, persistence, missing→None).
- **Live run**: `vulnadvisor backfill pyyaml jinja2` wrote **24** real advisories; a second run
  skipped all 24 (dataset stable at 24).

**Open questions**
- None blocking. The dataset can now grow over time. Next: M6 — Reachability v2 (Task 6.1,
  demand-driven call graph using these symbols to emit IMPORTED-AND-CALLED with the call path).

---

## Task 5.1 — Fix-commit → vulnerable-symbol extraction  (2026-06-08)

**Status:** complete, Validation Gate passing. (M5 — the data moat — begins.)

**What changed**
- `model/advisory.py`: added `AdvisoryReference` and `Advisory.references`; OSV client now parses
  the `references` array (defensively).
- `model/symbols.py`: `VulnerableSymbol` (name, qualname, kind, file), `SymbolExtraction`
  (symbols + confidence + provenance + `ExtractionStatus`), `SymbolKind`.
- `symbols/extractor.py`: pure `extract_symbols_from_patch(diff)` mapping each changed hunk to its
  enclosing function/method/class (heading-seeded scope stack; removed `def`/`class` recorded
  directly); `fix_commit_urls(advisory)`; `SymbolExtractor(transport).extract(advisory)` which
  fetches `<commit>.patch` and degrades to NO_FIX_LINK / FETCH_FAILED / NO_SYMBOLS.
- 5 recorded patch fixtures (`fixtures/patches/`) + `tests/test_symbols.py` (15 tests).

**Why these choices**
- The vulnerable symbol is the code the fix *changed*, so we attribute changed lines to their
  enclosing symbol and record removed defs (deleted functions). Brand-new added defs are NOT
  recorded (they are fix code, not the vuln) to avoid false symbols.
- The diff parser is pure/string-in (tested against recorded patches, no network); the extractor
  injects a `Transport` (offline-testable) and never crashes — every failure mode is a typed
  status. Confidence is a documented heuristic (lower for sprawling multi-file diffs).
- Fix-commit discovery is reference-based (`/commit/` URLs). GIT-range-derived commits (repo +
  fixed sha) are a future enhancement (would need repo capture on ranges).

**Validation evidence**
- ruff + format clean; `mypy --strict src` clean (40 files); **pytest 183 passed**.
- ≥5 hand-verified advisories: PyYAML→FullConstructor.find_python_name, Jinja2→
  SandboxedEnvironment.is_safe_attribute, requests→SessionRedirectMixin.resolve_redirects,
  Flask→dumps, urllib3→parse_url — all matched. No-fix-link / fetch-failure / unusable-patch all
  handled without crashing.
- **Live run**: real OSV advisory GHSA-8q59-q68h-6hv4 (PyYAML 5.3.1) → fetched the fix commit
  and extracted the actual changed functions (construct_python_object_new, set_python_instance_state).

**Open questions**
- Kind classification falls back to FUNCTION when the enclosing class isn't visible in the hunk
  (header/context); the qualname/name are still correct, which is what reachability matches on.
  Refine with class context in Task 6 if needed. Next: Task 5.2 — dataset store + backfill.

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
