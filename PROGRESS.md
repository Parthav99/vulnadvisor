# PROGRESS

Running log of state + decisions. Newest entry on top. Updated after every task.

---

## Task 19.4 — Fix-centric finding card (the centrepiece redesign)  (2026-06-15)

**Status:** complete (**dashboard-v1.2**). **No new dependency.** Gate green: `ruff check` clean
(src + tests + platform), `ruff format --check` clean (189 files), `mypy --strict src
platform/vulnadvisor_platform` clean (118 files), **src pytest 917 passed / 1 skipped**, **platform
pytest 217 passed** (+1 new). Dashboard: **lib tests 79 passed** (`node --test`), `eslint` clean
(exit 0), **`npm run build` succeeded**.

**Maintainer decisions (asked up front):** (1) **defer decline tracking** — the platform stores only
*validated* fixes, so the card cannot yet honestly distinguish "genuinely declined" from "never
attempted"; this task is **positive-only** (hero panel + "Fix ready" badge when a fix exists; a
neutral *"No validated fix in this scan — run `vulnadvisor fix`"* when none, never asserting the loop
declined). Real decline tracking (suggestions doc + ingest + read) is a follow-up so "No safe fix
found" is only ever shown when truly declined. (2) **Plumb `provenance`** (19.3's
deterministic-vs-model field) through the platform so the badge has real data.

**What changed**
- **Provenance plumb (platform).** `reports.py: _clean_suggestion` now keeps `provenance`
  (coerced to `deterministic`/`model`, default `model` — back-compat with pre-19.3 uploads);
  `schemas.py: ProposedFix` gains `provenance: str = "model"`; `routers/read.py: _proposed_fixes`
  surfaces it. Additive and defensive — a garbage value coerces to `model`, never surfaced verbatim.
- **Dashboard lib (`lib/fix.ts`, pure + unit-tested).** New `dependencyFindingId` (the SCA join key
  `<package>:<advisory_id>`, mirror of the CLI's `sca_finding_id`); `fixedCodeFromDiff` (reconstructs
  the post-fix hunk for **copy-fixed-code** — context + added lines, drops removed/headers, defensive
  so any string yields a string); `fixProvenanceLabel`/`fixProvenanceClass` (Deterministic = trusted
  safe-teal badge, AI-generated = neutral; absent → AI-generated, never claims determinism it can't
  prove); `FIX_VALIDATION_STEPS` (the proven-steps line). `ProposedFix` type gains optional
  `provenance`.
- **Fix-centric card (`components/finding-card.tsx`).** `ProposedFixPanel` is now the **hero** — it
  **leads** the expanded view (evidence/story sit below), styled with the safe-teal accent, a
  **deterministic-vs-model** badge, a confidence chip, the rationale, **copy-diff + copy-fixed-code**
  buttons, and an honest provenance line *"validated: applied · ruff · mypy · tests · re-scan clean"*
  (true for any emitted patch — the 17.1 loop never surfaces one that skipped a step). The collapsed
  row gains a **"Fix ready"** badge when a validated patch exists; the no-fix Action note is now the
  neutral *"No validated fix in this scan"* wording. Works for **both SAST and SCA** findings (the
  dependency card now takes `proposedFix` too). Soundness wording unchanged: *suggested,
  machine-validated, never auto-applied — you commit it on the PR*; pure presentation, no
  tier/score/ranking touched.
- **Joins + demo.** `app/scans/[scan]/page.tsx` now joins **SCA** fixes (`dependencyFindingId`) as
  well as SAST. The `/demo` scan page joins seeded fixes too: two deterministic `requirements.txt`
  version-bump patches (pyyaml, jinja2) seeded on the latest payments scan so the public
  dashboard-v1.2 face shows the hero. `DemoScan` gains a `suggestions` list.

**Tests**
- `lib/fix.test.ts` (+5): `dependencyFindingId` parity with the CLI id; `fixedCodeFromDiff` exact
  reconstruction + defensive cases; provenance label/class (deterministic = safe, model/undefined =
  neutral); the validation-steps order.
- `lib/demo.test.ts` (+1): every seeded fix joins to a finding in its scan, non-empty diff, valid
  provenance.
- `platform/tests/test_read.py` (+1, +1 assertion): a `provenance: "deterministic"` round-trips to
  the read API; a garbage value coerces to `model`; the existing SAST fix defaults to `model`.
- `platform/tests/test_ingest.py` (+1 assertion): absent provenance defaults to `model` at ingest.

**Soundness/scope:** pure presentation — the panel never changes the deterministic verdict; the
provenance badge is advisory (both kinds cleared the *same* validator). Detection/scoring untouched.
**Deferred:** decline tracking (honest "No safe fix found" state) per maintainer decision (1); SAST
seeding in `/demo` (the seed dataset is SCA-only — a SAST CodeFinding needs the demo scan type
widened to `AnyFinding`, out of scope here); live e2e (real PR → fix uploaded → card hero) stays
credential-gated by prior-task precedent — every join hop is proven hermetically (platform tests +
lib joins).

---

## Task 19.3 — Raise fix yield with deterministic quick-fixes  (2026-06-15)

**Status:** complete. **No new dependency.** Gate green: `ruff check` clean (src + tests + platform),
`ruff format --check` clean (129 files), `mypy --strict src platform/vulnadvisor_platform` clean (118
files), **src pytest 916 passed / 1 skipped**, **platform pytest 216 passed**. SAST soundness gate
re-run (`python -m benchmarks --sast`): **PASS, 0 missed vulns**, exit 0 (detection untouched).

**Maintainer decision (asked up front):** scope the quick-fix set to the **three CWEs the engine
detects today** (CWE-502 yaml, CWE-78 subprocess-shell, CWE-94 eval) rather than pulling M20/M23
*detection* work forward. The task lists six CWEs, but weak-hash (327/328), insecure-RNG (330) and
`verify=False` (295) have **no sink rule yet** — a quick-fix for a vuln the engine never flags is
dead code (no finding to rewrite, no rescan to prove it). Those land in M23 once their detections do.

**The yield gap (19.1):** the fix loop was **model-only** — no deterministic path — so an offline run
(no key, or a model that returns nothing the validator accepts) declined *everything*. The decline
reasons were correct (soundness held); the low **yield** was the bug.

**What changed**
- **New pure module `llm/quickfix.py`.** `quick_fix_candidates(finding, source_for)` returns 0–1
  AST-targeted patch candidates for the three CWEs, as a git-appliable unified diff (built with
  `difflib`, byte-offset span surgery so `col_offset` is handled correctly, aliases like `import
  yaml as y` preserved by renaming only the `.attr`). Builders: **yaml** `load`/`load_all`/`unsafe_*`
  → `safe_load`/`safe_load_all` (drops a `Loader=` arg — that *is* the safe form); **subprocess**
  `shell=True`→`shlex.split(cmd)` + `shell=False` (only when `shell` is a *literal* `True`, adds
  `import shlex`); **eval** single-arg → `ast.literal_eval` (adds `import ast`, declines exec/compile
  and the globals/locals form). Each builder is **gated on the engine's resolved `finding.callee`**,
  so `pickle.load`/`marshal.load` (same CWE-502/kind, no safe drop-in) and `os.system` (CWE-78, no
  `shell=`) correctly **decline** instead of being mangled. Fully defensive: unreadable/oversized/
  unparseable source, a missing call, or any shape it can't map cleanly → `[]` (no candidate).
- **`generate_fix` (`llm/fix.py`) runs quick-fixes first.** New optional `source_for` param: when
  given, each quick-fix candidate is run through the **same injected validator** (apply → ruff →
  mypy → tests → re-scan clean); a passing one returns `VALIDATED` immediately with **no model call**.
  `client` is now `LLMClient | None` — a quick-fix that validates needs no key; when none validates
  and `client is None` the outcome is `NO_SAFE_FIX`. The quality bar is identical: an unproven patch
  is never emitted, whatever produced it.
- **Provenance plumbing (for 19.4's badge).** New `FixProvenance` enum (`deterministic`/`model`) on
  `FixSuggestion` (default `model`, so the parsed model path is unchanged) and on `ValidatedFix`
  (additive — the platform `parse_suggestions` ignores unknown fields, so old/new docs both ingest).
  `build_validated_fix` and `generate_suggestions` thread it through.
- **Fix-yield metric (`llm/suggest.py`).** `deterministic_fixable(scored)` (the denominator) +
  `fix_yield(validated, fixable)` (clamped `[0,1]`). **Documented target: 1.0 for the quick-fix CWEs
  offline** — proven by `test_fix_yield_is_total_for_the_quickfix_cwes` (3 CWEs in one project, all 3
  come back validated with no model call).
- **CLI `fix` (`cli/main.py`).** No longer exits 2 when no model key — it runs quick-fixes offline
  first; only when none apply does it report `NO_SAFE_FIX` (exit 1) with the missing-key hint. Output
  now badges the origin: "Validated patch found (deterministic quick-fix)" vs "(model, confidence: …)".
- **README.** New paragraph in the *Validated fixes* section: the three deterministic quick-fixes
  work with **no model key**, run before the model, and are accepted only after the same validator.

**Tests**
- `tests/test_fix_gap.py` — 19.1's yield `xfail(strict)` **marker removed**; now a plain green
  regression (offline `yaml.load` → validated `safe_load`, provenance `deterministic`).
- `tests/test_quickfix.py` (new, 17 tests) — **pure** (the exact rewrite per CWE; alias preserved;
  Loader dropped; and the five **decline** shapes: pickle/os.system/non-literal-shell/eval-with-
  globals/non-quickfix-CWE/unreadable source) + **end-to-end** (a `_NeverCalledClient` proves the
  quick-fix needs no model call; real validator via git/ruff/rescan; pickle declines then the
  key-less model yields nothing; fix-yield = 1.0 over a 3-CWE project; metric bounds).
- `tests/test_cli.py` — `test_fix_requires_model_key` rewritten to the new contract (os.system, no
  key → exit 1 "no safe fix" + key hint); new `test_fix_deterministic_quickfix_works_offline`
  (yaml, no key → exit 0, "deterministic quick-fix", `yaml.safe_load`).

**Soundness/scope:** detection untouched (benchmark recall still 0-missed); the quick-fix changes
*how a fix is produced*, never a tier/score/ranking. Every emitted patch — deterministic or model —
clears the identical 17.1 validator, so "never bogus" holds.

**Deferred / next:** **19.4** (fix-centric card redesign — surface the new `provenance` as a
"deterministic vs model" badge + "Fix ready" state, `dashboard-v1.2`). The remaining CWE quick-fix
templates (weak hash, insecure RNG, `verify=False`) wait on their **detections** in M20/M23, then
generalize this exact set. Live e2e (real PR → offline quick-fix suggested → card renders) stays
credential-gated by prior-task precedent; every hop is proven hermetically here.

---

## Task 19.2 — Repair the fix→dashboard visibility pipeline  (2026-06-15)

**Status:** complete. **No new dependency.** Gate green: `ruff check` clean, `ruff format --check`
clean (60 files), `mypy --strict src platform/vulnadvisor_platform` clean (117 files), **src pytest
897 passed / 1 skipped / 1 xfailed**, **platform pytest 215 passed / 1 pre-existing unrelated fail**
(`test_llm.py::test_complete_without_byo_key_is_graceful_noop` — 502≠200, fails identically with my
production changes stashed; the LLM-proxy router is untouched here). The remaining src `xfailed` is
19.1's **yield** test (`tests/test_fix_gap.py`), which stays red until 19.3.

**Maintainer decisions (asked up front):** (1) single source of truth = **`scan --upload
--suggestions <file>`** (reuse the existing tested plumbing; works on push *and* PR) over a unified
`suggest --upload`; (2) SCA scope = **pipeline only** — make the schema/ingest/read-join carry+join
an SCA fix (proven with a seeded fix), defer real SCA fix *generation* (deterministic version-bump
patches) to 19.3.

**Root of the visibility gap (19.1):** the generated workflow ran `scan . --upload` **without**
`--suggestions` and a separate `suggest` that only posted to GitHub — so `Scan.suggestions` stayed
empty and 17.5's read join surfaced nothing, independent of yield. Join-key parity was already fine.

**What changed**
- **Generated workflow (`setup_pr.py: render_workflow`).** Now three steps wired to one document
  (`FIXES_DOC = "vulnadvisor-fixes.json"`): (1) **Generate validated fixes** — `vulnadvisor fix
  --suggest-json vulnadvisor-fixes.json --path .` (runs the loop **once**); (2) **Scan and upload**
  — `vulnadvisor scan . --upload --suggestions vulnadvisor-fixes.json` (carries the report **and**
  the fixes to `Scan.suggestions`, on push and PR); (3) **Suggest** (PR-only) — `vulnadvisor suggest
  --from vulnadvisor-fixes.json` posts the *same* document in-line (no second fix loop). The fix
  step carries the platform proxy creds (`VULNADVISOR_API_KEY`/`API_URL`) **and** the three optional
  direct model-key secrets (a direct key keeps source on the runner); the suggest step now carries
  only `GITHUB_TOKEN`. `render_pr_body` updated honestly: the fix step sends per-finding code context
  to the platform (or a direct key if set); the scan uploads report **+ validated fixes**; the PR
  step posts them.
- **CLI (`cli/main.py`).** `_fix_suggest_json` now builds its client with **`build_suggest_client`**
  (direct key wins, else the platform proxy — so the CI fix step needs no model-key secret) and is
  **graceful** when no client is available at all: it writes an empty (valid) `SuggestionReport` and
  exits 0, so a not-yet-keyed repo onboards green and the downstream `--suggestions` file always
  exists (mirrors `scan --upload`'s v1.0.5 missing-key skip). New `--from <file>` on **`suggest`**
  loads a pre-generated document and posts it **without re-scanning/re-validating** (the workflow's
  single-source-of-truth seam); defensive load → `BadParameter` on a corrupt artifact. Extracted
  `_write_suggestions_doc` / `_read_suggestions_doc` helpers.
- **SCA join id (`llm/fix.py`).** New pure `sca_finding_id(package, advisory_id) -> "<pkg>:<adv>"`
  (added to `__all__`) — the dependency analogue of `sast_finding_id`'s `<file>:<line>:<kind>`, so a
  validated SCA fix persists on `Scan.suggestions` and the read API joins it. The existing
  `parse_suggestions`/`_proposed_fixes` already carry any well-formed fix row verbatim (an SCA fix
  anchors on its manifest `file:line`), so no ingest/read change was needed — only a defined key + a
  round-trip test.

**Tests**
- `platform/tests/test_fix_gap.py` — the 19.1 **visibility** xfail is now a **plain green**
  regression: the workflow uploads `--suggestions`, generates the doc once (`fix --suggest-json`),
  and reuses it (`suggest --from`).
- `platform/tests/test_setup_pr.py` — `EXPECTED_WORKFLOW` snapshot + structure test rewritten for
  the three-step layout (fix env carries proxy + direct keys; scan uploads `--suggestions`; suggest
  carries only `GITHUB_TOKEN`, no API/model creds).
- `platform/tests/test_github.py` — setup-PR assertion updated to the new three runs.
- `platform/tests/test_read.py` — new `test_findings_response_carries_sca_proposed_fix`: a seeded
  **SCA** fix keyed by `sca_finding_id` round-trips ingest→read and joins to its dependency finding
  by `<package>:<advisory_id>` (the SAST join test + cross-org 404 leak test still green).
- `tests/test_cli.py` — `fix --suggest-json` no-key test rewritten to assert the **graceful empty
  doc + exit 0**; new proxy-fallback test (no direct key → platform proxy validates a fix); three
  `suggest --from` tests (posts without re-scanning/re-validating — `build_matcher`/`build_suggest_client`
  raise if called; dry-run needs no token; malformed doc → exit 2). `scan --upload --suggestions`
  local-upload e2e (`test_scan_upload_attaches_suggestions`) unchanged and green.

**Soundness/scope:** pure presentation — no tier/score/ranking touched; the fix never changes the
deterministic verdict. Privacy copy kept honest about what each path sends. **Dashboard untouched**
(no `npm` gate needed); SCA *rendering* on the card is 19.4, SCA fix *generation* is 19.3.

**Deferred / next:** 19.3 (raise fix yield with deterministic quick-fixes — turns the remaining
`tests/test_fix_gap.py` yield xfail green and produces real SCA version-bump fixes for this pipeline
to carry). A live CI e2e (real PR → fixes uploaded → card renders) stays credential-gated by
prior-task precedent; every hop is proven hermetically here.

---

## Task 19.1 — Root-cause trace: why zero fixes *and* why none were visible (diagnosis)  (2026-06-15)

**Status:** complete. **Diagnosis only — no production code touched.** Full gate green with the two
intentional reds recorded as strict-xfail: `ruff check` clean, `ruff format --check` clean (198
files), `mypy --strict src platform/vulnadvisor_platform` clean (117 files), **pytest 891 passed, 1
skipped, 2 xfailed**. `git diff` adds only `docs/fix-gap-trace.md` + two test files (no `src/` /
`platform/` production module).

**Both failures measured, attributed, reproduced.**

- **Yield gap.** The fix loop (`llm/fix.py` `generate_fix` / `llm/suggest.py` `generate_suggestions`)
  is **model-only** — there is no deterministic quick-fix path. Reproduced on a seeded `yaml.load`
  fixture (one alarming CWE-502 `possible-flow` finding, id `app.py:5:unsafe-deserialization`):
  `generate_fix` returns `no-safe-fix` both when the model errors (no key →
  `model call failed: no model key configured`) and when it returns empty/garbage
  (`response was not a valid fix JSON object`). On pygoat the platform-proxy client *latched*
  unavailable after the first call, so every finding declined for the same "no usable model" reason.
  The decline reasons are *correct* (soundness holds); the low **yield** is the bug. → repaired in
  **19.3** (deterministic quick-fix set that runs before the model, validated by the 17.1 loop).
- **Visibility gap.** Even a produced fix never reaches the 17.5 finding card. The generated setup
  workflow (`setup_pr.py: render_workflow`) runs `vulnadvisor scan . --upload` **without**
  `--suggestions` and a separate `vulnadvisor suggest` that **only posts to GitHub** via
  `GITHUB_TOKEN`. Confirmed on the rendered workflow: `--suggestions` absent, `suggest --upload`
  absent. So `Scan.suggestions` is always `[]` (`parse_suggestions(None)`), `read.py: _proposed_fixes`
  returns `[]`, and `CodeFindingCard` joins nothing — independent of yield. **Join-key parity is fine
  and not the break:** CLI `sast_finding_id`, `parse_suggestions`, `_proposed_fixes`, and dashboard
  `codeFindingId` all emit `<file>:<line>:<kind>`. Second sub-problem: `generate_suggestions` iterates
  only `ScoredSastFinding`, so **SCA findings get no fix at all**. → repaired in **19.2** (workflow +
  CLI upload the suggestions, SAST **and** SCA).

**Deliverables.** `docs/fix-gap-trace.md` (per-finding decline table + the hop-by-hop visibility
trace with payloads + join-key parity proof + repair attributions). Two failing tests, each
`xfail(strict=True)` so they run+fail today (reported `xfailed`, gate stays green) and force the flip
when fixed (XPASS under strict → remove the marker):
- `tests/test_fix_gap.py::test_yaml_load_yields_a_validated_fix_offline` — yield gap, green in 19.3.
- `platform/tests/test_fix_gap.py::test_setup_workflow_uploads_validated_suggestions` — visibility
  gap, green in 19.2.

**Note for 19.2 / 19.3.** Deleting each `xfail` marker (turning the red into a plain green regression
test) is part of that task; 19.2 will also need to update the `render_workflow` snapshot
(`test_workflow_snapshot` / `EXPECTED_WORKFLOW`) once the workflow uploads suggestions.

---

## v1.0.5: ship suggest + graceful upload skip  (2026-06-15)

**Status:** complete. 891 passed, 1 skipped. Published to PyPI. Pushed to main (`f99510a`).

**What happened.** After the setup PR was opened for `parthav-san/pygoat`, the generated CI workflow failed twice:
1. `scan --upload` exited 1 when `VULNADVISOR_API_KEY` secret wasn't set yet → fixed: missing-key upload now warns + exits 0.
2. `vulnadvisor suggest` was "no such command" → `suggest` existed in source but hadn't been published; fixed by bumping to 1.0.5.

**CI result after fix.** Workflow passed end-to-end: scan ran, `suggest` ran, posted 0 in-line suggestions (22 findings all "no safe fix" — pygoat is intentionally vulnerable). `VULNADVISOR_API_KEY` + `API_URL` confirmed working on render.com deployment.

**What changed**
- `pyproject.toml`: 1.0.4 → 1.0.5
- `src/vulnadvisor/cli/main.py`: `_do_upload` returns early with yellow warning when no API key/URL instead of `Exit(code=1)`

---

## Setup-PR fix: resolve the repo's real default branch from GitHub  (2026-06-14)

**Status:** complete. `ruff` + `ruff format --check` clean, `mypy --strict` clean (40 files),
`pytest tests/test_setup_pr.py tests/test_github.py` 86/86. Full suite 213 passed, 1 pre-existing
unrelated fail (`test_llm.py::test_complete_without_byo_key_is_graceful_noop`, red on clean HEAD).

**Symptom.** Opening the setup PR for `parthav-san/pygoat` failed with *"GitHub App error: base
branch 'main' not found"* — the repo's real default is `master`, but the dashboard showed "default
main". Root cause: `_upsert_repo` (the `installation_repositories` webhook) never sets
`default_branch`, and that webhook payload's repo objects don't carry it, so every synced repo sits
at the model default `"main"`. That stale value was used both as the PR base **and** the workflow's
`on: push` branch — so a non-`main` repo got a PR off a non-existent base and a dead push trigger.

**What changed**
- `github_app.py`: added `default_branch(installation_id, repo_full_name)` /
  `default_branch_with_token(token, repo_full_name)` (+ shared `_default_branch`) — GET `/repos/
  {owner}/{repo}` and return its `default_branch`, defensively (`None` on any failure).
- `routers/github.py`: `open_setup_pr` now resolves the real default branch from GitHub (via the
  same App/OAuth credential it will open the PR with), **self-heals** `repo.default_branch` in the
  DB when it differs, and renders the workflow + PR base from the corrected value. A lookup failure
  is non-fatal — it falls back to the stored value rather than blocking setup. The `_open_setup_pr`
  404 base-branch guard stays as a last-resort safety net.
- Tests: `test_github.py` self-heal case (`master` repo → PR base + workflow push trigger both
  `master`, stored value flips); `test_setup_pr.py` unit tests for `default_branch` (reports
  GitHub's value; `None` on a 404 lookup), plus a `GET /repos/{owner}/{repo}` route on the stateful
  GitHub fake. Fake `_FakeApp` gained the two methods + a `default_branch_value` knob.

**Why.** GitHub is the source of truth for the default branch; the stored value is a sync-time guess
that the webhook can't populate. Resolving at setup time (and self-healing the row) fixes both the
PR base and the push trigger in one place, and makes the dashboard's "default <branch>" honest.

---

## Setup-PR UX fix: PUBLIC_API_URL falls back to the request host  (2026-06-14)

**Status:** complete. Platform gate green for the touched areas — `ruff check` + `ruff format
--check` clean, `mypy --strict` clean (40 files), `pytest tests/test_setup_pr.py
tests/test_github.py` 83/83. (One pre-existing, unrelated failure remains in
`tests/test_llm.py::test_complete_without_byo_key_is_graceful_noop` — it fails identically on clean
HEAD; not touched here.)

**Symptom.** A user forked a repo, hit **Open setup PR**, and got a 500 surfaced verbatim in the
dashboard: *"API URL points at localhost ('http://localhost:8000'); set PUBLIC_API_URL…"*. Root
cause: the deployment never set `PUBLIC_API_URL`, so it stayed at the dev default and the Task-C
guard hard-failed before opening any PR. Bad UX for a config the platform can usually infer itself.

**What changed**
- `setup_pr.py` (pure): added `public_api_url_from_request(scheme, host, forwarded_proto)` —
  reconstructs the platform's own public base URL from the inbound request (prefers
  `X-Forwarded-Proto` since we sit behind Fly's TLS proxy; `Host` carries the public hostname).
  Added `resolve_workflow_api_url(configured, derived)` — an explicit public `PUBLIC_API_URL` always
  wins; if it's the localhost/private default, fall back to the request-derived URL; only when
  **neither** is reachable does it return the actionable `PUBLIC_API_URL` problem.
- `routers/github.py`: `open_setup_pr` now takes `request: Request`, derives the fallback URL, and
  bakes the resolved URL into the workflow. Still 500s (with the same hint) when nothing is reachable
  — soundness preserved: we never ship a loopback workflow that CI can't reach.
- `docs/deploy.md`: `PUBLIC_API_URL` reworded from "must be set" to "set it to pin the exact URL;
  otherwise it's auto-derived from the request, refused only when no reachable URL exists".

**Why.** A correctly-deployed platform (dashboard `/api` proxy → platform's public URL) reaches the
backend over its real public ingress, so the request itself already carries the URL we need to bake
in — no reason to demand a duplicate env var. The localhost guard stays for genuine local dev, where
there *is* no public URL and a shipped workflow would silently never reach the platform.

**Tests.** `test_setup_pr.py`: table tests for both new pure helpers (forwarded-proto precedence,
proto fallback, comma chains, missing host; configured-wins / request-fallback / no-reachable-URL).
`test_github.py`: replaced the old hard-500 test with two — localhost config now falls back to the
request host and opens the PR (workflow bakes `https://test`, not localhost); a request arriving on
a loopback `Host` still 500s with the `PUBLIC_API_URL` hint.

---

## One-click setup — Task E: dashboard secret_set UX + one-click consent  (2026-06-14)

**Status:** complete, dashboard gate green (npm test 73/73, eslint clean, `next build` compiled +
typecheck clean). Dashboard-only; no backend change (the API already returns `secret_set` (Task B)
and a 409 with `/v1/auth/github/login?setup=1` in its detail). Closes the one-click-setup arc
(A–E): a user can now finish onboarding without ever touching GitHub Settings.

**What changed**
- `lib/types.ts`: `SetupPrResponse.secret_set: boolean`.
- `lib/setup.ts` (new, pure): `SETUP_OAUTH_PATH` (`/api/v1/auth/github/login?setup=1`, same-origin
  proxy) + `oauthPopupReturned(popupOrigin, popupHref, selfOrigin)` — the popup-return detector.
  It fires **only** once same-origin AND off any `/auth/github` route AND not `about:blank`, so
  neither the start login URL (same-origin!) nor the opener-origin-inheriting blank document
  triggers a premature retry. Unit-tested in `lib/setup.test.ts` (+5).
- `app/setup/repo-setup-row.tsx`: on success shows "Repository secret configured automatically."
  when `secret_set`; when `secret_set` is false **or** the POST 409s, shows a one-click **Grant
  repository access** button that pops the incremental-OAuth flow and **auto-retries the setup-PR
  POST on return** (poll `popup.closed` + `oauthPopupReturned`; interval cleared on unmount). The
  401/403/502 paths and idempotent "updated in place" copy are unchanged.

**Why these choices.** Popup + poll keeps it dashboard-only (the existing callback redirects to the
dashboard root, carrying no return path) and works with the same-origin `/api` proxy so the session
cookie rides along. The return detector is the one piece with real edge cases (the login URL shares
our origin; `about:blank` can inherit it), so it's extracted pure and table-tested rather than
buried in the component. A blocked popup degrades to a clear message, never a dead button.

**Deferred (prior-task precedent):** a live browser e2e of the consent→retry round-trip against a
real GitHub account (the detector, the 409/secret_set branching, and the retry wiring are proven by
the unit test + the typed build). **Next:** the deferred live e2e checks across A–E, or the
remaining v2.1.0 tag work.

---

## One-click setup — Task D2: CLI suggest via the platform proxy + zero-config fallback key  (2026-06-14)

**Status:** complete, automated gate passing (ruff + format + mypy --strict + full pytest 876
passed / 1 skip). Second half of Task D: the CLI `suggest` loop now runs its model call through the
D1 endpoint, so a CI workflow needs **no model-key secret**. Plus a maintainer-requested amendment
to D1 — a **platform fallback model key** so suggestions work zero-config even before an org saves
its own BYO key.

**Maintainer decisions (this turn).** (1) `suggest` prefers a direct model key when one is set
(source stays on the runner), else the platform proxy. (2) No-key / spent-cap → graceful no-op,
exit 0, never fail the build. (3) Add a platform fallback key (BYOM pressure off the org). The
fallback key is a **no-credit OpenRouter key**, so its model must be an explicit `:free` model
(`deepseek/deepseek-r1:free`) — `openrouter/auto` routes to paid and would fail. **The key is NOT
committed**: it lives in the gitignored `platform/.env` (local) / a fly secret (prod), sourced via
`os.environ` per the standing no-hardcoded-secrets rule.

**What changed**
- **Platform fallback (amends D1).** `config.py`: `copilot_fallback_api_key` + `copilot_fallback_model`
  (env-only, empty default = disabled). `routers/llm.py`: key selection is now org BYO key → fallback
  key → `available=False`; the fallback path uses the configured free model (request `model` still
  wins). Decrypt moved before `consume_grant` so a corrupt ciphertext 500s without metering.
- **CLI proxy client.** New `src/vulnadvisor/llm/proxy.py` — `PlatformSuggestClient` implements the
  `LLMClient` Protocol over the project `Transport`, POSTing to `/v1/llm/complete` with the org API
  key. It **latches** "unavailable" on an `available:false` body or a 429, so a key-less org costs at
  most one round-trip across the whole sweep; a transient 502 is per-attempt (retries). Defensive
  parse (bad JSON / non-object / missing/blank/non-string text → `LLMError`).
- **CLI rewire.** `main.py`: `build_platform_suggest_client` (creds resolved env→login store, like
  `scan --upload`) + `build_suggest_client` (direct key wins, else proxy), both module-level for test
  substitution. `suggest` uses `build_suggest_client`; the missing-client message names both options.
  `fix --suggest-json` stays direct-key only (local-first). The suggest docstring now states the
  proxy sends the fix-prompt's code context to *your* platform (honesty: validation still runs in CI).
- **Workflow + PR body (`setup_pr.py`).** The suggest step drops `OPENROUTER_/OPENAI_/ANTHROPIC_API_KEY`
  and now carries `VULNADVISOR_API_KEY` + `API_URL` (GITHUB_TOKEN still posts). PR body: "no model-key
  secret to add"; the "what leaves CI" note is now accurate (suggest sends code around each finding to
  the platform; an opt-in direct-key path keeps source on the runner). Workflow header comment updated.
- **Docs.** `docs/deploy.md`: optional `COPILOT_FALLBACK_API_KEY`/`COPILOT_FALLBACK_MODEL` fly-secrets
  block with the free-model caveat.

**Why these choices**
- A direct key still keeps source in CI; the proxy is the zero-config default. Honest PR-body copy on
  the trade-off (code context → your own platform) keeps the privacy posture truthful rather than
  silently broadening what leaves CI.
- The proxy latch bounds wasted calls for a key-less org to one; a 502 is treated as transient so a
  blip doesn't permanently silence the run. Both keep the build green (the loop records a failed
  attempt and moves on).

**Validation evidence**
- `ruff check` / `ruff format --check` (src + platform + tests) — clean.
- `mypy --strict src platform/vulnadvisor_platform` — Success, 117 files.
- `pytest` — **876 passed, 1 skipped** (+15). New `tests/test_proxy.py` (11): request contract
  (URL/Bearer/body, model included only when set, sentinel model id), `available:false` latch (one
  call), 429 latch, transient-502 retry, 5-case malformed→`LLMError`. `tests/test_cli.py`: suggest
  falls back to the proxy when no model key; no-key-anywhere→exit 2 naming both options (replaces the
  old requires-model-key test); existing suggest happy-paths unchanged (direct key wins).
  `platform/tests/test_llm.py` (+3): fallback key drives the call + uses its free model; org key wins
  over fallback; request model overrides the fallback model. `platform/tests/test_setup_pr.py`:
  workflow snapshot + structure assert the suggest step has VULNADVISOR_API_KEY+API_URL and **no**
  model-key env; PR-body asserts the zero-config copy.

**Open questions / next.** Task D fully done. **Live e2e deferred** (prior-task precedent): a real PR
with the proxy generating a real patch via the fallback key end-to-end (the contract, latch, cap, and
key selection are all proven hermetically). **Next: Task E** — dashboard `secret_set` UX + auto-consent
(`SetupPrResponse.secret_set`, the 409 "needs repo access" retry); read `node_modules/next/dist/docs/`
first per `dashboard/AGENTS.md`.

---

## One-click setup — Task D1: platform-proxy `/v1/llm/complete` endpoint  (2026-06-14)

**Status:** complete, automated gate passing (ruff + format + mypy --strict + full pytest 861
passed / 1 skip). First half of Task D — the **platform endpoint**; D2 (CLI rewire of `suggest` +
the workflow/PR-body edits to drop the model-key secrets) is the next turn. Split agreed with the
maintainer up front: the seam spans a new server-side LLM call *and* a CLI rewire, so each half
gets its own green gate + commit.

**Goal.** `vulnadvisor suggest` in CI should need **no model-key secret**: it authenticates with
the existing `VULNADVISOR_API_KEY` and the platform performs the LLM call server-side using the
org's BYO copilot key (under the daily cap). This endpoint is that server-side call.

**The seam (recon).** The whole validated-fix loop (`generate_suggestions`→`generate_fix`) depends
only on the `LLMClient` Protocol (`complete(system, user)->str`), and `_validate_fixes` already
takes an injected client — so D2 just supplies a proxy client; nothing in the loop/validator/poster
changes. Platform pieces already lined up: org-API-key auth (`CurrentApiKey`), `consume_grant` +
`decrypt_api_key` (copilot.py). The **one** genuinely new capability: the platform never called a
model server-side before (copilot only hands the key to the dashboard) — it now does, reusing the
CLI's dependency-free clients.

**What changed**
- `src/vulnadvisor/llm/client.py`: extracted `build_fix_client_for_key(api_key, *, provider?,
  model?, transport?)` — the single place the OpenAI/OpenRouter/Anthropic routing + endpoint URLs
  live. `build_fix_client_from_env` now delegates to it (behaviour byte-identical; existing 17.3
  tests stayed green). The platform reuses it so the server-side call is identical to the local
  `fix` path.
- `platform/.../routers/llm.py` (new) — `POST /v1/llm/complete`, authed by the org API key. Resolves
  the org from the key; **no copilot key → `available=False`, no grant consumed** (graceful no-op,
  the maintainer-locked behaviour); else `consume_grant` (429 on a spent daily cap) → `decrypt_api_key`
  (500 on a corrupt ciphertext) → build the client for the decrypted key → run `complete` via
  `run_in_threadpool` (the urllib transport is blocking; keep it off the event loop) → **commit the
  grant only after the call succeeds**. An `LLMError` → 502 with the grant left unconsumed.
- `schemas.py`: `LlmCompleteRequest` (system/user/optional model, bounded lengths) +
  `LlmCompleteResponse` (`available`/`text`/`remaining_today`). `app.py`: router registered.

**Why these choices**
- The decrypted BYO key never leaves the platform — only the model's text output is returned
  (mirrors the copilot grant's trust posture; here there's no service token because the org API key
  *is* the user-facing auth).
- Grant-consumed-only-on-success (commit last) means a 429 cap or a 502 model failure never burns
  budget; the CLI's fix loop already treats a per-call `LLMError` as a failed attempt and moves on,
  so a 502 keeps the build green and honest (no silent success).
- No-key → `available=False` rather than an error, so D2's `suggest` posts nothing and never fails
  the build (the locked graceful-no-op decision, covering both no-key and cap-spent).

**Validation evidence**
- `ruff check` / `ruff format --check` (src + platform) — clean.
- `mypy --strict src platform/vulnadvisor_platform` — Success, 116 files.
- `pytest platform/tests/test_llm.py` — 7 passed. Full suite — **861 passed, 1 skipped** (+7).
  New `test_llm.py`: no-BYO-key→`available=False` + zero grants; org key drives the call (decrypted
  key + requested model + prompt captured, `remaining_today` decrements, `used_today`=1); model
  defaults to None downstream; daily cap [1,0]→429; an `LLMError`→502 with the grant **not** burned
  (`used_today`=0); a corrupt ciphertext→loud 500 ("re-save"); no API key→401. The model call is
  monkeypatched in the router namespace (no network) — provider routing stays unit-tested in
  `tests/test_llm.py` (src).

**Open questions / next (D2).** Add a CLI `LLMClient` that POSTs to `/v1/llm/complete` with
`VULNADVISOR_API_KEY`; rewire `suggest` to **prefer a direct model key if present, else the platform
proxy** (maintainer-locked); treat `available=False`/429 as a graceful no-op (exit 0). Drop
`OPENROUTER_/OPENAI_/ANTHROPIC_API_KEY` from `render_workflow`'s suggest step + the "add a model key"
PR-body copy (now only `VULNADVISOR_API_KEY` + `GITHUB_TOKEN`), and update the `test_setup_pr.py`
workflow snapshot. Then Task E (dashboard `secret_set` UX + auto-consent).

---

## One-click setup — Task C: API-URL guard (kill the localhost-in-workflow bug)  (2026-06-14)

**Status:** complete, automated gate passing (ruff + mypy --strict + full pytest 854 passed/1 skip).

**Root cause of friction #2.** `public_api_url` defaults to `http://localhost:8000` (config.py) and
is baked verbatim into the setup workflow; the deploy guide never set `PUBLIC_API_URL` in prod, so
shipped workflows pointed at localhost and CI uploads silently failed.

**What changed**
- `setup_pr.py`: new pure `api_url_problem(api_url) -> str | None` — returns an operator-facing
  reason the URL is unreachable from CI (bad scheme, no host, `localhost`/`*.localhost`, or an IP
  that is loopback/private/link-local/unspecified/reserved via stdlib `ipaddress`), else None. A
  real DNS hostname is assumed public (we don't resolve it).
- `routers/github.py` `open_setup_pr`: calls the guard right after the repo checks and **before any
  GitHub work**; a problem raises 500 (platform-misconfig, not the caller's fault) with the reason.
- `docs/deploy.md`: the backend `fly secrets set` block now sets `PUBLIC_API_URL`, with a note that
  it must be set and that the endpoint refuses loopback/private URLs — fixing the actual root cause
  alongside the guard.

**Why these choices**
- Guard is a pure function so the host/IP matrix is table-tested without a server; the endpoint test
  only confirms the wiring (500 + no GitHub calls).
- 500 not 409: the caller can't fix a server-side config value; the detail tells the operator what
  to set. Fail-fast before opening a PR or writing a secret, so a misconfig never half-applies.
- DNS hostnames pass without resolution — avoids network in a pure function and false negatives on
  split-horizon DNS; loopback/private *literals* (the realistic misconfig) are what we catch.

**Validation evidence**
- `ruff check platform` / `ruff format --check platform` — clean.
- `mypy --strict src platform/vulnadvisor_platform` — Success, 115 files.
- `pytest platform/tests/test_github.py test_setup_pr.py` — 71 passed. Full suite — 854 passed,
  1 skipped. New: a 4-case accepts table + a 14-case rejects table for `api_url_problem`, and an
  endpoint test proving a localhost `public_api_url` → 500 with no setup/secret calls. `_overrides()`
  now uses a public api URL so the existing setup-PR endpoint tests still pass the guard.

**Open questions / next**
- Task D (platform-proxy `suggest`, drop model-key secrets from the workflow) and Task E (dashboard
  auto-consent + `secret_set` copy) remain.

---

## One-click setup — Task B: auto-write the VULNADVISOR_API_KEY secret  (2026-06-14)

**Status:** complete, automated gate passing (ruff + mypy --strict + full pytest 835 passed/1 skip).

**What changed**
- `setup_pr.py`: new `API_KEY_SECRET_NAME = "VULNADVISOR_API_KEY"` constant (the one secret the
  workflow authenticates with), so the name has a single source of truth.
- `schemas.py`: `SetupPrResponse` gains `secret_set: bool` — True when the secret was auto-written,
  False when no write-capable credential was available (Task E will prompt for access).
- `routers/github.py` `open_setup_pr`: after the PR's state is committed, if a write-capable user
  OAuth token is available it mints an org API key and writes it as the repo's `VULNADVISOR_API_KEY`
  secret via the new `GitHubSecretsDep` (Task A). Helpers:
  - `_optional_user_setup_token` — no-raise variant of `_user_setup_token`; returns the decrypted
    write-capable token or None. Lets the App path opportunistically auto-set the secret when the
    user also granted repo scope, while a missing token just means `secret_set=False` (not an error).
  - `_write_api_key_secret` — mints the key, PUTs the secret, and only **after** GitHub accepts it
    persists the new `ApiKey` (named `setup:{repo}`) and revokes any prior live key of that name, so
    re-clicks rotate the secret without accumulating live keys. A GitHub rejection raises 502 (the
    PR is already open; the next click retries idempotently); no key is persisted on failure.

**Why these choices (per the decisions locked before Task A)**
- OAuth-token path is primary: writing secrets needs only the `repo` scope the setup token already
  carries, so existing GitHub App installs are untouched (no `secrets: write` re-consent).
- PR state is committed *before* the secret step so a secret failure never hides that the PR opened
  (honesty over a clean-looking rollback) — and the flow is idempotent on retry.
- Persist-after-accept ordering means a failed secret write leaves the repo's prior secret/key valid
  and adds no orphaned key (soundness: never half-apply a credential change).

**Validation evidence**
- `ruff check platform` / `ruff format --check platform` — clean.
- `mypy --strict src platform/vulnadvisor_platform` — Success, 115 files.
- `pytest platform/tests/test_github.py test_setup_pr.py` — 52 passed. Full suite — 835 passed,
  1 skipped. New endpoint tests: OAuth path sets the secret + persists one `setup:web` key; App path
  (no user token) → `secret_set=False`, no secret call; reclick rotates the key (2 keys, 1 live);
  secret-write failure → 502 with the PR still recorded and no key persisted.

**Open questions / next**
- Dashboard `SetupPrResponse` type doesn't yet know `secret_set` (extra field ignored at runtime —
  no breakage); Task E will consume it for the "secret configured" copy + auto-consent retry.
- Task C (api-url guard) and Task D (platform-proxy `suggest`) still pending.

---

## One-click setup — Task A: encrypted repo-secret writer  (2026-06-14)

**Status:** complete, automated gate passing (ruff + mypy --strict + full pytest).

**Context.** First slice of the "true one-click, zero-config setup PR" architecture. Decisions
locked with the user up front: model key for `vulnadvisor suggest` → **proxy via platform** (reuse
the BYO copilot key + daily cap); primary credential → **the user's `repo`-scoped OAuth token** (no
GitHub App permission change, so existing installs are undisturbed); secret scope → **per-repo**.
Remaining slices (B wire-in, C api-url guard, D platform-proxy suggest, E dashboard auto-consent)
are not started.

**What changed**
- New dependency: `pynacl==1.5.0` in the `platform` group. GitHub Actions secrets must be encrypted
  client-side with the repo's public key via libsodium's sealed box (`crypto_box_seal`);
  `cryptography` does not expose that construction, PyNaCl does. Ships `py.typed`, so no mypy
  override needed.
- New `platform/vulnadvisor_platform/github_secrets.py`:
  - `encrypt_secret(public_key_b64, value)` — pure sealed-box encryption returning the base64 the
    PUT expects; a malformed key raises `GitHubSecretsError`, never a raw crypto error.
  - `GitHubSecrets.put_repo_secret(...)` — fetch the repo's Actions public key, then
    `PUT /repos/{repo}/actions/secrets/{name}`. 201→created, 204→updated; any 4xx surfaces GitHub's
    own `message` (mirrors the github_app 502-detail pattern). Needs only `repo` scope.
  - `get_github_secrets` / `GitHubSecretsDep` FastAPI dependency for Task B wire-in + test override.
- New `platform/tests/test_github_secrets.py` (10 tests): encrypt round-trips and is not plaintext;
  fresh ciphertext per call; malformed key rejected; the REST path proven against an
  `httpx.MockTransport` fake holding a **real** keypair, so a test decrypts what the client PUT
  (true end-to-end encryption), plus 204-update, 404-public-key, malformed-key, and 403-permission.

**Why these choices**
- Encryption kept a pure function so correctness is provable offline; only the two-call dance needs
  the network fake. Matches the existing setup-PR test style.
- Per-call `token` (not settings-bound) so the same client serves both the OAuth path now and an
  installation-token path later without change.

**Validation evidence**
- `ruff check` / `ruff format --check` — clean.
- `mypy --strict src platform/vulnadvisor_platform` — Success, no issues in 115 files.
- `pytest platform/tests/test_github_secrets.py` — 10 passed. Full suite — 833 passed, 1 skipped.

**Open questions**
- None blocking. Task B will mint an org key and call `put_repo_secret` from `open_setup_pr`.

---

## Task 17.5 — Proposed fix in the dashboard finding card (demo-ready)  (2026-06-14)

**Status:** complete, full automated gate passing (CLI/src + platform + dashboard). **No new
dependency, no new table, no migration** — pure surfacing of the validated fixes already stored on
`Scan.suggestions` (17.2). The whole loop (vulnerability → source→sink evidence → machine-validated
fix) now reads in **our own UI**: opening a SAST finding on the scan page shows its proposed patch
inline. Dashboard-only payoff; ships independently of the v2.1.0 CLI tag (candidate `dashboard-v1.1`).

**Soundness shape:** the panel is **pure presentation** — it renders stored data and changes no
tier/score/ranking. The wording keeps the contract: a *suggested, machine-validated* patch, **never
auto-applied** (the commit happens on the GitHub PR). A finding with no stored fix renders **no
panel** (most won't have one). Read access rides the existing org-scoped findings endpoint, so the
stored patch inherits the same tenant isolation (no separate leak path).

**Join model (maintainer choice: sibling list, not per-finding attach):** the read API returns a
scan's stored fixes as a **`suggestions` list on the findings response**; the dashboard joins each to
its code finding by **`finding_id` = `<file>:<line>:<kind>`** — exactly the id the CLI assigns
(`llm/fix.sast_finding_id`) and the platform stores. No new table; the stored rows are reused.

**The pieces:**
- **Platform read API (`schemas.py` + `routers/read.py`).** New `ProposedFix` response model
  (`finding_id`/`diff`/`rationale`/`confidence`). `FindingsResponse` gains `suggestions:
  list[ProposedFix] = []`. `list_findings` builds it via a **defensive** `_proposed_fixes(scan)` —
  the rows were cleaned at ingest, but a row lacking a `finding_id` or a non-empty `diff` is skipped
  (never an empty panel), confidence coerced to a safe default. No filtering: all stored fixes are
  returned and the client join naturally limits what renders.
- **Dashboard.** `types.ts`: mirror `ProposedFix` + optional `suggestions` on `FindingsResponse`.
  New pure `lib/fix.ts`: `codeFindingId(finding)` (the join key) + `parseDiffLines(diff)` (a
  defensive unified-diff parser — any string parses, never throws) + `diffLineClass` (**Aegis**
  mapping: removed/vulnerable line = risk-red, added/fixed line = safe-teal, headers muted). The
  expanded `CodeFindingCard` gains a **"Proposed fix" panel** — the diff with add/remove styling, a
  confidence chip, a **copy-diff** button (generalized `CopyFixButton` with an `ariaLabel`), the
  model's rationale, and the "never auto-applied" note; Card C's action line flips to "A validated
  patch is proposed below." when a fix is present. The scan page joins `findings.suggestions` to each
  code finding by `codeFindingId` and threads it as `proposedFix`. The demo dataset (dependency-only)
  and the diff page are untouched — `proposedFix` defaults undefined → no panel.

**Validation:** ruff + format clean (190 files) · `mypy --strict src` clean (85) / `platform` clean
(29) · **pytest 823 passed, 1 skipped** (+3 in `platform/tests/test_read.py`: the findings response
**carries the fix joined by the recomputed `<file>:<line>:<kind>` id** — diff/rationale/confidence
surfaced; a scan with no uploaded fixes returns `suggestions == []`; an unauthorized caller 401/404s
on the findings endpoint, so the stored patch never leaks). **Dashboard:** `npm run lint` clean ·
`npm test` **68/68** (+4 `lib/fix.test.ts`: `codeFindingId` == the CLI id; diff classification of
headers/add/del/context; defensive empty/non-diff parsing; Aegis add=safe / del=risk, del never
safe) · `npm run build` compiled + typecheck clean.

**Deferred (prior-task precedent):** live browser e2e of a seeded SAST finding with a stored fix
rendering the panel + clipboard copy (the data path is proven hermetically: ingest stores the rows,
the read joins+returns them, the diff parser/styling and join key are unit-tested, the component
builds). **Next:** the optional `dashboard-v1.1` tag + that live spot-check, the deferred
v2.0.0/v2.1.0 live checks, or M18 (launch/benchmark/pitch).

---

## Audit — Release auditor pass before M18 (M12–M17)  (2026-06-14)

**Status:** **audit complete, no code changes needed.** Acted as release auditor for M12–M17 (no
new features, did not start M18). The hermetic gate is fully green, all five cross-cutting
invariants hold, and **no genuine in-code gap or regression was found**. Produced
**`docs/release-checklist.md`** — the single inventory + copy-pasteable runbooks for every
deferred/credential-gated item and the exact blockers for the `v2.0.0`/`v2.1.0` tags. Neither tag
cut (by design both end-of-milestone gates require a live e2e the maintainer must run).

**1. Full gate re-run (real output, not claims):** `ruff check` "All checks passed!" · `ruff format
--check` "190 files already formatted" · `mypy --strict src` Success (85) · `mypy --strict
platform/vulnadvisor_platform` Success (29) · `pytest` **819 passed, 1 skipped** — true split is
`tests/` 665+1 and `platform/tests/` 154 (combined 820 items; PROGRESS elsewhere labels the
combined 819 as "src" — a cosmetic reporting quirk, not a defect, noted in the checklist). Dashboard:
`npm run lint` clean · `npm test` **64/64** · `npm run build` compiled + typecheck clean. **No
failures to fix.**

**2. Cross-cutting invariants — all verified:** (a) JSON `schema_version` 1.0/1.1/1.2 all parse
(`SUPPORTED_SCHEMA_VERSIONS={1.0,1.1,1.2}` + `test_ingest` asserts each). (b) SARIF validates against
the bundled `fixtures/schemas/sarif-2.1.0.json` (Draft7), **including code findings**
(`test_sast_scoring`). (c) Every Alembic migration is **additive** (upgrades only relax-to-nullable
or `add_column` with `server_default`; `drop_*` only in `downgrade()`); chain is linear (single head
`e2d5a8f3c6b1`); started the docker Postgres, `alembic upgrade head` + **`alembic check` → "No new
upgrade operations detected"** (no drift). (d) Core wheel = **exactly 3 runtime deps**
`{packaging,pydantic,typer}`, mcp extra-only (metadata test + pyproject). (e) **No telemetry** — the
only outbound hosts in `src/` are OSV/EPSS/KEV/GitHub + the user's own model key
(anthropic/openai/openrouter) + the user's own configured platform URL; no analytics/sentry SDKs;
`socket.gethostname()` is local-only (device-name for the login key).

**3. Deferred-item inventory (`docs/release-checklist.md`):** runbooks (prereqs, exact commands,
pass criteria, code-complete-vs-gap) for — copilot red-team live (15.1), copilot chat e2e (15.2),
SAST card browser e2e (16.4), GitHub code-scanning SARIF upload (16.4), SCA+SAST+pyscan perf
(16.5), `vulnadvisor fix` live (17.1/17.3), 17.2 App-path in-line suggestion live e2e, 17.4
`GITHUB_TOKEN` zero-setup live e2e, 17.4 P3 OAuth setup-PR spot-check. **Every one is
code-complete** (proven hermetically with scripted/faked clients + real subprocess/rescan +
snapshots + a live-applied additive migration); only live credential-gated verification remains.
The release-blocking **SAST zero-missed gate runs offline today** (`python -m benchmarks --sast` →
100% recall, exit 0) — re-confirmed during the audit.

**4. Tag blockers:** **v2.0.0** waits on two live checks only — SAST card browser e2e + GitHub
code-scanning SARIF acceptance (16.5 benchmark gate already green). **v2.1.0** waits on four live
checks only — `vulnadvisor fix` live, 17.2 App-path e2e, 17.4 `GITHUB_TOKEN` e2e, 17.4 P3 OAuth
spot-check. Both sets are **purely maintainer live verification, no code gap**; neither tag's gate
is green hermetically, so neither was cut. (17.5 dashboard fix card ships as `dashboard-v1.1`, does
not gate v2.1.0, and is not yet implemented — out of audit scope.)

**Next:** the maintainer runs the §3 runbooks with a model key + GitHub credentials, then cuts
`v2.0.0` / `v2.1.0` per §4; or proceed to M18 (launch/benchmark/pitch).

---

## Task 17.4 Part 3 — Hosted onboarding: setup-PR via the user's OAuth token (no App)  (2026-06-14)

**Status:** **Part 3 complete**, full automated gate passing (CLI + platform), migration applied to
**live Postgres** with `alembic check` = no drift. **No new dependency** — token encryption reuses
the 15.1 Fernet helper (`cryptography` already present). With this, all of Task 17.4 is done: the
PR-suggestion payoff now reaches a user with **no GitHub App at all** — either CI posts via
`GITHUB_TOKEN` (Parts 1–2) **or** "Sign in with GitHub → set up repo" opens the setup-PR as the
logged-in user (Part 3).

**Maintainer UX decision (at task start): incremental authorization.** Login stays least-privilege
(`read:user user:email`); the elevated `repo`/`workflow` scopes are requested **only** when the user
clicks "set up repo" and we don't already hold a write-capable token. This protects the trust
posture — most users never grant write — at the cost of one re-auth round-trip + a "needs
authorization" 409 the dashboard surfaces (chosen over requesting broad write scope at every login).

**The four pieces:**
- **Scope-aware OAuth (`github_oauth.py`).** `authorize_url(state, *, write_access=False)` selects
  `read:user user:email` vs. `…repo workflow`. `exchange_code` now returns an **`OAuthToken`**
  (`access_token` + the **granted** `scopes`, parsed defensively from GitHub's comma-separated
  `scope` field → `()` when absent). `has_setup_scopes(scopes)` answers "write-capable?" by requiring
  both `repo` and `workflow` (the latter is mandatory to commit a `.github/workflows/*.yml` file).
- **Encrypted-at-rest persistence (`auth.py` + `models.py` + migration).** The OAuth callback now
  persists the freshest token on the `User` via `_store_oauth_token`, **reusing 15.1's
  `encrypt_api_key`/`decrypt_api_key`** (Fernet keyed by `SECRET_KEY` — no second secret). Two new
  additive nullable `User` columns: `github_token_ciphertext` (String(1024)) + `github_token_scopes`
  (space-joined granted scopes, **in clear** so the setup path checks write-capability without
  decrypting). `/v1/auth/github/login?setup=1` triggers the write-scope authorize; the callback
  persists whatever scopes GitHub grants, so a setup login **upgrades the stored token in place**.
  Alembic `e2d5a8f3c6b1` (revises `c3b9e7d1f4a8`) — applied live, `alembic check` no drift. The token
  is never returned by any endpoint.
- **OAuth branch in `github_app.py`.** Extracted the REST PR choreography into a private
  `_open_setup_pr(token=…)`; `open_setup_pr(installation_id=…)` (mints the installation token, App
  path) and the new **`open_setup_pr_with_token(token=…)`** (user OAuth path) both delegate to it —
  identical idempotent branch/commit/PR logic, only the credential differs.
- **Router wiring (`routers/github.py`).** The setup-PR endpoint now **prefers an App installation**
  (org-wide, bot identity) and **falls back to the user's write-scoped OAuth token** when none is
  installed: `repo_full_name` owner = `installation.account_login` (App) or `user.login` (OAuth).
  `_user_setup_token(user, settings)` decrypts the token or raises a **409** (missing/insufficient
  scope → "install the App, or sign in and grant repo access at `…/login?setup=1`"; an unreadable
  ciphertext after a `SECRET_KEY` rotation → re-auth 409). The existing
  `test_setup_pr_requires_installation` still passes (the 409 message still says "install").

**Validation:** ruff + format clean (src 85 / platform 55) · `mypy --strict src` clean (85) /
`vulnadvisor_platform` clean (38) · **src pytest 819 passed, 1 skipped** · **platform pytest 154
passed** (+5). New platform tests: `test_auth.py` +3 — `?setup=1` requests `repo+workflow` scope
(plain login doesn't); the callback **stores the token encrypted** (ciphertext ≠ plaintext, decrypts
back, read-only scopes recorded); a setup callback **upgrades the stored scopes** to include
repo/workflow. `test_github.py` +2 — **no App + a write-scoped OAuth token opens the PR via
`open_setup_pr_with_token`** (owner = `octocat`, the token threaded, not the App path) and the status
chip flips to `pr-open`; a **read-only token → 409** ("grant repository access") with no GitHub call.
**Live Postgres:** `alembic upgrade head` (`c3b9e7d1f4a8 → e2d5a8f3c6b1`) + `alembic check` → no drift.

**Deferred (by prior-task precedent / scope):** (1) **Live spot-check** of the OAuth setup-PR against
a real scratch repo (a logged-in user with `setup=1` opening a real PR) — the choreography, scope
upgrade, encryption, and credential-selection are all proven hermetically with a faked client.
(2) **Dashboard wiring** of the `needs-authorization` 409 → a "Connect GitHub to set up" button
linking `…/login?setup=1` (the API contract is in place; the UI is a follow-up). (3) **Cosmetic:**
`render_pr_body`'s footer still reads "Opened by the VulnAdvisor GitHub App" even on the OAuth path —
left unparameterized to avoid snapshot churn; worth a small `opened_by` tweak later. (4) The **live
e2e** (Parts 1–2) + the **v2.1.0 tag** still hold for the next turn. **Next:** the deferred live
checks + v2.1.0 tag, or Task 17.5 (proposed fix in the dashboard finding card).

---

## Task 17.4 — Zero-setup PR suggestions (a GitHub login is enough; no App)  (2026-06-14)

**Status:** **Parts 1 + 2 complete**, full automated gate passing (CLI + platform). **No new
dependency** — the CI poster is a second stdlib (`urllib`) client beside `output/upload.py`, so the
published wheel still has 3 runtime deps. Part 3 (hosted OAuth setup-PR) deferred to the next turn,
and the live scratch-repo e2e stays credential-gated (prior-task precedent). The pivot's payoff now
reaches a user **without any GitHub App**: a workflow running `vulnadvisor suggest` posts one-click
in-line `suggestion` comments straight from Actions with the built-in `GITHUB_TOKEN`.

**Scope decisions (maintainer, at task start):** (1) **new `vulnadvisor suggest` command** (not
`fix --post-pr`) — a self-contained scan → validate → post; keeps `fix` local-first. (2) **Parts
1+2 now** (renderer move + CI-native posting + workflow), **part 3 next** (OAuth-token setup-PR).
(3) Live e2e deferred.

**The soundness shape:** identical to 17.2 — the review event is **always `COMMENT`** (never
`REQUEST_CHANGES`, never auto-commit), only **completely-expressible** fixes are posted in-line, and
every run **prunes our own prior `<!-- vulnadvisor:fix -->` comments before reposting** so a fixed or
moved line never strands a stale suggestion. The only network calls are the user's own model key and
GitHub; source code stays in CI.

**Part 1 — one renderer, two callers.** Moved the pure diff→suggestion renderer to
**`src/vulnadvisor/output/pr_suggestion.py`** (so the CLI can post without the platform);
`platform/vulnadvisor_platform/pr_suggestion.py` is now a **thin re-export** of it (every existing
`from vulnadvisor_platform.pr_suggestion import …` keeps working, behaviour byte-identical). A new
platform test asserts **object identity** between the two modules (no copy drift); the 17.2 snapshot
tests stayed green untouched.

**Part 2 — CI-native posting (`output/github_pr.py`, stdlib).**
- **Event parsing** — pure `parse_pr_event(payload, github_sha=?, repository=?)` reads
  `pull_request.number`/`head.sha`/`repository.full_name` with top-level `number` + `GITHUB_SHA` +
  `GITHUB_REPOSITORY` fallbacks; `read_pr_context(env)` reads the `GITHUB_EVENT_PATH` file. Both are
  fully defensive — a push event / missing file / bad JSON → `None` (a clean no-op, never a crash).
- **HTTP** — `GitHubHttp` Protocol + `UrllibGitHubHttp` (urllib): an HTTP error **status is returned
  as a `GitHubResponse`** (so a 404 on delete is tolerable), a network error raises
  `GitHubPostError`. `post_review_suggestions(http, token, ctx, comments)` paginates + prunes our
  marker'd comments (tolerating 404), then posts one `event:"COMMENT"` review on the head sha;
  returns the count (pruning still runs with zero comments, so a now-fixed PR clears old ones).
- **CLI `vulnadvisor suggest`** — `--path/--max-attempts/--provider/--model/--dry-run`. Resolves the
  PR from the Actions env (no PR → no-op exit 0), requires a model key (exit 2, provider-agnostic
  17.3 message), SAST-scans, runs the shared validated-fix loop (refactored `_validate_fixes`, now
  used by both `fix --suggest-json` and `suggest`), builds the in-line comments, then needs
  `GITHUB_TOKEN`/`GH_TOKEN` (exit 2 with a "permissions: pull-requests: write" hint) and posts.
  `--dry-run` prints the comments without a token. `build_github_http` is module-level for test
  substitution.
- **Generated workflow (14.2, `setup_pr.py`)** — added `permissions: pull-requests: write` and a
  `vulnadvisor suggest` step gated on `github.event_name == 'pull_request'`, carrying `GITHUB_TOKEN`
  + all three provider key env vars (`OPENROUTER_/OPENAI_/ANTHROPIC_API_KEY`) so **any** BYOM secret
  works via 17.3 prefix detection; an unset key → no suggestions, never a failed build. PR body +
  README document the zero-setup path (no App; add one model-key secret).

**Validation:** ruff + format clean (178 files) · `mypy --strict src` clean (85) / `platform` clean
(29) / `tests/test_github_pr.py` clean · **src pytest 814 passed, 1 skipped** (+30) · **platform
pytest 149 passed** (+1). New `tests/test_github_pr.py` (23): event parsing (number/sha/repo +
fallbacks + 8-case malformed→None + event-file read/missing/bad-JSON); poster against a fake GitHub
— **COMMENT review on the head sha**, Bearer token + API-version headers, **prunes only our marker'd
comments** (human comment untouched), zero-comments still prunes + posts nothing, **404-tolerant
delete** vs **raises on a real delete/post failure**, **pagination**; urllib transport maps an HTTP
status to a response and raises on a network error. `tests/test_cli.py` (+6): `suggest` end-to-end
posts one anchored COMMENT review (tree untouched), idempotent prune, `--dry-run` prints + posts
nothing, missing-token → 2, missing-key → 2, no-PR-context → 0 no-op. `platform`: workflow snapshot
+ structure + `test_github` setup-PR updated for the new suggest step; **re-export identity** test.
**CLI smoke:** `suggest --help` shows the flags; push build (no PR) → "nothing to suggest" exit 0;
PR context with no model key → provider-agnostic message exit 2.

**Deferred (this task, by scope):** (1) **Part 3** — hosted onboarding via the logged-in user's
GitHub **OAuth token** opening the setup-PR (no App install), the optional upgrade path; next turn.
(2) **Live scratch-repo e2e** — PR with a seeded vuln → Actions `GITHUB_TOKEN` posts the in-line
suggestion → "Commit suggestion" → next run shows it fixed — GitHub-credential + funded-model-key
gated; the posting choreography, anchoring, idempotency, and event parsing are all proven
hermetically. (3) **`v2.1.0` tag** holds until Part 3 + the live e2e land (mirrors the v2.0 tag
deferral). **Next:** Task 17.4 Part 3 (OAuth setup-PR), then the deferred live e2e + the v2.1.0 tag.

**Part 3 recon (done 2026-06-14, so next session executes fast):** the GitHub **OAuth token is NOT
persisted today** — `auth.py` exchanges the code, calls `fetch_user`, and discards the token; the
`User` model has no token column, and `authorize_url` only requests `read:user user:email` (no
write scope). So Part 3 is the **migration-heavy path**: (1) request `repo`/`workflow` scope —
decide **incremental authorization** at the "set up repo" click vs. at login (UX call, ask first);
(2) **persist the token encrypted at rest** (reuse the 15.1 BYO-key encryption) → **new `User`
column + Alembic migration, applied to live Postgres, `alembic check` no drift**; (3) add an
OAuth-token branch to `github_app.open_setup_pr` (today installation-token only) + router wiring to
choose OAuth-vs-App; (4) faked-client tests for the OAuth path + the scope-upgrade/re-auth flow.

---

## Task 17.3 — Provider-flexible `fix` (BYOM on the CLI: OpenRouter / OpenAI / Anthropic)  (2026-06-14)

**Status:** complete, full automated gate passing. **No new dependency** — a second stdlib client
over the existing `Transport` (published wheel still 3 runtime deps). Closes the gap where the
dashboard copilot already did BYOM (15.1b) but the CLI fix loop was Anthropic-only: a **free
OpenRouter key is now enough** to run `vulnadvisor fix` and `fix --suggest-json`.

**The shape (mirrors 15.1b server-side):** provider is **detected from the key prefix** — `sk-or-`
→ **OpenRouter**, `sk-ant-` → Anthropic, `sk-`/`sk-proj-` → OpenAI — with `--provider` /
`--model` flags and a `VULNADVISOR_MODEL` env override. Keys are read from `OPENROUTER_API_KEY` →
`OPENAI_API_KEY` → `ANTHROPIC_API_KEY` (first present wins, documented). The 17.1 validation loop
(propose → apply → syntax → ruff → mypy → tests → rescan → retry) is **reused verbatim** — only the
client behind the `LLMClient` Protocol changed, so soundness is inherited and the "code never leaves
the machine except to your own model endpoint" audit holds for every provider.

**Pieces:**
- **`llm/client.py`** — generalized into a two-client module. New `Provider` enum
  (anthropic/openai/openrouter), `provider_for_key` (prefix detection, specific prefixes first),
  `DEFAULT_FIX_MODEL` per provider (Anthropic keeps the historical haiku default → existing path
  byte-for-byte unchanged; OpenRouter `openrouter/auto`; OpenAI `gpt-5.2`). New
  **`OpenAICompatibleClient`** — the OpenAI `/chat/completions` shape over the existing `Transport`
  with `Authorization: Bearer`, `base_url` selecting OpenAI vs OpenRouter; **one** client serves
  both. Defensive `_extract_openai_text` parses `choices[0].message.content` (string *or* a
  list-of-parts), every malformed shape → `LLMError` (same fallback contract as the Anthropic
  extractor, refactored onto a shared `_load_object`). Pure `resolve_fix_client_config(env, ...)`
  (key precedence → provider → model resolution, fully unit-testable on a dict) + thin
  `build_fix_client_from_env(transport=?, provider_override=?, model_override=?, env=?)`.
  `build_anthropic_client` (the explainer's builder) is untouched.
- **CLI (`cli/main.py`)** — `build_fix_client(provider, model)` now calls
  `build_fix_client_from_env`; `fix` gains `--provider {openrouter,openai,anthropic}` and `--model`
  (threaded into both the interactive path and `_fix_suggest_json`). The missing-key message is now
  the shared, provider-agnostic `_MISSING_FIX_KEY_MESSAGE` (lists all three keys; still mentions
  `ANTHROPIC_API_KEY`, so the existing assertions hold).
- **Docs** — README gains a "Validated fixes (`vulnadvisor fix`)" section (provider-flexible,
  free-OpenRouter-key-is-enough, prefix detection + precedence + override flags) and the Privacy
  note now covers `fix` across all three providers.

**Validation:** ruff + format clean (121 files) · `mypy --strict src` clean (83) · **pytest 784
passed, 1 skipped** (+31). New in `test_llm.py` (+24): `provider_for_key` prefix table incl.
unrecognized→default; `resolve_fix_client_config` key-precedence (OpenRouter first), fall-through to
Anthropic, OpenAI default model, no-key→None, `--provider` override beats prefix, `--model` beats
`VULNADVISOR_MODEL` beats Anthropic-legacy `ANTHROPIC_MODEL` beats default; `build_fix_client_from_env`
returns `OpenAICompatibleClient` w/ correct base_url+model for OpenRouter/OpenAI and `AnthropicClient`
for sk-ant; `OpenAICompatibleClient` parses a choice + sends Bearer + hits the right URL, accepts
list content-parts, **7-case malformed→`LLMError`** table; **network audit** — a built OpenRouter
client's only outbound host is `openrouter.ai`, never `api.anthropic.com`. `test_fix.py` (+1):
**full 17.1 loop end-to-end through a scripted OpenAI-compatible (OpenRouter) client** — chat-
completions response shape, real apply→syntax→ruff→rescan validation → `VALIDATED`, host audit
(only `openrouter.ai`). `test_cli.py` (+1): `--provider`/`--model` flags reach the builder; the 7
existing fix monkeypatches updated to `lambda *a, **k:` for the new builder signature. **CLI smoke:**
`fix --help` shows the flags; with no key set, a real finding yields the provider-agnostic message +
exit 2.

**Deferred (prior-task precedent, tool/credential-gated):** (1) the **live** OpenRouter run (a real
free key authoring a real diff end-to-end) — the loop, parsing, routing, and host audit are proven
hermetically with a scripted OpenAI-compatible client; only the model's own patch authorship needs a
funded/free key. (2) The **generated workflow's** model-key step belongs to **17.4** (which
explicitly updates the 14.2 workflow to run `fix`/`suggest` with a provider key + `GITHUB_TOKEN`);
17.3 leaves the upload-only workflow as-is. **Next:** Task 17.4 (zero-setup PR suggestions — a
GitHub login / Actions `GITHUB_TOKEN` is enough, no App; tags **v2.1.0**).

---

## Task 17.2 — PR review agent (CodeRabbit-grade, engine-grounded)  (2026-06-14)

**Status:** complete, full automated gate passing (CLI + platform), migration applied to **live
Postgres** with `alembic check` = no drift. **No new dependency.** The pivot's payoff lands in the
PR: the validated patches from 17.1 become **one-click in-line GitHub `suggestion` comments** on the
exact vulnerable lines — code never leaves CI.

**Scope decisions (maintainer, at task start):** (1) **CI produces, platform posts.** CI runs
`vulnadvisor fix --suggest-json <file>` (the non-interactive sibling of 17.1) and uploads the
validated-fix document **alongside** the report via `scan --upload --suggestions <file>`; the diffs
travel as data, the source stays in CI. (2) **Soundness over coverage for one-click commits:** a
fix is offered in-line **only when its *entire* patch is expressible as anchored suggestions** —
because a GitHub `suggestion` replaces exactly the lines it's attached to, committing one hunk of a
multi-hunk fix would leave the code half-patched. A fix whose patch can't be cleanly suggested is
skipped in-line (still counted in the summary), never posted as a partial click. (3) **Never
requests changes, never auto-commits:** the review event is always `COMMENT`; the human clicks
*Commit suggestion*. (4) **Live e2e deferred** (scratch-repo PR → suggestion → commit → rescan):
GitHub-credential-gated, same precedent as 14.x/16.4.

**The soundness shape:** every suggestion's block content **is** the validated diff hunk's new-side
text, anchored to the **head (old) side** line numbers (the fix diff is `head -> fixed`, so `a/` is
exactly the file GitHub sees). Idempotent on `synchronize`: the App deletes its own prior fix
comments (by a hidden `<!-- vulnadvisor:fix -->` marker) before reposting, so moved lines never
strand a stale suggestion.

**CLI half (`src/vulnadvisor`):**
- **`model/suggestion.py`** — frozen `ValidatedFix` (finding identity + engine facts: cwe/kind/
  title/tier/**rendered flow** + the model's rationale/confidence + the unified `diff`) and
  `SuggestionReport` (`schema_version 1.0` + tool_version + `fixes`). Self-contained so the platform
  renders the 3-card story without re-running the engine.
- **`llm/suggest.py`** — pure `generate_suggestions`: sweeps every **alarming** finding (SANITIZED
  skipped — nothing to fix), runs the 17.1 propose->validate->retry loop with the **validator and
  client injected** (so the whole sweep is unit-testable with no subprocess/network), and keeps only
  `VALIDATED` patches. Soundness inherited verbatim from 17.1.
- **CLI** — `fix` gains `--suggest-json <file>` (finding id now optional; with the flag it fixes
  *every* finding, writes the document, exits 0 even on zero safe fixes — an empty doc is valid;
  exit 2 only on missing key / unwritable file; the working tree is never touched). `scan` gains
  `--suggestions <file>`, defensively parsed (`SuggestionReport.model_validate_json` → clean
  `BadParameter` on garbage) and attached to the upload (`output/upload.py` adds an optional
  `suggestions` body field, omitted entirely when absent — published wheel still stdlib-only).

**Platform half (`platform/`):**
- **Storage** — additive `Scan.suggestions` JSON column (Alembic `c3b9e7d1f4a8`, `server_default
  "[]"`; applied live, `alembic check` no drift). `reports.parse_suggestions` is defensive: None →
  `[]`; bad doc/`schema_version`/non-list `fixes` → `ReportValidationError` (422 like the report);
  individual malformed fix entries dropped (must carry a non-empty diff, a positive line, a
  finding_id and file); diff capped, confidence coerced, ≤200 fixes. Both ingest endpoints accept +
  store it.
- **`pr_suggestion.py`** (pure) — `diff_to_suggestions` parses a unified diff into per-hunk
  `ReviewSuggestion`s: narrows to the minimal changed window, anchors to the head-side line(s)
  (`start_line`/`line`, `side=RIGHT`), and a **pure insertion borrows one neighbour context line**
  so it still has an anchor. `complete` is True only if the diff parsed and *every* hunk anchored.
  `render_suggestion_body` = the marker + a ` ```suggestion ` block (== the hunk's new side) + the
  3-card attack story (title, tier, flow, rationale) in a `<details>`; multi-hunk fixes are labelled
  "part N of M - commit all together" with the story shown once. `build_review_comments` emits API-
  ready comments only for complete fixes; `count_suggestable_fixes` feeds the summary line.
- **`github_app.post_or_update_suggestions`** — mints the installation token, **prunes** its own
  marked review comments (tolerating 404), then posts one `event:"COMMENT"` review carrying the
  anchored comments on the head sha (multi-line keys only when needed). Never `REQUEST_CHANGES`.
- **Webhook wiring** — `_handle_pull_request` reads `head_scan.suggestions`, builds the review
  comments, posts the summary (now `render_pr_comment(..., validated_fixes=N)` adds a ":wrench: N
  validated fixes ... click Commit suggestion" line), then posts the in-line suggestions when a head
  sha is present. Existing summary/diff behaviour unchanged when there are no suggestions.

**Validation:** ruff + format clean (src 121 files; platform 54) · `mypy --strict src` clean (83) /
`mypy --strict vulnadvisor_platform` clean (37) · **src pytest 753 passed, 1 skipped** (+27:
`tests/test_suggest.py` — validated-only sweep / SANITIZED-skipped / no-safe-fix → empty / engine-
facts carried / JSON round-trip; `tests/test_cli.py` +6 — `fix --suggest-json` writes 1 validated
fix without touching the tree, missing-key → 2, no-id-no-flag → 2, `scan --suggestions` forwards the
doc, malformed suggestions → 2). **platform pytest 148 passed** (+17: `test_pr_suggestion.py` 9 —
single-hunk anchors to the sink line + **suggestion block == diff hunk snapshot**, pure-insertion
context anchor, multi-line start/end, file-add not-suggestable, garbage not-suggestable, body has
marker/fence/story, multi-hunk part-labels + story-once, **mixed fixable/unfixable** skips cleanly,
`to_api` multiline-keys-only-when-needed; `test_github.py` +4 — webhook posts an anchored in-line
suggestion + summary "1 validated fix", unsuggestable fix posts none, **synchronize reposts**,
**transport-level prune-then-repost** (deletes only our marker'd comment, event COMMENT, head sha);
`test_ingest.py` +4 — stores suggestions, rejects bad schema (422), empty when absent, defensive
`parse_suggestions` unit). **Live Postgres:** `alembic upgrade head` + `alembic check` → no drift.

**Open questions / deferred (tool/credential-gated, prior-task precedent):** the **live scratch-repo
e2e** — PR with a seeded vuln → CI uploads report+suggestions → App posts the in-line suggestion →
"Commit suggestion" → next scan shows it fixed — needs a real GitHub App install + a funded model
key in CI (the loop, parsing, anchoring, idempotency and review payload are all proven hermetically).
**Known limitation (documented):** each validated fix is proven independently against the original
head, so two fixes whose diffs touch overlapping lines may not compose in a single batch-commit
(non-overlapping fixes compose fine); refine to a sequential re-validate if it bites. **CLI v2.1 tag
(v2.1.0) deferred** until that live e2e lands (mirrors the v2.0 tag deferral). **Next:** the deferred
CLI v2.0/v2.1 live checks + tags, or M18 (launch + fundraising assets).

---

## Task 17.1 — `vulnadvisor fix` (local, validated)  (2026-06-14)

**Status:** complete, full automated gate passing. **No new dependency** (stdlib `ast`/`shutil`/
`subprocess`/`tempfile` + the existing SAST engine + the existing dependency-free Anthropic client).
First M17 task — the pivot from "here's the direction" (16.4 Card C) to a **machine-proven patch**.

**Scope decisions (maintainer, at task start):** (1) **SAST findings only** — SCA findings already
carry a deterministic, by-construction-valid safe-fix (version bump from `engine/safe_fix.py`); the
LLM-validated loop is built around first-party code, exactly what the "re-scan proves the finding is
gone" gate and the >=8-fixture harness test. (2) **Temp-copy + `git apply`** — the patch is proven
on a throwaway copy of the project; the user's working tree is never touched until `--apply`.

**The soundness shape:** the model only *proposes*; a deterministic loop *proves*. A patch is
surfaced **only** when it passed every check — an unvalidated patch is never emitted (the release
rule). The single network call is the model request through the user's own key; **every** validation
step is local (subprocess + filesystem only), so code never leaves the machine otherwise.

**Pieces:**
- **`model/fix.py`** — pure, frozen pydantic: `FixSuggestion` (unified diff + rationale +
  self-reported `FixConfidence` — advisory only, never gates), `ValidationStep`/`StepStatus`/
  `ValidationReport` (with `first_failure()` + `failure_feedback()`), `FixAttempt`, `FixOutcome`,
  `FixResult`.
- **`llm/fix.py`** (pure half) — finding identity (`sast_finding_id` = `<file>:<line>:<kind>`,
  matches scan output; `sast_signature` = `(file, cwe, kind)`, **line-independent** since a patch
  shifts lines; `is_alarming` = tier != SANITIZED), `resolve_sast_finding` (full id / `file:line` /
  bare `file`/`kind`/`cwe`, ambiguous → error listing exact ids), `extract_code_context` (only the
  **flow's functions** — the enclosing `def` of the sink and every flow step, decorators included so
  framework routes/sources are visible; module-scope sinks get a small window; injectable
  `source_for` keeps it pure), the prompt (`FIX_SYSTEM_PROMPT` + `build_fix_messages` with retry
  feedback), defensive `parse_fix_suggestion` (fence/prose-tolerant, requires non-empty diff +
  rationale, coerces unknown confidence → MEDIUM, adds the trailing newline `git apply` needs), and
  the **`generate_fix` loop** (validator *injected* → unit-testable with no subprocess).
- **`llm/fix_validate.py`** (impure half) — `validate_fix`: copytree (ignoring vcs/venv/caches) →
  `git apply -p1 --recount` → **syntax** (`ast.parse` every changed `.py`, *always* run — closes the
  hole where a broken file would silently drop out of the re-scan) → **ruff** (skipped if absent) →
  **mypy** (only if the project configures it) → **tests** (only if a suite is present; pytest exit
  5 "no tests" treated as pass) → **rescan** (re-run `analyze_taint`+`score_sast_findings` on the
  copy; **the target signature must no longer be alarming AND no new alarming signature may appear**
  — the regression guard). Stops at the first failed step and feeds its diagnostic back. Plus
  `build_validator` (binds it to a project/target) and `apply_patch_to_tree` (`--apply`, `git apply
  --check` first so a bad patch leaves the tree untouched).
- **CLI `vulnadvisor fix <finding-id> [--apply] [--path .] [--max-attempts 3]`** — SAST-only scan
  (offline, `run_sca=False`) → resolve → require own model key (clean exit 2 + message if absent;
  named as the only network call) → `generate_fix` → print the validated diff + rationale (or an
  honest "No safe fix found after N attempt(s)" with per-attempt reasons, exit 1) → `--apply`
  writes it. `build_fix_client` is module-level for test substitution.

**Validation:** ruff + format clean (180 files) · `mypy --strict src` clean (81) /
`src platform` clean (109) · **pytest 726 passed, 1 skipped** (+37). New `tests/test_fix.py` (33):
**harness over 8 fixture vulns across all 7 CWE classes** (CWE-78 sanitize *and* argv-list, CWE-89
parameterize, CWE-94 literal_eval, CWE-502 yaml-safe *and* pickle→json, CWE-22 secure_filename,
CWE-798 secret→env) — each canonical (git-authored) fix passes the **full** apply→syntax→ruff→rescan
loop; **deliberately-ineffective patch → NO_SAFE_FIX** (rescan "still present", 3 attempts, no patch
returned); **`--apply` round-trip** (git repo: apply → file == intended fix → clean re-scan);
**network audit** (recording transport proves the only outbound URL is `api.anthropic.com`);
parse matrix (valid/fenced/missing-diff/non-json/bad-confidence); resolution (id/file:line/bare/
not-found/ambiguous); context (enclosing fn + cross-function step / unreadable file / module-scope
secret window); loop (first-try / retry-with-feedback / all-fail / parse-failure / model-error
attempts recorded) with a fake validator; validator integration (non-applying / syntax-breaking /
**regression-introducing → rescan "introduced new finding"** / sanitizing-accepted / bad-patch
raises). `tests/test_cli.py` (+4): no-key → exit 2, unknown id → exit 2, validated diff printed
without touching the tree, `--apply` writes the patch.

**Open questions / deferred (prior-task precedent, tool/credential-gated):** the **live LLM run**
(`vulnadvisor fix` against a real Anthropic key generating a real diff end-to-end) — the loop,
prompt, parsing, and every validation step are proven hermetically with a scripted client and real
subprocess/rescan; only the model's own patch authorship needs a funded key (same blocker as the
15.x red-team). **Known limitation (documented):** the rescan signature is `(file, cwe, kind)`, so a
file with two same-class sinks where only one is fixed reports "still present" — conservative
(soundness-safe), refine later if needed. **Next:** Task 17.2 (PR review agent — in-line
`suggestion` comments from CI-validated fixes) or the deferred CLI v2.0/v2.1 live checks + tags.

---

## Task 16.6 — Dynamic coverage overlay (resolve DYNAMIC-UNKNOWN with runtime truth)  (2026-06-14)

**Status:** complete, full automated gate passing. **No new runtime/dev dependency** — the parser
reads coverage.py's JSON (stdlib `json`); the live e2e produced the report with an *ephemeral*
`uv run --with coverage --with pytest` (never added to the lockfile, published wheel still 3 runtime
deps). Marries the static structure (reachability tiers, taint flows) with runtime evidence from a
real test run, shrinking the ambiguous tiers **with proof, never with optimism**.

**The soundness shape (decided up front):** the overlay is a **pure annotation** — it only ever
*sets* a finding's new `runtime` field; it **never touches the tier, the score, or the ranking**.
So no coverage input can downgrade a finding (the release-blocking rule), and ranking stays
deterministic. `RUNTIME-CONFIRMED` is escalation-only (KEV-style); `not-observed` is advisory only
(a test suite is not production). I kept JSON at `schema_version` **1.2** with an **additive
`runtime` key present only when `--coverage` annotated the finding** — reports without coverage are
byte-for-byte unchanged (no platform/migration churn; the existing `report.json`/`mixed_ranking`
snapshots stayed green untouched).

**Pieces:**
- **`model/runtime.py`** — `RuntimeStatus` (`RUNTIME_CONFIRMED` / `NOT_OBSERVED`), `ObservedLine`,
  `RuntimeEvidence` (status + reason + observed `file:line`s). Optional `runtime` field added to
  **`ScoredFinding`** and **`ScoredSastFinding`** (frozen, additive, default `None`).
- **`coverage/parse.py`** — defensive coverage.py-JSON → `CoverageData` (project-relative POSIX →
  executed-line set). Reads **only `executed_lines`**, which is present in *both* line and branch
  mode, so one code path handles both. Malformed input (not JSON / wrong top-level / missing
  `files`) → `CoverageParseError`; individual bad file entries skipped; non-int/bool/non-positive
  line values coerced out; **paths resolved against the project root and dropped if outside it**
  (Windows backslash keys normalize to the same posix paths findings use).
- **`coverage/overlay.py`** — pure `apply_coverage_overlay` + per-finding annotators. A finding's
  *evidence lines* = the first-party `file:line`s that prove its usage (SCA: import sites, dynamic
  sites, call-path steps; SAST: the sink + every flow step). If coverage includes those files and
  >=1 executed → `RUNTIME_CONFIRMED`; if it includes them but none executed → `NOT_OBSERVED`; if it
  doesn't include them → no annotation (we say nothing rather than guess). Confidently-safe tiers
  (`NOT_IMPORTED` / SAST `SANITIZED`) are never annotated.
- **CLI** — `vulnadvisor scan --coverage <coverage.json>` (Typer `exists=True` validation;
  malformed content → clean `BadParameter`/exit 2, never a traceback). Coverage paths normalized
  against the scan root (dir, or the file's parent). Overlay runs before ranking, so terminal /
  JSON / SARIF / `--upload` all carry it.
- **Output** — terminal Card C gains a `Runtime: RUNTIME-CONFIRMED - ...` line *alongside* the tier;
  JSON gains the additive `runtime` object; SARIF result `properties.runtime` (status + observed).
  All three additive-only-when-present.

**Live e2e (real pytest + branch coverage, documented):** fixture `c:\tmp\va166` — `myapp/runner.py`
with two CWE-78 sinks, a test that calls only `run_command`. `coverage run --branch -m pytest` +
`coverage json` → `executed_lines` for `runner.py` = `[1,4,6,9]` (the exercised `os.system` is
line 6; the orphan sink line 11 never runs). `vulnadvisor scan . --sast-only --coverage coverage.json`
→ the **executed sink (runner.py:6) is `RUNTIME-CONFIRMED`** with `observed=[runner.py:6]`, the
**unexercised sibling (runner.py:11) is `not-observed`** — and both stay `POSSIBLE-FLOW` (the param
isn't a modeled entry-point source, so the tier is unchanged: exactly the soundness contract). This
also proves cross-platform path handling (Windows `myapp\runner.py` coverage keys vs posix finding
paths) and branch-mode parsing.

**Validation:** ruff + format clean (114 files) · `mypy --strict src` clean (78) · **pytest 689
passed, 1 skipped** (+28: `tests/test_coverage_overlay.py` 23 — parse line/branch/absolute-path/
outside-project-ignored/garbage-coerced/4x malformed-rejected/skip-bad-entry/dup-path-union; SCA
import-site + call-path-step + dynamic-evidence confirmation, covered-but-unexecuted not-observed,
uncovered→no-annotation, NOT_IMPORTED never annotated; SAST sink + flow-step confirmation,
not-observed, SANITIZED never annotated; order-preserving + inputs-not-mutated; **exhaustive
soundness sweep** — every tier x 5 coverage inputs, tier+score unchanged; `tests/test_cli.py` +5:
`--coverage` confirmed/not-observed/terminal-RUNTIME-CONFIRMED/malformed→exit 2/missing-file→exit 2).
Existing JSON/SARIF snapshots untouched (additive-only-when-present verified).

**Open questions:** none blocking. M16 SAST v1 complete (16.1–16.6). **Next:** the deferred CLI v2.0
tag (v2.0.0) + 16.4/16.5 live checks (GitHub code-scanning SARIF upload; seeded-platform SAST card
e2e; full SCA+SAST warm/cold + pyscan perf), or M17 (Task 17.1 `vulnadvisor fix`).

---

## Task 16.5 — SAST benchmark vs Bandit  (2026-06-14)

**Status:** complete, full automated gate passing. **New dev/benchmark dependency (approved at task
start): `bandit==1.8.6`** — added to the `dev` group only (published core wheel still 3 runtime
deps); the harness invokes it via subprocess and is **defensive** (skips gracefully if absent, so CI
without bandit still runs the VulnAdvisor side and the zero-missed gate). pyscan handling: **best-
effort optional** (run if on PATH, else "n/a"). Scope: **harness + hermetic now, live deferred**
(the precedent set by 14.x/16.4 live checks).

The SCA benchmark measures *noise reduction*; this SAST benchmark measures the two numbers that
decide first-party security on a **ground-truth-labeled corpus** — recall (a missed real vuln is
release-blocking) and **top-tier precision** (of the findings a tool calls most-serious, how many
are real). That second number is the pitch: Bandit has no taint/reachability model, so it raises
`HIGH` on sanitized and entry-point-unreachable sinks; VulnAdvisor reserves `CONFIRMED-FLOW` for
proven flows.

**Pieces (all under `benchmarks/`, mirroring the hermetic/live SCA split):**
- **`sast_metrics.py`** — pure, fully-unit-tested metric models. Ground truth lives in the corpus
  source as `# seed: CWE-NN vuln|safe|possible` marker comments (parsed here, so labels sit next to
  the code and survive edits — no hand-maintained line numbers). `Detection` carries a per-tool
  `is_alarm`/`is_top` predicate (VulnAdvisor `SANITIZED` is *not* an alarm; `CONFIRMED-FLOW` is top /
  Bandit `HIGH` is top). `compute_tool_metrics` / `compute_cwe_recall` are total folds → deterministic.
- **`sast_corpus.py`** — 10 labeled apps across **all 7 CWE classes** (20 sink sites: 13 real, 7
  safe), shaped to exercise the differentiator: reachable flows (`vuln`), sanitized/literal sinks
  (`safe`), and a real-but-unreachable orphan (`possible`). Each case runs in its **own** temp dir
  (isolation preserves ground truth — an entry point in one case can't root an orphan in another).
  VulnAdvisor via the real `analyze_taint` + `score_sast_findings`; Bandit via `-f json` subprocess,
  CWE+line normalized to detections.
- **`sast_report.py`** — renders `SAST-REPORT.md`: headline, head-to-head table, per-CWE recall,
  an honest **"Where Bandit wins or ties"** section, a **"Known limitations"** section, and a
  Performance section (deterministic budget statement always; the non-deterministic wall-time table
  only with `--perf`, so the committed artifact stays reproducible). ASCII-only (matches the SCA
  report convention + Windows consoles).
- **`sast_perf.py`** — offline, runnable: times `analyze_taint` over the corpus and over our own
  `src/`. `pyscan_wall_time` runs pyscan if on PATH else returns `None`. Full SCA+SAST warm/cold +
  pyscan over real OSS apps = the live perf run (deferred).
- **`__main__.py`** — `python -m benchmarks --sast [--perf]` → `SAST-REPORT.md`; exit non-zero iff
  VulnAdvisor missed a seeded vuln. `_print_safe` guards the console echo against cp1252 (the Task
  14.1 lesson — a successful run never exits 1 while printing itself).

**Results (reproducible, regenerate identically):** VulnAdvisor **100% recall (12/12), 100% top-tier
precision, 0 alarms on safe code**; Bandit **92% recall (misses path traversal entirely — no
taint-based check), 71% top-tier precision** (2 `HIGH` alarms on `shlex.quote`'d shell calls) plus 2
off-target import-lint findings. Honest ties recorded: both catch SQLi/eval/exec/yaml/pickle (Bandit
at `MEDIUM`, us at `CONFIRMED-FLOW` with the path); Bandit "catches" the SSRF line only incidentally
via a missing-timeout lint. **Known-limitation documented, not hidden:** `secure_filename(...)`
through `os.path.join(...)` is conservatively re-tainted (16.3 drops the cleared set on an opaque
transform) → a false `CONFIRMED-FLOW`; excluded from the scored corpus and called out in the report
so the precision number isn't flattered. **Perf:** SAST over the 10-case corpus 0.02 s, over our own
`src/` ~0.55 s (74 files) — well under the documented ≤30 s warm budget.

**Validation:** ruff + format clean (11 files) · `mypy --strict src platform` clean (102) + `mypy
--strict benchmarks tests` clean (11) · **pytest 661 passed, 1 skipped** (+18 `tests/
test_sast_benchmark.py`: seed-marker parsing incl. malformed-ignored; per-tool `is_alarm`/`is_top`;
table-driven recall/precision math incl. a noisy-tool false-top-alarm+miss case, dedup, empty-top=
100%; per-CWE grouping; corpus integrity — unique case names, **all 7 CWE classes covered**, safe+
possible decoys present; **end-to-end zero-missed gate** (recall 100%, top_on_safe 0); **determinism**
(two runs → identical metrics + identical rendered markdown); bandit-gated assertion that Bandit is
noisier at the top tier; render contains headline/tables/gate + `isascii`; no-bandit render omits the
comparison). One command regenerates `SAST-REPORT.md` byte-identically (verified by diffing two runs).

**Remaining live checks (maintainer, tool/network-gated, deferred per task scope):** the full
SCA+SAST warm/cold split + pyscan side-by-side over 2–3 real OSS apps (`--sast --perf` provides the
SAST half offline today; pyscan needs the Rust binary on PATH).

**Open questions:** none blocking. **Next:** Task 16.6 (dynamic coverage overlay — resolve
DYNAMIC-UNKNOWN with runtime truth) — or the deferred 16.4/16.5 live checks + the CLI v2.0 tag.

---

## Task 16.4 — Engine + output integration  (2026-06-13)

**Status:** complete, full automated gate passing. No new dependencies. The pivot lands in the
output: `vulnadvisor scan` now triages **your code and your deps in one ranked list**, scored by the
same deterministic engine, reported with the same tiers-and-evidence, across terminal / JSON 1.2 /
SARIF, gated by one `--fail-on`, ingested by the platform, and rendered on the dashboard.

**Scoring (`engine/sast_scoring.py`) — CWE→severity through the existing scorer.** First-party code
has no CVSS/EPSS/KEV, so severity comes from the published **CWE base-severity table** (§5: CWE-78/94/95
9.5 · CWE-89/502 9.0 · CWE-22/918 7.5 · CWE-798 7.0; unknown CWE → 5.0, never zeroed) fed into the
*same* `compute_score` (EPSS/KEV absent). The confidence tier then discounts it the way reachability
discounts SCA: **CONFIRMED-FLOW** full · **DYNAMIC-UNKNOWN** full (uncertainty is *not* a discount —
soundness; rationale records the block) · **POSSIBLE-FLOW** ×**0.6** (the reviewer-deferred constant,
pinned here with a table-driven cross-type test) · **SANITIZED** ×0.05 capped to 5.0 (INFO), relabeled
"Sanitized on every path" — mirrors `NOT_IMPORTED`. Reuses `compute_score` for the discounted value
too (feed it a scaled severity) so there is **one** band table, no drift. `ScoredSastFinding` (=
`SastFinding` + `Score`) and `order_unified` (the single ranked list; for SCA-only input it reproduces
`order_findings` exactly, so no snapshot drift) live here.

**One pipeline, two analyses (`cli/pipeline.py`, `cli/main.py`).** `scan_project(run_sca, run_sast)`
runs both by default; `ScanReport` gained `sast_findings`. New flags **`--sca-only`** / **`--sast-only`**
(mutually exclusive → exit 2; `--sast-only` skips all network, fully offline). `--top` slices the
*merged* ranking, then splits back so each renderer re-merges into the identical order. `--fail-on`
gates over **both** types (a CONFIRMED CWE-78 is critical → exit 1, verified).

**Output (all additive).** JSON **`schema_version` 1.2**: a `finding_type` discriminator on *every*
finding (`"dependency"` set on the existing shape too) + the `"code"` sub-shape (`rule`/`location`/
`flow{tier,source,sink,path,sanitizers}`/`score{cvss_known:false}`/`fix{direction,has_fix:false}` —
remediation *direction*, the validated fix is M17). SARIF 2.1.0: code rules get the namespaced
`ruleId` **`vulnadvisor/<kind>`**, a **CWE taxonomy** (`taxonomies` + rule `relationships`), the
sink's real `file:line`, and the source→sink path as a **`codeFlow`/`threadFlow`**; SCA `ruleId`
unchanged. The 3-card terminal renderer (`cli/render.py`) renders code findings (Card A story, Card B
risk, Card C remediation direction + the flow) interleaved by priority with SCA cards; explanations
are paired by object identity so interleaving never mismatches a story. `sast/remediation.py` =
CWE→one-sentence direction (pure data).

**Platform ingest (`reports.py`, +`finding_type` column, Alembic `a1f6c0d4e2b7`).** `parse_report`
accepts **1.0/1.1/1.2**; a code finding denormalizes to `package`=sink file, `advisory_id`=
`vulnadvisor/<kind>` (≤64), `tier`=SAST tier, `band`/`priority` from the score, `finding_type="code"`
(new column, `server_default "dependency"` so every existing row backfills). Migration applied to
**live Postgres** (docker compose): `alembic upgrade head` + **`alembic check` → no drift**.

**Dashboard.** `Finding` gained an optional `finding_type`; new `CodeFinding` + `AnyFinding` union;
`isCodeFinding`/`findingKey`/`sastTierClass`/`sastTierLabel` (Aegis semantics: confirmed=risk,
dynamic=dashed amber, sanitized=teal — uncertainty never styled safe). `FindingCard` dispatches to a
new **`CodeFindingCard`** (collapsed CWE·title·`file:line` + band/tier badges; expanded 3 cards;
**evidence drawer shows the source→sink taint path** via the existing `CallPathChain`). `matchesFocus`
made tolerant of code findings (CWE / kind / `file:line`); scan / demo-scan / diff pages key by
`findingKey` and the diff "fixed" list renders code findings.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (102 files) · **pytest 643
passed, 1 skipped** (+19 `tests/test_sast_scoring.py`: CWE table incl. unknown→5.0; the 4 tier
discounts incl. DYNAMIC-not-discounted + the pinned 0.6× POSSIBLE factor + SANITIZED→INFO; order_unified
== order_findings for SCA-only; **POSSIBLE code never outranks a proven KEV dep**; determinism; JSON 1.2
merge + code shape + empty-path-when-no-flow; **SARIF code finding validates against the 2.1.0 schema**
with CWE taxonomy + codeFlow; the **mixed-fixture one-ranked-list snapshot** `fixtures/snapshots/
mixed_ranking.json` — code-CONFIRMED 95 > dep-KEV 91.9 > code-POSSIBLE 57 > dep-flask 22.4 >
code-SANITIZED 4.8, priority monotonically non-increasing) · platform `+2` ingest tests (1.0/1.1/1.2
accepted; a 1.2 **code finding ingests**, introduced=1) · existing 1.1→1.2 / finding_type assertions
updated · `report.json` snapshot regenerated (additive `finding_type`). **Dashboard:** `npm run lint`
+ `next build` clean · **`npm test` 64/64** (+4 `lib/finding.test.ts`). **CLI smoke** (mixed fixture,
`--sast-only`): terminal renders the 3 ranked CWE-78 cards (CONFIRMED 95 / POSSIBLE 57 / SANITIZED 4.8
with the flow shown); JSON is `1.2` with 3 `"code"` findings; `--fail-on high/critical` → exit 1;
`--sca-only --sast-only` → exit 2.

**Remaining live checks (maintainer, credential/stack-gated, prior-task precedent):** (1) seeded
platform + browser **e2e rendering a SAST finding card** end-to-end (structural path proven by the
component build + unit tests + the ingest test; not yet driven through a live browser this task);
(2) **GitHub code-scanning** accepts the SARIF with code findings (it validates against the 2.1.0
schema locally). **CLI v2.0 tag (v2.0.0) deferred** until those two live checks + 16.5 benchmark land.

**Open questions:** none blocking. **Next:** Task 16.5 (SAST benchmark vs Bandit).

---

## Task 16.3 — Taint propagation on the existing call graph  (2026-06-13)

**Status:** complete, Validation Gate passing. No new dependencies (stdlib `ast` + the existing
call-graph infra). The differentiator: a first-party finding now proves a flow from a *real entry
point* to a sink, with the source→sink path shown.

Two pieces — entry-point **breadth** (sources) and the **taint engine** (the flow):

- **Entry-point breadth expansion** (`callgraph/frameworks/`, benefits SCA reachability too): two
  new plugins — **`FlaskPlugin`** (`@app.route` + the Flask-2 verb shortcuts `@app.get/post/...`,
  on `app` or a blueprint) and **`CeleryPlugin`** (`@app.task`/`@shared_task`/`@task(...)`) — added
  to `DEFAULT_PLUGINS` alongside the existing FastAPI + Django (URLconf views, CBVs, `@receiver`).
  A missed entry point is a catastrophic false negative, so over-rooting is the safe direction. The
  SCA pipeline picks these up for free (more BFS roots, never fewer).
- **`sast/taint.py`** — demand-driven taint over the **same per-file call graph the SCA engine
  uses**, escalating the 16.2 intra-procedural baseline (which stays the floor):
  - **Sources** seed taint: framework entry-point **parameters** (FastAPI/Flask/Django/Celery —
    every param of a routed handler, `self`/`cls` excluded), the Flask **`request`** global
    (`request.args.get(...)` etc.), and **`stdin`/`argv`/the environment** (`sys.argv`,
    `os.environ`/`os.getenv`/`environ.get`, `input()`) — untrusted by default per design §13.3.
  - **Propagation** (`_Taint = (source, cleared-CWEs, dynamic)`): assignments, aug/ann/walrus,
    `for`/`with` targets, f-strings/`%`/`+`, containers, ternaries, comprehensions, and
    **inter-procedural** flow — a tainted argument taints the callee parameter (riding the same
    bare-name→top-level-function edges the SCA call graph walks) and a tainted `return` taints the
    call site (memoized return summaries). Flow-insensitive with a monotone fixpoint; **sanitizer
    state merges by intersection**, so a *partially* sanitized value stays dangerous (release-
    blocking invariant §4.2). Conservatism is always *toward* taint (an unknown transform drops the
    cleared set; an unsure value stays tainted).
  - **Sinks** are the 16.2 rule pack (reused matcher: aliased imports, guards, `safe_args`). A
    tainted, unsanitized value at a dangerous arg → **`CONFIRMED_FLOW`** with the source→sink
    **`CallPath`** as evidence (`r -> sink -> os.system (m.py:5)`, byte-for-byte the SCA shape). A
    value whose provenance crossed a dynamic construct (`eval`/`exec`/`getattr` dispatch, a computed
    callee) → **`DYNAMIC_UNKNOWN`** — escalated above POSSIBLE, never dropped. Sanitizers are
    **CWE-scoped** (`shlex.quote` clears CWE-78, not CWE-89; `secure_filename` clears CWE-22).
  - **Cross-file rooting:** entry-point *names* are collected project-wide (exactly like the SCA
    search), so a Django view defined in `views.py` but routed in `urls.py` is still a source.
  - **Merge:** `analyze_taint` takes every `find_sinks` hit and raises only the tier the engine can
    *prove* (concern order `CONFIRMED > DYNAMIC > POSSIBLE > SANITIZED`); a sink it can't tie to a
    source keeps its intra-procedural tier (so a non-reachable helper stays `POSSIBLE_FLOW`, **never**
    `CONFIRMED`). New model `sast/model.SastFinding` carries `source_kind` + `flow`.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (100 files) · **pytest 623
passed, 1 skipped** (+35: `tests/test_sast_taint.py` — the full design §12 set: direct flow per
source kind, cross-function (helper-return + sink-in-callee, path asserted), sanitized (no
escalation) / **partial-sanitization → CONFIRMED** / CWE-scoped-sanitizer / dynamic-blocked
(`getattr` dispatch + `eval`-built arg) / FastAPI+Flask+Celery routing + Flask request global / SQLi
/ code-injection / deserialization / SSRF (`url=`) / path-traversal confirmed flows / not-reachable
+ local-non-source → no escalation; the `taint_mixed` + cross-file `taint_django` project fixtures;
whole-`src/` determinism + no-crash + malformed→`()`; **perf budget**; plus 5 in `test_frameworks.py`
for the Flask/Celery plugins + `DEFAULT_PLUGINS` coverage). **Perf:** `analyze_taint(src/)` =
**0.52 s over 72 files** (budget 10 s); `fixtures/` 0.02 s. **Real-code check:** the engine finds one
`CONFIRMED_FLOW` in our own `output/credentials.py` — `os.environ.get("XDG_CONFIG_HOME")` traced
across `default_credentials_path` → through `Path()` → into `os.open` — a correct cross-function,
env-source, through-unknown-call trace (env untrusted by design, not a bug).

**Open questions:** none blocking. **Next:** Task 16.4 (engine + output integration — CWE→severity
through the deterministic scorer, JSON `1.2` `finding_type`, SARIF `codeFlows`/CWE taxa, `--fail-on`
over both types, dashboard rendering; pins the `POSSIBLE-FLOW` discount constant).

---

## Task 16.2 — Sink detection + rule pack (intra-procedural)  (2026-06-13)

**Status:** complete, Validation Gate passing. No new dependencies (stdlib `ast` + `re` + the
existing import-graph file walker). New package `src/vulnadvisor/sast/` — the first M16 code,
implementing exactly the §3 rule schema from the approved design doc.

Find every sink, classify locally, never crash on weird code:

- **`sast/model.py`** — `SastTier` (the four design-doc tiers: `CONFIRMED_FLOW` / `DYNAMIC_UNKNOWN`
  / `POSSIBLE_FLOW` / `SANITIZED`, its own enum — *not* the import-centric `ReachabilityTier`) and
  `SinkHit` (frozen pydantic: cwe/kind/title/file/line/col/callee/tier/reason). Task 16.2 fills
  `tier` as a **local** guess; 16.3 proves the source→sink flow and refines it.
- **`sast/rules.py`** — the rule pack **as pure data** (frozen dataclasses, like `public_api.py`):
  `SinkRule(callee_kind, callees, tainted_positions/keywords, guard, safe_args, sanitizers)` over
  three `CalleeKind`s — `MODULE` (`os.system`, `subprocess.*`, `yaml.load`, `pickle.loads`,
  `requests.*`, `urllib.request.urlopen`, …), `BUILTIN` (`eval`/`exec`/`compile`, `open`),
  `METHOD` (`cursor.execute`, unresolved receiver → heuristic). All 7 CWEs from the design:
  **78** (with a `shell=True` `Guard` for `subprocess.run/call/Popen/...`; `os.system`/`getoutput`
  always shell; `shlex.quote` sanitizer), **89**, **94/95**, **502** (`yaml.load` cleared by a
  `SafeLoader` safe-arg; `yaml.safe_load` isn't a sink at all), **22** (`secure_filename`
  sanitizer), **918** (positional + `url=` keyword), **798** (literal `SecretPattern` regexes —
  AWS/private-key/GitHub/Slack — plus secret-named literal assignments with a placeholder/length
  denylist).
- **`sast/sinks.py`** — the single **pure** matcher. `find_sinks_in_source(source, rel)` (pure, no
  I/O) and `find_sinks(project_dir)` (defensive file walk, reuses `_iter_python_files`). Callees are
  resolved through per-file import bindings, so **aliased imports match the same rule**:
  `import yaml as y; y.load(...)`, `from os import system as run; run(...)`, and the 3-segment
  attribute chain `urllib.request.urlopen` all resolve to their canonical FQN (the `callee` display
  is the FQN regardless of import style). Local tier guess: literal/`SafeLoader`/sanitizer-wrapped
  dangerous arg → `SANITIZED`; non-literal → `POSSIBLE_FLOW` (pending 16.3); CWE-798 literal →
  `CONFIRMED_FLOW` (the literal *is* the vuln). **Soundness direction is always toward a hit:**
  `*args` splats, non-literal `shell=` values, and unresolved receivers classify
  `POSSIBLE_FLOW`/stay-a-sink, never clear; `shell=False`/`shell` absent → the safe argv form is
  *not* reported; an unparseable file is skipped, never raised.

**Validation:** ruff + format clean · `mypy --strict src` clean (69 files; fixed an `ast.walk`
narrowing) · **pytest 588 passed, 1 skipped** (+41 in `tests/test_sast_sinks.py`: table-driven
positive/negative/**adversarial** per rule — aliased `import yaml as y`, `from os import system as
run`, chained-receiver `conn.cursor().execute`, 3-segment `urllib.request.urlopen`; the
`shell=True`/`False`/`<expr>`/absent matrix; `yaml.safe_load`/`SafeLoader`/`shlex.quote`/
`secure_filename` clearing; secret patterns + placeholder/short-value rejection + no double-count;
`*args` stays cautious; `re.compile` ≠ builtin `compile`; deterministic sort; unparseable → `()`).
**Runs over `fixtures/` and the repo's own `src/` without crashing, output deterministic** (asserted
in the gate).

**Open questions:** none blocking. **Next:** Task 16.3 (taint propagation on the existing call
graph — sources, entry-point breadth expansion, `CONFIRMED-FLOW` with a provable source→sink path).

---

## Task 16.1 — SAST v1 design doc (approval gate)  (2026-06-13)

**Status:** **APPROVED by the maintainer 2026-06-13** — Validation Gate passing (doc coverage +
recorded approval). No code in this task, per the gate. First M16 task. Proceeding to 16.2.

**Maintainer decisions on the §13 open questions** (folded into the doc's status banner + §13):
(1) `POSSIBLE-FLOW` discount factor — **fix in 16.4 with a table-driven test** (no constant pinned
now); (2) **CWE-798 stays in v1** (literal-pattern finding, `source == sink`, empty path);
(3) **stdin/argv/env are untrusted by default** (over-report per soundness; trusted-operator
opt-out is a later non-default, if ever).

Wrote **`docs/sast-design.md`** — the architecture agreement that precedes any M16 code. It pins
the contract Tasks 16.2–16.6 implement; a later deviation requires amending the doc first. House
style follows `docs/platform-design.md` (status/approval banner, numbered sections).

Coverage against the Validation Gate checklist (every required item present):

- **Rule schema** (§3) — sources/sinks/sanitizers **as data, pure matching**: `SinkRule` /
  `SourceRule` / `SanitizerRule` shapes, callee resolved through the **existing** import-graph
  binding logic (`call_paths._bindings`) so aliases (`import yaml as y`, `from os import system`)
  match; CWE-scoped sanitizers; `guard` for conditional sinks (`shell=True`); `safe_args` mirroring
  the existing `guarded_apis`. Initial CWE set table: **CWE-89, 78, 94/95, 502, 22, 918, 798** with
  representative resolved sinks + v1 sanitizers. CWE-798 documented as a literal-pattern finding
  outside the taint graph.
- **Tier semantics + soundness proof obligations** (§4) — four tiers **`CONFIRMED-FLOW` /
  `POSSIBLE-FLOW` / `DYNAMIC-UNKNOWN` / `SANITIZED`** (own enum, *not* reused from
  `ReachabilityTier` — import-centric vocab doesn't fit), each with an explicit proof obligation;
  five release-blocking invariants (no silent clear; `SANITIZED` needs total path coverage; dynamic
  never downgrades; entry-point completeness is sacred; FFI escalates) — the SAST analogue of the
  SCA "zero missed reachable findings" gate. Concern ordering fixed.
- **Scoring** (§5) — **CWE→base-severity table** fed into the *same* `engine/scoring.compute_score`
  with **EPSS and KEV absent** (the formula already handles `epss=None`); tier discounts mirror
  `apply_reachability` (`SANITIZED` → INFO band like `NOT_IMPORTED`, `DYNAMIC-UNKNOWN` keeps full
  severity — uncertainty is not a discount). Constants live in `engine/`, unit-tested, published,
  LLM-untouched. **No EPSS for first-party — documented.**
- **Output schema** (§7) — **JSON `schema_version` 1.2, additive**: a `finding_type`
  discriminator (`"dependency"` set on existing findings too) + a `"code"` finding sub-shape
  (`rule`/`location`/`flow`/`score`/`fix`); 1.0/1.1/1.2 all ingest. **SARIF mapping** (§8):
  `ruleId` namespaced `vulnadvisor/<kind>`, **CWE taxonomy via `taxa`/`relationships`**,
  source→sink as a SARIF **`codeFlow`**, `--fail-on` over both types.
- **FFI boundary policy** (§9) — a taint path crossing into a C/Rust native extension
  **escalates to `DYNAMIC-UNKNOWN`** (named boundary), never terminates as clean, never counts as a
  sanitizer.
- **Test/fixture strategy** (§12) — table-driven per rule (positive/negative/adversarial); ≥12
  taint fixtures incl. framework-routed FastAPI+Django and partial-sanitization; soundness
  regression tests encoding the §4 invariants; <10 s perf budget; Bandit benchmark.
- **Explicit non-goals** (§10) — **no cross-language call graphs**, **no dataflow through I/O**
  (write-to-file/DB then read-back is a fresh untainted read unless itself a modeled source), no
  inter-file global aliasing, no taint through eval/exec-constructed code, no auto-fix (M17), **no
  new runtime dependency** (stdlib `ast` + existing call graph; core-wheel dep count guarded by a
  metadata test as in 15.3).
- **Package layout** (§11) — `src/vulnadvisor/sast/` (`rules.py`/`sinks.py`/`taint.py`/`model.py`)
  + additive touch points in `engine/`/`model/`/`output/`/`cli/`. **Reuse table** (§2) maps each
  existing component (`call_paths.py` BFS, framework plugins, `type_resolver`, `model/callpath.py`,
  `engine/scoring.py`, `output/`) to its SAST role — the differentiator already exists for deps.

Three open questions for the reviewer recorded in §13 (POSSIBLE-FLOW discount constant; CWE-798
placement in v1; treating stdin/argv/env as untrusted by default).

**Validation:**
- [x] Doc covers rule schema, tier semantics + soundness obligations, scoring, output schema,
  test/fixture strategy, FFI policy, explicit non-goals — all present (mapped above).
- [x] **Maintainer approval recorded in PROGRESS.md** (2026-06-13, decisions above). No global gate
  (ruff/mypy/pytest) applies — this task adds no code.

**Open questions:** none — §13 resolved. **Next:** Task 16.2 (sink detection + rule pack).

---

## Task 15.3 — VulnAdvisor MCP server (agent-native triage)  (2026-06-13)

**Status:** complete, Validation Gate passing. **New dependency (approved at task start):
`mcp==1.27.2`** added as a *user-facing optional extra* `[mcp]` (`pip install 'vulnadvisor[mcp]'`)
— the published core wheel still has **exactly 3 runtime deps** (packaging/pydantic/typer), proven
by a metadata test. The same pin is mirrored into the `dev` dependency-group (uv 0.11.19 has no
`default-extras`) so a default `uv sync` gives contributors an env where `mypy`/`pytest` can
type-check and exercise the server.

An editor agent (Claude Code / Cursor / any MCP client) can now ask "what's reachable here and
why" and get engine truth, fully offline beyond the public vuln APIs a scan already uses:

- **`vulnadvisor mcp`** (new Typer command, `cli/main.py`) serves a **stdio** MCP server. The
  third-party `mcp` SDK is imported **lazily** inside the command, so a user without the extra
  gets a clean install hint (`pip install 'vulnadvisor[mcp]'`, exit 1) instead of a traceback.
- **New `src/vulnadvisor/mcp/` package, split pure ↔ wired** (the codebase's "pure and testable"
  rule): `tools.py` (filter/lookup/explain over a plain report dict — **no MCP import**, no
  network, no filesystem; fully unit-tested), `state.py` (`ReportStore` — single-row SQLite
  "last report", defensive load → `None` on corrupt/missing, never raises into a tool call),
  `session.py` (`McpSession` — holds the current report in memory after a scan, falls back to the
  persisted last scan; the scan fn is **injected** so the whole session runs offline in tests),
  and `server.py` (the **only** module importing `mcp.server.fastmcp`; registers the four tools,
  reports VulnAdvisor's own version as the server version — FastMCP otherwise advertises the SDK's).
- **Four tools, all deterministic engine truth:** `scan(path)` runs the same engine the CLI uses
  (incremental cache + type resolver + framework plugins; **no LLM** — wording is the client's
  job), persists the report, returns counts + compact rows; `list_findings(tier/band/package/
  min_score/in_kev/limit)` filters that report (unknown tier/band → a helpful tool error listing
  the valid vocabulary, never a silent empty match); `get_finding(id)` returns full evidence —
  advisory, score, reachability tier with import sites **and the concrete call path**, fix;
  `explain_finding(id)` returns the engine's deterministic **facts** (priority + rationale, tier +
  its CLAUDE.md meaning, KEV/EPSS/CVSS signals, fix) plus a plain-statement list for the client to
  narrate. Findings are referenced by `finding_id` (`<pkg>:<advisory-id>`), CVE/display id, alias,
  **or bare package name** (ambiguous → an error listing the exact finding_ids — helpful, never
  lossy). Soundness held: no tool re-ranks, invents a verdict, or emits an unfounded all-clear
  (the `actionable` count is a tally of non-`not-imported` tiers, explicitly *not* a safety verdict).

**Validation:** ruff + format clean · `mypy --strict src platform` clean (93 files) · **pytest
547 passed, 1 skipped** (+24: pure-tool filter/lookup/ambiguity/explain-facts/tier-meaning matrix;
`scan_summary` tier+actionable counts; **MCP protocol round-trip** over the in-memory client↔server
transport — 4 tools advertised with JSON-Schema inputs, scan→list→get→explain against a seeded
jinja2 project incl. the call-path evidence; list-before-scan and unknown-tier surface as tool
errors; **last-report persists across two SQLite-backed sessions** without re-scanning; corrupt row
→ no-scan; **core-wheel runtime deps == {packaging,pydantic,typer}** with mcp extra-only). **Live
check** (real `uv run vulnadvisor mcp` over an actual **stdio** transport, driven by the `mcp`
stdio client against `examples/quickstart`, network live): server `vulnadvisor 1.0.4`, 4 tools,
`scan` → 9 findings (2 imported-and-called, 7 not-imported, 0 degraded), top =
**pyyaml CVE-2020-14343 imported-and-called**, `get_finding` returns 1 import site + 1 call path,
`explain_finding` returns the tier meaning + facts ("CVE-2020-14343 affects pyyaml 5.3.1."), a bad
id is a tool error. This is exactly the round-trip an editor agent drives.

**Open questions:** none blocking. M15 complete (copilot + MCP). Next: M16 — Task 16.1 SAST
design doc (approval gate, no code).

---

## Task 15.2 — Copilot UI  (2026-06-13)

**Status:** built + gated; the only outstanding item is the live **LLM chat round-trip**
(ask → cites top finding → click deep link), blocked on a working model key (the OpenAI key
was revoked mid-session; paste a free OpenRouter key to close it). **New npm deps (pinned
exact, dashboard-only): `@ai-sdk/react@3.0.206`, `react-markdown@10.1.0`, `remark-gfm@4.0.1`.**

Help that is present everywhere and in the way nowhere:

- **Floating launcher → slide-over panel** (`components/copilot/copilot-panel.tsx`, mounted
  once in the app shell): a fixed "How can I help?" button opens a right-side **Sheet**
  (`components/ui/sheet.tsx`, a slide-over built on the same Radix Dialog primitive the app's
  modals already use — focus trap, Esc, scroll-lock, sibling `aria-hidden` SR-modality all
  inherited). Streams from `/api/copilot` via the AI SDK's `useChat` +
  `DefaultChatTransport`; the transport's `prepareSendMessagesRequest` is built per send so it
  always carries the current `orgSlug`, page-context label, and — if present in this browser —
  the BYOM personal-key headers (15.1b), picked up fresh even if the key was saved mid-session.
- **Org-scoped, privacy-first:** the launcher only renders where an org slug is derivable from
  the path (`/orgs/{org}/**`); on home/setup/demo it returns null. The conversation lives only
  in React state — never persisted to localStorage, never sent anywhere but the request itself
  (we don't store chats). "Clear" wipes it; closing keeps it for the session.
- **Markdown + deep links:** assistant turns render through `react-markdown` + `remark-gfm`
  (minimal `prose-copilot` styles, no typography plugin). The system prompt now instructs the
  model to cite a finding as `[<pkg> <advisory_id>](/scans/<scan_id>?finding=<advisory_id>)`
  using verbatim tool-result strings; the panel routes such in-app links client-side and
  closes on click. The scan page reads `?finding=` and **expands + scrolls the matching card**
  (`matchesFocus` in `lib/copilot-ui.ts` pairs exactly with the link builder; `FindingCard`
  gained `focus`/`defaultOpen` props). Context chip shows the current page; three suggested
  prompts seed an empty conversation ("What should I fix first?", "Why is this deprioritized?",
  "Explain this call path").
- **15.1c follow-up bundled here:** the BYOM config modal's mount-time localStorage hydration
  was a setState-in-effect (a stricter lint rule flagged it). Refactored to
  `useSyncExternalStore` over a tiny `lib/byom.ts` snapshot store (subscribe + raw-string
  snapshot; same-tab writes notify, cross-tab via the `storage` event) — lint-clean, SSR-safe,
  and the trigger label now reflects a saved key reactively.

**Validation:** `npm test` **60/60** (+6 copilot-ui: org/context derivation, the deep-link
build↔match contract, internal-vs-external href, suggested prompts) · lint + `next build`
clean · **SSR e2e** (seeded `c:\tmp\va151`): launcher present on `/orgs/acme`, absent on `/`;
`?finding=PYSEC-2019-217` expands exactly the jinja2 card (0 finding-cards open at baseline →
1 on match → 0 on a non-matching token) · **headless-Edge panel e2e 13/13**: opens from the
launcher (after hydration), named dialog (role + "Triage copilot" title), rest of document
hidden from SR while open, input focused on open, three suggested prompts, `aria-live` polite
conversation log, focus trap holds across 12 Tabs, Escape closes, launcher absent off-org.

**Open / blocked:**
- **LLM chat round-trip e2e pending a working key.** Everything structural is verified; the
  one thing needing a live model is the ask→answer→cited-deep-link flow. With a free
  OpenRouter key: open the panel on a seeded org, set the key in Settings → AI copilot, ask
  "what should I fix first?" → it should cite the top finding and the link should open its
  expanded card. (Same key unblocks red-team 5–6.)
- `react-markdown`/`remark-gfm` pull a few transitive deps; `npm audit` unchanged in severity
  (the pre-existing Next/postcss moderates).

---

## Task 15.1 — Copilot backend: grounded, org-scoped, injection-hardened  (2026-06-13)

**Status:** implementation complete; full gate green **except the live red-team run, which is
blocked on `ANTHROPIC_API_KEY`** (no key in any env/.env — the harness + snapshots are built and
ready; see Open questions). **New npm deps (pre-declared in task.md, pinned exact):
`ai@6.0.203` + `@ai-sdk/anthropic@3.0.84`** — dashboard-only, published wheel untouched.

An assistant that answers from *your* scan data and cannot be talked out of its rules:

- **Platform — BYO key encrypted at rest + daily cap (`copilot.py`, `routers/copilot.py`,
  Alembic `f7a2d9c4e8b3`):** `orgs.copilot_key_ciphertext/_hint` (Fernet under a SHA-256
  derivation of `SECRET_KEY` — no second secret to rotate) + `copilot_usage(org_id, day, count)`.
  Settings endpoints: `GET /v1/orgs/{org}/settings/copilot` (members; `byo_key_set`, `…last4`
  hint, cap, `used_today`), `PUT`/`DELETE .../settings/copilot-key` (owner/admin; key format
  validated `sk-ant-*`, returned **never** — only the hint). **Grant endpoint**
  `POST /v1/orgs/{org}/copilot/grant`: the *only* place the decrypted key leaves the platform,
  and it requires **both** the shared `COPILOT_SERVICE_TOKEN` header (constant-time compare;
  503 when unconfigured, 403 otherwise) **and** the caller's own session (`require_org` → 404
  cross-org, even with a valid service token). Consumes one slot of the per-org UTC-day cap
  (`COPILOT_DAILY_CAP`, default 50) → 429 when spent; the count commits only on a successful
  grant. Corrupted/undecryptable ciphertext is a **loud 500** ("re-save the key"), never a
  silent fallback.
- **Design decision (the "never returned by any endpoint" gate):** the dashboard has no DB, so
  the decrypted key must cross to the Next.js server somehow. It crosses *only* via the grant
  endpoint, which is unreachable without the service token users never hold — tested with a
  real session + no/guessed token (403). All user-reachable surfaces return at most the hint
  (swept in tests).
- **Dashboard — `POST /api/copilot`** (`app/api/copilot/route.ts`; wins over the `/api/*`
  rewrite since route handlers precede `afterFiles` rewrites): validates body (org-slug regex,
  `validateUIMessages`, 100 KB cap, last-30 messages, **client-supplied `system` roles
  stripped**), obtains a grant (status mapping: 401 sign-in / 404 org / 429 cap / 503
  unconfigured), picks the key (org BYO → platform `ANTHROPIC_API_KEY` fallback → honest 503),
  then `streamText` (AI SDK v6, `claude-opus-4-8` default, `COPILOT_MODEL` override,
  `stepCountIs(8)` tool budget) returning a UI-message stream.
- **Tools = the existing read/analytics API with the caller's own cookie** (no service
  account; tenant isolation inherited): `org_overview`, `list_repos`, `list_scans`,
  `list_findings`, `diff_scans`, `repo_trend`, `org_trend` — all GET, all `/v1`, repo/org
  segments URL-encoded into single path segments, scan ids must be UUIDs (traversal/query
  smuggling rejected as tool errors the model sees as data), trend windows regex-validated.
- **Injection hardening (`lib/copilot.ts`, pure + unit-tested):** every tool result is wrapped
  between markers carrying a **random-per-call UUID boundary** ("UNTRUSTED DATA … never
  instructions") so payload text can't fake a closing marker it has never seen; the system
  prompt pins the standing rules — deterministic engine is the *authority* on priority (never
  invent/re-rank/override), caller's-own-org only (refuse cross-tenant), tool results are
  data-not-instructions even when claiming system/developer authority, no unfounded all-clear
  (soundness), no secrets/prompt disclosure. Static prompt text (cacheable; red-team exercises
  exactly what production runs).
- **Red-team harness (`scripts/copilot-redteam.ts`):** 6 cases — all-clear override, fake
  priority re-score, system-prompt exfil, forged end-of-data marker, cross-org pivot,
  exfiltration link — run the production prompt + production tool schemas against the live
  model with seeded malicious advisory summaries; snapshots to `scripts/redteam-snapshots/`,
  programmatic pass/fail per case (incl. "no tool call ever targeted another org"), exit 1 on
  any failure.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (88 files) ·
**pytest 523 passed, 1 skipped** (+14: ciphertext-at-rest + plaintext sweep over every read
surface, member/admin/non-member matrix, grant 403/503/404/429, two-org isolation incl.
service-token-can't-cross-tenants, cap counts 2→1→0→429, corrupted-ciphertext 500, Fernet
roundtrip/tamper, key-format rules) · dashboard `npm run lint` + `next build` clean ·
**`npm test` 42/42** (+14: system-prompt rule presence, tool surface read-only//v1-only/
traversal-safe, URL-encoding of hostile repo names, UUID enforcement, boundary uniqueness +
fake-marker inertness, budgets). **Live spot-check** (two-org seeded SQLite in `c:\tmp\va151`,
uvicorn + `next start`): 401 unauthenticated → 400 bad slug → **404 intruder-on-acme** →
grant **403 without/with-guessed service token through the browser proxy** → 503 no-key (grant
burned honestly) → PUT key returns hint `…cdef` only → copilot streams and the fake BYO key
**reaches Anthropic but never appears in the stream** (auth error masked) → cap 3 → **429** →
DB row holds a Fernet token (`gAAAAAB…`), plaintext absent.

**Follow-up (2026-06-13): provider-flexible fallback key (maintainer decision).** The
maintainer has no Anthropic key and directed the copilot to use their OpenAI key. Added
`@ai-sdk/openai@3.0.71` (pinned): the *deployment fallback* key may now be either vendor —
provider + default model (`claude-opus-4-8` / `gpt-5.2`) are detected from the key's prefix
(`providerForKey`, unit-tested); `COPILOT_MODEL` still overrides; **org BYO keys remain
Anthropic-only** (platform still validates `sk-ant-`). The red-team harness follows the same
detection (`OPENAI_API_KEY` accepted) and now fails cleanly (exit 2 + provider message) on
auth/quota errors instead of a stack dump. This diverges from the instructions-file stack rule
("Anthropic API for the plain-English layer") — recorded here as an explicit maintainer call.
Lint/build clean; `npm test` 43/43.

**Follow-up (2026-06-13): Task 15.1b — BYOM personal-key pass-through (maintainer-requested,
now in task.md).** Anyone can use the copilot at zero platform cost by bringing their own
key: `/api/copilot` accepts `X-Copilot-User-Key` (+ optional `X-Copilot-Provider` /
`X-Copilot-Model`), used for that single request and never stored or logged — the key lives
in the user's browser (localStorage UI = Task 15.1c, ships with the 15.2 panel) and transits
per request over TLS. Providers: **OpenRouter** (`sk-or-`, OpenAI-compatible
chat-completions via `createOpenAI({baseURL}).chat()`, default `openrouter/auto` — free
models work), OpenAI, Anthropic. Personal-key requests **skip the grant and the daily cap**
(no platform spend to protect) but still verify org membership with the caller's own session
before any model call. Key precedence: personal → org BYO (encrypted, capped) → deployment
fallback. Chose pass-through over the browser-direct variant deliberately: OpenAI's API
blocks browser CORS, browser-direct would punch per-provider holes in the strict CSP, and
the injection-hardened tool loop would need a client-side duplicate; local **Ollama** is the
one case that genuinely needs browser-direct (server can't reach a user's localhost) —
recorded as an explicit deferred non-goal in task.md 15.1b. Validation: `npm test` 47/47
(+4: `sk-or-` detection, per-provider defaults, key/model/provider format rules), lint +
build clean; live: malformed key/provider → 400, intruder + personal key → 404, fake
OpenRouter key reaches the provider with the key absent from the stream, and `used_today`
stays 0 across personal-key requests.

**Follow-up (2026-06-13): Task 15.1c — BYOM key-configuration UI.** `lib/byom.ts` (pure,
storage-injectable): defensive parse/serialize of the localStorage config (anything malformed
degrades to null), the 15.1b header mapping, masking (`sk-or-…cdef`), private-mode-safe loads.
`components/copilot/byom-config.tsx`: shadcn Dialog from the org settings page ("AI copilot"
section) — provider radiogroup (OpenRouter/OpenAI/Anthropic), masked key field with live
validation, optional model override (placeholder = provider default), test-connection (one
trivial request through `/api/copilot` with the 15.1b headers; stream errors surface as
"provider rejected the key"), clear button, `aria-live` status, labelled fields. Save writes
localStorage only — no network call. Validation: `npm test` 54/54 (+7 byom), lint + build
clean. In-browser e2e (focus trap, real free-OpenRouter-key test-connection) rides with the
Task 15.2 live pass — grab a free key at openrouter.ai when we get there.

**Open questions / blocked:**
- **Red-team live run still blocked — now on quota, not key type.** The provided OpenAI key
  authenticates (models list 200) but the account has **zero credits**: every inference call,
  even `gpt-4.1-nano`, returns `insufficient_quota`. To close the gate either add billing to
  that OpenAI account or supply any funded key, then from `dashboard/`:
  `OPENAI_API_KEY=... node scripts/copilot-redteam.ts` (or `ANTHROPIC_API_KEY=...`) — writes
  the ≥5 snapshots and exits non-zero on any failed case.
- `npm audit` shows 2 pre-existing moderates (Next.js's bundled postcss), unrelated to the new
  deps; the "fix" downgrades Next to 9.x — ignored deliberately.
- Production env to set: platform `COPILOT_SERVICE_TOKEN` (+ same value in the dashboard env),
  dashboard `ANTHROPIC_API_KEY` (platform fallback key), optional `COPILOT_DAILY_CAP` /
  `COPILOT_MODEL`. Documented in both `.env.example`s.

---

## Task 14.3 — Product tour + teaching empty states + demo mode  (2026-06-12)

**Status:** complete, Validation Gate passing. **New npm dep (approved at task start):
`driver.js@1.4.0`** (pinned exact; ~5 kB, zero deps, MIT) — dashboard-only, the published
wheel is untouched.

Nobody lands on a page they don't understand, including logged-out visitors:

- **Product tour** (driver.js, Aegis-themed via `popoverClass` + token overrides in
  `globals.css`): two legs joined by a sessionStorage handoff. Leg A on an org home —
  posture hero ("Am I protected?") → repo list — then navigates to that org's **latest real
  scan**; leg B there — first finding card (**expanded for the user** before highlighting) →
  tier badge ("why it's quiet") → sidebar Analytics → Settings. Pure step/rule definitions in
  `lib/tour.ts` (selectors, leg shapes, `shouldAutoStart`); runner in
  `components/tour/product-tour.tsx`, streamed as a third shell slot (`ShellTour` computes
  latest-scan-per-org from the existing palette data). Steps anchor to **stable
  `data-tour` attributes** (posture-hero, repo-list, finding-card, tier-badge,
  nav-analytics, nav-settings, help-menu); steps whose element is absent/invisible are
  filtered (demo has no Settings → that step drops out). **Auto-starts once** on a signed-in
  org home; completing OR dismissing writes `va_tour_done` (localStorage, allowed per task)
  — it never reappears unasked. Re-launchable from the new top-bar **help menu**
  (CircleHelp: Product tour / Explore the demo org / Documentation); on a non-start page it
  navigates home first. `prefers-reduced-motion` → `animate: false`.
- **driver.js 1.4.0 bug found live and worked around:** the library never registers its
  internal `nextClick`/`prevClick`/`closeClick` hooks, so without explicit handlers the
  popover **buttons are silent no-ops** (only arrow keys work — verified in the bundled
  source: `L("nextClick")` dispatches into an empty registry). Fix: global
  `onNextClick/onPrevClick/onCloseClick` calling `moveNext/movePrevious/destroy`; the
  handoff step's own `onNextClick` still takes precedence.
- **Demo mode (`/demo`)** — public, no auth, watermarked, **read-only by construction**:
  `lib/demo-data.ts` is a typed seeded org (Acme Robotics (demo): payments-api with a
  jinja2 CVE-2019-10906 KEV + call-path marquee and a previous scan with a since-fixed
  flask finding; etl-pipeline with imported/dynamic-unknown; internal-tools all
  not-imported) whose **overview/packages aggregates are computed from the findings** at
  module load, so the demo can never contradict its own cards; the trend's last point is
  pinned to the derived totals. Routes `/demo`, `/demo/repos/[repo]`, `/demo/scans/[scan]`
  (working tier/band filters), `/demo/analytics` compose the exact product components
  (PostureHero, FindingCard, recharts kit — `PackagesBar` gained an additive
  `scanPathPrefix` so click-through stays in /demo). Demo pages import **only demo-data +
  presentational components — never `lib/api`**; the demo layout banner ("Demo organization
  — sample data, read-only") carries "Take the 60-second tour" + a sign-in link; the
  sidebar shows a demo org chip, Repos/Analytics nav, and a disabled Settings. The demo
  **never auto-starts** the tour (banner offers it instead).
- **Empty-state pass (one sentence + one action):** home signed-out card gains "or explore
  the live demo" (the landing-page hook); org-with-no-repos → "Set up scanning" button
  (was two competing actions); repo trend/scans-empty/ref-filter → upload command or "show
  all refs"; clean scan → `--fail-on high` CI hint; filtered scan → "clear the filter";
  empty analytics footer → **links to /demo/analytics** ("see this page with data");
  setup-page per-org empty tightened to one action.

**Validation:** dashboard `npm run build` + `npm run lint` clean · **`npm test` 28/28**
(+17: auto-start contract incl. done-flag/handoff/demo/non-home cases, start/scan page
classification, leg shapes, **selector drift guard** — every tour selector must exist as a
`data-tour` anchor in the sources; demo: no `lib/api`/`next/headers`/`fetch(`/`<form`/
mutating-component imports anywhere under `app/demo`, watermark present, every finding has
known tier/band + fix, summaries match findings, overview internally consistent, trend's
last point equals the overview, packages ranked + clicking through to existing demo scans,
tour scan's first finding has a call path + KEV) · ruff + format clean · `mypy --strict
src platform` clean (86 files) · **pytest 509 passed, 1 skipped** (no Python changes).
**Live e2e** (seeded SQLite in `c:\tmp\va143`; uvicorn + `next start` + headless Edge):
- **SSR 29/29 PASS** — and the four /demo pages return identical 200s **with the API
  process down** (zero backend coupling proven); watermark/tour-offer/hero("At risk — 1
  KEV-listed finding")/anchors/repos in HTML; scan page carries CVE-2019-10906 + KEV badge
  + call path + fix command; tier filter filters; unknown demo scan → not-found; analytics
  KPIs + aria values + /demo-scoped click-through; signed-out home links the demo; no
  `<form>` on any demo page.
- **Browser 25/25 PASS** — tour auto-starts on first org-home visit, walks hero → repo
  list → **navigates to the real scan** → finding card auto-expanded (asserted
  `aria-expanded=true`) → tier badge → analytics → settings → Done writes the flag;
  **reload shows no tour** (completion AND skip paths both asserted); clearing the flag
  re-arms it; help menu relaunches from a non-start page (navigates to the org home);
  demo: never auto-starts, banner button runs the full tour inside /demo with the settings
  step filtered, and **zero browser requests hit the API** across the whole demo session
  (request-log asserted). Screenshots eyeballed (tour step 1, expanded KEV finding mid-tour,
  demo repo page).

**Open questions:** none blocking. M14 complete. Next: M15 — Task 15.1 copilot backend
(new npm deps `ai` + `@ai-sdk/anthropic` to approve at task start).

---

## Task 14.2 — One-click GitHub App install + auto-setup PR  (2026-06-12)

**Status:** complete, Validation Gate passing. **New dev dep (approved at task start):
`pyyaml==6.0.3`** — test-only (the gate's "valid YAML" check needs a parser); the published wheel
stays at 3 runtime deps.

From "Sign in with GitHub" to a scanning repo without leaving the browser:

- **Pure content (`setup_pr.py`):** `render_workflow(default_branch, api_url)` — the proposed
  `.github/workflows/vulnadvisor.yml` (checkout → setup-python 3.12 → `pip install vulnadvisor` →
  `vulnadvisor scan . --upload` with `VULNADVISOR_API_KEY` from a repo secret and `API_URL` from
  the new `public_api_url` setting; commit/ref auto-detected via the 12.2 `GITHUB_SHA`/`GITHUB_REF`
  logic, so zero flags). Branch/URL interpolated via `json.dumps` (a strict subset of YAML
  double-quoted scalars — any legal branch name stays valid YAML). The scan **never fails the
  user's build by default** (`--fail-on` is suggested in the PR body for later).
  `render_pr_body(...)` — what the workflow does, the **one manual step** (add the
  `VULNADVISOR_API_KEY` secret, deep link to Settings → API keys, `vulnadvisor login` as the
  alternative), the privacy facts ("only the JSON report leaves CI"), and the idempotency promise
  in writing. `setup_status(scan_count, setup_pr_state)` — the chip rule (scans always win).
- **GitHubApp.open_setup_pr** (REST, installation token from 11.6): fixed branch
  `vulnadvisor/setup` = the idempotency key. Base-branch head → create the branch once → PUT the
  workflow (skips the commit when the branch already holds identical content; passes the file
  `sha` on updates) → if an open PR from that branch exists, **PATCH it in place**, else POST a
  new one. Returns `SetupPr(number, url, created)`. All GitHub errors → contextual
  `GitHubAppError` (route maps to 502).
- **`POST /v1/orgs/{org}/repos/{repo}/setup-pr`** (session/Bearer auth): `require_org` +
  `require_admin` + `require_repo`; 409 for CLI-only repos (no `github_repo_id`) and for orgs
  with no App installation; persists `setup_pr_number/url/state` on the repository row.
- **Webhook lifecycle sync:** `pull_request` events whose head is `vulnadvisor/setup` update the
  stored state (opened/reopened → `open`; closed+merged → `merged`; closed unmerged → cleared =
  honestly "Not set up" again) and are **never commented on** (no triage noise on our own
  one-file PR). New columns `repositories.setup_pr_number/url/state` (Alembic `d4c8b6e2f1a9`).
- **Status chips** (derived, never stored): `not-set-up` / `pr-open` / **`pr-merged`** ("Merged ·
  awaiting first scan" — a 4th state beyond the task's three, because showing "Not set up" right
  after a merge would be dishonest) / `receiving-scans` (any scan wins). `RepoOut` gains
  `github_linked` + `setup_status` + `setup_pr_url` (additive).
- **Dashboard:** new **`/setup`** page (the App's post-install Setup URL): per-org repo rows with
  chips + **"Open setup PR"** (client POST through the same-origin proxy; flips to "Update setup
  PR" + "View PR"; CLI-only repos say so and get no button); signed-out → GitHub sign-in card.
  Onboarding CTAs: home empty-state gets an Install button, org page repo rows carry the chips +
  a "Set up scanning" button, settings links `/setup`. `SetupChip` palette: teal only for
  receiving-scans, amber for merged-unverified, blue for PR-awaiting-action, muted for not set up.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (86 files) · **pytest 509
passed, 1 skipped** (+27: workflow exact snapshot + `yaml.safe_load` structure + awkward branch
names; PR-body content; status table; `open_setup_pr` against a stateful MockTransport GitHub —
create path / **re-click = 1 PR, 1 commit, PATCH not POST** / changed-content recommit with `sha` /
missing base branch; route flow — webhook install → sync → setup PR → chip `pr-open`, re-click
`created:false` never duplicates, merged/closed webhook transitions, receiving-scans wins,
409 unlinked / 409 no-installation / 403 member / **404 cross-org** / 502 GitHub-down with no
half-recorded state). Migration applied to **live Postgres** (docker compose): `alembic upgrade
head` + `alembic check` no drift. Dashboard `npm run build` + `lint` + `npm test` (11/11) clean.
**Live e2e** (seeded SQLite in `c:\tmp\va142`; uvicorn + `next start` + headless Edge; the only
fake is GitHub itself — a local REST stand-in on :9999, with the platform signing a real RS256
App JWT): **browser 20/20 PASS** — /setup lists both repos ("Not set up" ×2, CLI-only repo has no
button), click → chip "Setup PR open" + working View PR link, fake GitHub holds exactly 1 PR with
the workflow at the right path (decodes to the snapshot, runs `scan . --upload`, uses the secret),
re-click → "Update setup PR", still 1 PR / 1 commit; signed merged webhook → "Merged · awaiting
first scan"; then `vulnadvisor scan examples/quickstart --upload` with only env vars (exactly the
workflow's CI step) → chip **"Receiving scans"** while local-only stays "Not set up". Screenshots
eyeballed. **Remaining for the maintainer (credential-gated, 11.6 precedent):** provision the
GitHub App (set `GITHUB_APP_ID`/`GITHUB_APP_PRIVATE_KEY`/`GITHUB_WEBHOOK_SECRET`/`PUBLIC_API_URL`,
point the App's **Setup URL** at `<dashboard>/setup`) and repeat install → PR → merge → Action on
a scratch github.com repo — every platform-side step of that path is what the 20/20 run exercised.

**Open questions:** none blocking. Next: 14.3 — product tour + teaching empty states + demo mode
(new npm dep `driver.js` to approve at task start).

---

## Task 14.1 — `vulnadvisor login` (device flow)  (2026-06-12)

**Status:** complete, Validation Gate passing. First M14 task. No new dependencies (CLI side is
stdlib `urllib`/`webbrowser`; platform side reuses the existing key machinery).

Key copy-paste is dead — RFC 8628-shaped three-legged flow:

- **Platform** — new `DeviceGrant` model (`device_grants` table, Alembic `b9e4d3a1c7f2`) +
  `routers/device.py`:
  - `POST /v1/device/code` (unauthenticated, **rate-limited**: ≥10 grants per requester IP per
    60 s → 429, DB-backed so it works multi-instance): mints a human-typable `user_code`
    (`XK7M-2PQ9`, 8 chars over an unambiguous alphabet — no 0/O/1/I/L) and a high-entropy
    `device_code` (**only its SHA-256 stored**, like API keys). Returns
    `verification_uri[_complete]` (dashboard `/activate`), `expires_in` 900 s, `interval` 5 s.
  - `POST /v1/device/approve` (session/Bearer auth): binds the grant to one of the caller's orgs
    via `require_org` (non-member org → 404, tenant semantics as everywhere). Input normalized
    (case/hyphen/space-insensitive). Unknown → 404, expired → 400, already used → 409.
  - `POST /v1/device/token` (the CLI poll): pending → 400 `{"error":"authorization_pending"}`
    (RFC error shape); expired → `expired_token`; unknown/consumed → `invalid_grant`. On an
    approved grant the org-scoped API key is **minted at poll time** — the plaintext secret
    exists only in that one response, never at rest — named `device login (<client>)` so it's
    recognizable/revocable under Settings → API keys; the grant is consumed in the same
    transaction (reuse rejected).
- **CLI** — `output/credentials.py` (store: `~/.config/vulnadvisor/credentials`, JSON, created
  via `os.open` mode **0600**, dir 0700, `XDG_CONFIG_HOME` honored; defensive loads → `None`,
  never a crash) + `output/devicelogin.py` (stdlib client; injectable `sleep`/`clock` for
  hermetic poll tests). `vulnadvisor login [--api-url] [--no-browser]`: prints the code, opens
  the browser (fallback prints the URL), polls, stores credentials — **the key is never
  printed**. `vulnadvisor logout` removes the file. `scan --upload` resolves credentials
  flag/env first, then the store — a bare `scan --upload` works with no flags after login.
- **Dashboard** — new `/activate` page: signed-out users get the GitHub sign-in card; signed-in
  users get a form (code prefilled from `?code=`, org selector from their memberships) that
  POSTs `/api/v1/device/approve` through the same-origin proxy; success says "Device connected —
  return to your terminal"; 404/400/409 mapped to human messages.
- **Windows-console honesty fix found live:** the success messages used "✓"/"—", which crash
  `cp1252` consoles (UnicodeEncodeError after a *successful* login). login/logout and the
  pre-existing `scan --upload` confirmation are now ASCII-only — a success must never exit 1
  while printing itself.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (85 files) ·
**pytest 482 passed, 1 skipped** (+36: full grant lifecycle incl. the minted key authorizing a
real `/v1/scans` upload + reuse rejected + hash-only-at-rest asserted; expiry blocks approve and
token; double-approve 409; unknown 404; unauth 401; **non-member org 404**; **rate limit 429
after 10**; code normalization; credentials round-trip/malformed/delete/XDG + **0600 asserted on
POSIX** (skipped on Windows — content/overwrite still asserted); device client: pending→token
with injected clock, expired/invalid/timeout/429/network errors; CLI: login stores credentials
**and never prints the key**, login failure exits 1, logout idempotent, bare `scan --upload`
uses the store, explicit flags beat the store). Migration applied to **live Postgres** (docker
compose): `alembic upgrade head` + `alembic check` no drift. Dashboard `npm run build` + `lint`
clean (`/activate` route compiles).
**Live e2e** (seeded SQLite in `c:\tmp\va141`, uvicorn + `next start`, headless Edge):
`vulnadvisor login --no-browser` printed `32WH-B9C4` → **browser 7/7 PASS** on the real
`/activate` page (form rendered, code prefilled from the URL, org defaulted, approve →
"Device connected", re-approval → "already used") → login exited 0 with credentials stored →
`scan examples/quickstart --upload` **with no flags and no env vars** uploaded 9 findings →
read API confirms the scan (`complete`, 9 findings) and lists the minted
`device login (yeshp@Parth_ROG)` keys.

**Open questions:** none blocking. Next: 14.2 — one-click GitHub App install + auto-setup PR.

---

## Task 13.5 — Security-posture hero + a11y/perf gate  (2026-06-11)

**Status:** complete, Validation Gate passing. Closes M13 → **dashboard v1.0** (tag
`dashboard-v1.0`). No new dependencies (`node --test` + Node ≥23.6 native TS type-stripping
power the new wording tests — `npm test`).

**The hero** — org home answers "am I protected?" in one glance:

- **`lib/posture.ts`** (pure, unit-tested): `computePosture(overview, scannedRepoCount)` →
  five levels with sound wording rules baked in: **KEV > 0 → "At risk"** even if every KEV
  finding is deprioritized (escalation-only; KEV = exploited in the wild) →
  **confirmed call path → "At risk"** → **dynamic-unknown-only → "Unverified — N findings
  cannot be ruled out"** (never "Protected", detail says "treat these as unresolved") →
  **imported-only → "Under watch"** (with a "N of them resists verification" note when dynamic
  is mixed in) → **"Protected"** only when scans exist AND actionable == 0.
  `scannedRepoCount` (from the repos list the page already fetches) disambiguates "no findings
  because nothing scanned" → **"Awaiting first scan — protection is unverified until…"**, so an
  unscanned org never reads as safe.
- **`components/posture-hero.tsx`**: shield card on `/orgs/{org}` (ShieldAlert red / Shield
  amber / ShieldCheck teal / unverified gets the **dashed** amber border per the uncertainty
  convention), status dot with a **2.4 s CSS ping** (`status-pulse` keyframes; no pulse on
  "awaiting"), `aria-label="Security posture"`. Renders only when the overview endpoint
  responds (degrades to the old page, never guesses).

**The a11y/perf pass:**

- **Reduced motion now truly disables *all* animation:** global
  `@media (prefers-reduced-motion: reduce)` rule collapses every CSS animation/transition to
  0.01 ms, and the JS-driven motion animations (shell content fade, finding-card panel/drawer
  height) opt out via `useReducedMotion()` (MotionConfig `reducedMotion="user"` only suppresses
  transforms — opacity/height tweens needed the explicit opt-out).
- **Skip link** ("Skip to content" → `#main` on `motion.main`): first tab stop, sr-only until
  focused. Fonts already optimal (self-hosted Geist via next/font); images are inline SVG +
  ICO only — nothing further to optimize (best-practices 100 confirms).

**Validation:** `npm test` **11/11** wording cases (incl. the 4 gate mixes, KEV-overrides-
deprioritized soundness sweep, grammar) · build + lint clean · ruff + format clean ·
`mypy --strict src platform` clean (82 files) · **pytest 446 passed** (no Python changes).
**Live e2e** (re-seeded `c:\tmp\va132` stack: acme = KEV at-risk, safe-org = deprioritized-only,
dyn-org = dynamic-unknown-only, empty-org = unscanned):
- **SSR 16/16 PASS** — each org renders its exact headline/detail; dyn-org and empty-org HTML
  contain zero "Protected —"; dashed frame on unverified; pulse absent on awaiting; skip link +
  `#main` in the shell.
- **Browser 8/8 PASS** (headless Edge, puppeteer-core) — pulse animates 2.4 s/infinite by
  default; **`prefers-reduced-motion: reduce` verified**: pulse + chevron collapse to ~0 ms and
  the card expand completes within 2 frames (instant), while normal motion still tweens; skip
  link is the first tab stop, becomes visible on focus, jumps to `#main`. Hero screenshots
  (at-risk/protected/unverified) eyeballed.
- **Lighthouse (desktop preset, documented):** home **100/100**, repo **99/100**, scan (50
  findings) **100/100**, analytics **98/100** (perf/a11y; best-practices 100 across) — gate
  ≥90/≥95 met everywhere. Mobile emulation documented honestly: analytics 65, scan 76 (recharts
  hydration, a11y 100 both) — desktop is the product form factor (13.4 precedent); mobile perf
  stays on the backlog.

**Deploy:** pushed to main (Vercel auto-deploys `dashboard/`); tagged **`dashboard-v1.0`**.

**Open questions:** none blocking. M13 complete — the product looks fundable. Next: M14 —
Task 14.1 `vulnadvisor login` (device flow).

---

## Task 13.4 — Analytics page (charts)  (2026-06-11)

**Status:** complete, Validation Gate passing. **New npm dep (pre-listed in task.md, approved at
task start): `recharts@3.8.0`** via `npx shadcn add chart` (adds `components/ui/chart.tsx`, themed
from the 13.1 `--chart-*`/state tokens).

**`/orgs/{org}/analytics`** (new route; sidebar "Analytics" enabled — "Soon" badge gone — and the
⌘K palette gained "{org} analytics"):

- **KPI strip** (server-rendered, SSR-assertable): Protected repos (`repo_count − repos_at_risk`
  of total, teal), Actionable findings (red when >0, teal at 0), KEV count (same semantics),
  Median fix time (overall median from `/analytics/resolution`, "—" when nothing resolved yet).
- **Severity donut** (findings by band, center = total) · **Reachability split donut** — *our*
  chart: center shows **"N% deprioritized"** in teal; dynamic-unknown renders as a lighter amber
  (uncertainty stays amber-family, never safe-looking) · **90-day stacked area trend**
  (actionable over deprioritized; reachable-called drawn as a **line**, never stacked — it's a
  subset of actionable, stacking would double-count) · **top-risky-packages horizontal bars**
  (0–100 priority axis labeled, bars colored by band, names mono).
- **Click-through:** small additive platform change — `PackageRisk.top_scan_id` (the scan holding
  the package's top-priority finding, from the existing rank-1 window query; no migration).
  Clicking a bar routes to that scan's ranked finding list; an **sr-only link list** provides the
  same path for keyboard/screen-reader users. Every chart carries `role="img"` + an `aria-label`
  that includes the actual values (so even the SSR HTML carries the numbers — recharts pie
  sectors only paint after hydration).
- Chart animations **disabled** (`isAnimationActive={false}`): deterministic rendering, no
  half-drawn donuts at screenshot/LCP time, and nothing to suppress in the 13.5 reduced-motion
  pass. Empty states teach (`vulnadvisor scan . --upload`) per chart; analytics `loading.tsx`
  skeleton mirrors the layout.
- **Repo page trend migrated** to the same kit (`TrendAreaChart` shared component);
  `components/trend-chart.tsx` (hand-rolled SVG) **deleted**. SSR text-split lesson from 13.2
  re-applied (" of N" as a single template string).

**Validation:** dashboard `npm run build` + `npm run lint` clean · ruff + format clean ·
`mypy --strict src platform` clean (82 files) · **pytest 446 passed** (packages test now also
asserts `top_scan_id`). **Live e2e** (seeded SQLite via temp scripts in `c:\tmp\va134`, nothing
added to the repo: acme org = 3 repos / 3 scans across 3 days with hand-computable analytics
[protected 1 of 3 · actionable 3 · KEV 2 · median fix 5 days · tier split 25% deprioritized ·
packages jinja2 95/flask 75/requests 50/yaml 20] + an empty org; uvicorn + `next start`):
- **SSR 21/21 PASS** — KPI numbers in server HTML; chart aria-labels carry the exact values;
  sr-only click-through link present; empty org teaches on all four charts with 0-of-0 KPIs and
  no chart SVG; repo page on recharts with the old "peak N" SVG gone; unknown org → not-found.
- **Browser 21/21 PASS** (headless Edge, puppeteer-core) — donut sector counts + center labels
  ("4 findings", "25% deprioritized"), legends, 2 stacked areas + reachable-called line + 3 dated
  x-ticks + numeric y-axis, 4 band-colored bars, **bar click → lands on the scan and the jinja2
  CVE-2019-10906 card renders**, sidebar nav + palette navigation. Screenshots eyeballed
  (seeded + empty): deck-ready.
- **Lighthouse (documented):** desktop preset **98** perf (FCP 0.3s · LCP 1.1s · TBT 40ms ·
  CLS 0.006) — gate ≥85 met on the product's form factor. Mobile emulation (slow-4G + 4× CPU
  throttle) scores 58, dominated by recharts hydration — flagged as input for the 13.5 a11y/perf
  pass.

**Open questions:** none blocking. Next: 13.5 — security-posture hero + a11y/perf gate
(Lighthouse ≥90 perf / ≥95 a11y on home, repo, scan, analytics; `prefers-reduced-motion`).

---

## Task 13.3 — Analytics API (aggregates) + data retention  (2026-06-11)

**Status:** complete, Validation Gate passing. No new dependencies, **no schema change / no
migration** — everything is aggregates over the existing tables, and compaction only empties
`findings.payload`.

Four read endpoints under `/v1/orgs/{org}/analytics/` (new `routers/analytics.py`; tenant
isolation identical to 11.4 — non-members get 404 via `require_org`):

- **`/overview`** — current posture over **each repo's latest scan** (any ref; window-function
  `row_number()` keyset order `(created_at, id)`, never double-counting history): totals by band
  (stable shape, all 5 bands) and by tier (all 4 tiers), actionable/deprioritized/reachable-called
  (via the sound `summarize_tiers` from 11.4 — only `not-imported` deprioritizes), **KEV count**
  (SQL JSON path `payload['in_kev']` — works on SQLite JSON and PG JSONB), and **repos at risk**
  (distinct repos whose latest scan has any non-`not-imported` finding), plus `repo_count`/
  `total_findings` for the 13.4 KPI strip.
- **`/trend?window=30d|90d`** — org-wide per-day stacked counts: each day's latest scan per repo,
  summed across repos (mirrors the 11.4 repo-trend semantics; one grouped query, no N+1). Days
  with scans but zero findings still emit a zero point. `parse_window` moved to a shared
  `analytics.py` helper module (read.py's private copy deleted — same 400 semantics, tested).
- **`/packages?limit=`** — top risky packages over latest scans: `max(priority)`, finding count,
  distinct-repo count, ordered max-priority → count → name. Each package's **band is read from
  its top-priority finding row** (second window query) rather than re-deriving the engine's
  priority→band thresholds — the engine stays the authority.
- **`/resolution`** — median days first-seen→fixed, overall + per band. The platform stores no
  finding lifecycle, so it's **reconstructed from consecutive scan diffs** per (repo, ref)
  timeline: pure `resolution_episodes()` in `analytics.py` (a finding's episode starts at the
  first scan containing it, ends at the first later scan without it; still-present = unresolved,
  contributes nothing; disappear-and-reappear = one episode per contiguous run; band recorded at
  first sight). Median via `statistics.median`; bands with no episodes report `null`.

**Retention guard** (new `compact.py`, free-tier Neon): `python -m vulnadvisor_platform.compact
--days N [--apply]` — empties `findings.payload` for scans that are **both** older than N days
**and** superseded on their (repo, ref) partition (null refs partition together, so local scans
keep their own latest). Denormalized columns always survive → every analytics number stays
intact; latest-per-ref always keeps full payloads → the dashboard's current view and the KEV
count (payload-dependent, latest-only) are never degraded. **Dry-run by default** (`--apply` to
prune); idempotent (already-pruned payloads — `payload::text = '{}'`, portable to both backends —
drop out of the plan, so a cron re-run is a no-op); `plan_compaction`/`apply_compaction` share the
exact same selection, so dry-run reports precisely what live deletes (tested). Runs in the
deployed container as-is (Dockerfile already puts `platform/` on the path); locally needs
`PYTHONPATH=platform`.

**Validation:** ruff + format clean · `mypy --strict src platform` clean (82 files) · **pytest 446
passed** (+15: hand-computed overview incl. superseded-scan exclusion + empty org; org trend incl.
same-day-superseded scan + bad window 400; packages ranking/band/repo-count/limit + superseded
exclusion; resolution medians per band incl. per-ref independence + unresolved exclusion + pure
reappearance/unresolved episode tests; compact dry-run==live + latest-per-ref survives any cutoff
+ idempotent re-run + CLI dry-run-by-default output + parser validation). **Live Postgres smoke**
(docker compose, `alembic upgrade head` + `alembic check` clean — no drift): all four endpoints +
plan/apply/replan compaction verified against PG (the JSONB `in_kev` path, `payload::text` cast,
and window functions behave identically to SQLite). Dashboard untouched (charts are 13.4).

**Open questions:** none blocking. Next: 13.4 — analytics page (charts; new npm dep `recharts`
via shadcn charts to approve at task start).

---

## Task 13.2 — Interactive finding cards v2 (the attack story, uncut)  (2026-06-11)

**Status:** complete, Validation Gate passing. No new dependencies.

Progressive disclosure: rebuilt `dashboard/components/finding-card.tsx` as a client component
(`"use client"`); both consumers (scan page, diff page) unchanged — same `<FindingCard finding>`
signature, optional `defaultOpen`.

- **Collapsed row:** display_title (`CVE-… · pkg version`), one-line verdict (CSS `truncate`
  only — the full text is always in the DOM), band/tier/KEV badges, rotating chevron. Rows are
  `<button aria-expanded aria-controls>`; Enter **and** Space toggle natively;
  `focus-visible:ring-inset` keeps the ring visible inside the Card's `overflow-hidden`.
- **Expanded panel — always rendered, never clamped:** the panel stays in the DOM (SSR carries
  the full story; the previous gates' SSR assertions keep working). Collapse = motion height→0
  (`initial={false}` so SSR emits inline `height:0`) + **`inert`**, so hidden content is out of
  the tab order and the a11y tree — Tab from a collapsed row lands on the next row, never inside.
  Layout: **Card A full-width** (story gets the width it needs), Cards B (risk facts: priority,
  tier, EPSS, KEV — KEV line turns `text-risk` when listed, CVSS base) and C (fix command +
  **copy button** with `aria-live` "Copied" feedback + "Fixed in <version>") in a 2-col grid.
- **Evidence drawer** (second-level disclosure, own `aria-expanded`): call paths parsed from the
  engine's rendered `a -> b -> vuln (file:line)` format (model/callpath.py) into **step chains**
  — mono chips joined by `→`, final vulnerable step styled `text-risk` ring, location suffix —
  plus import sites as `file:line` chips and the reachability reason. **Defaults open when a
  concrete call path exists** (the evidence is the demo), closed otherwise.
- Tier/band filter bar untouched — it already persists via URL params (12.x). Two SSR niceties:
  JSX `{a}:{b}` text pairs became single template strings so React doesn't split them with
  `<!-- -->` comment nodes (cleaner DOM text + robust assertions).

**Validation:** dashboard `npm run build` + `npm run lint` clean · ruff + format clean ·
`mypy --strict src` clean (58 files) · **pytest 431 passed** (no Python changes). **Live e2e**
(seeded SQLite via temp scripts in `c:\tmp\va132` — nothing added to the repo: acme/webapp scan
with **50 findings**, marquee = jinja2 CVE-2019-10906, KEV, **1,593-char story**, 2 call paths,
2 import sites; uvicorn + `next start`):
- **SSR 23/23 PASS** — full story present untruncated; 50 cards in DOM; 50 collapsed rows +
  37 closed drawers (+1 org-switcher) `aria-expanded=false`; 13 call-path drawers SSR'd open;
  inline `height:0` on collapsed panels; copy button + exact fix command; step-chain spans,
  arrows, `(app/web.py:42)` location, reflective `getattr(jinja2, ...)` chain, import chips;
  tier/band filter links carry URL params.
- **Browser 18/18 PASS** (headless Edge, puppeteer-core): keyboard-only walkthrough — Tab →
  first row (collapsed), Tab skips the inert panel, Enter expands, Tab → copy button, Enter →
  **clipboard holds exactly** `uv pip install "jinja2>=2.11.3"`, "Copied" announced; story
  ≥1,200 chars, not CSS-clamped, fully laid out; drawer toggle keyboard-reachable + open by
  default; Space collapses; 50 rows render compact (tallest collapsed row < 90 px); focus ring visible.
  Screenshots (collapsed list + expanded card) eyeballed: 5-s scan collapsed, 60-s read expanded.

**Open questions:** none blocking. Next: 13.3 — analytics API (aggregates) + data retention.

---

## Task 13.1 — "Aegis" design tokens + app shell  (2026-06-11)

**Status:** complete, Validation Gate passing. First M13 task.

The visual language of "being protected" — SOC console, not crypto landing page:

- **New npm deps (the ones pre-listed in task.md for 13.1):** shadcn/ui via
  `npx shadcn init -y -b radix -p nova` (the `radix-nova` preset = Radix primitives + Lucide +
  Geist — exactly the planned stack; pulls `radix-ui`, `cmdk`, `class-variance-authority`,
  `clsx`, `tailwind-merge`, `tw-animate-css`, `lucide-react`), plus `geist` and `motion`.
  Copied-in components: button, badge, card, skeleton, command, dialog, dropdown-menu, input,
  input-group, separator, textarea (`components/ui/`).
- **Aegis tokens** (`globals.css`, Tailwind v4 `:root` vars + `@theme inline`): base deepened to
  `#0a0e14` with the `#0d1117` surface family; **one guarded accent** `--safe: #2dd4bf` (teal)
  reserved strictly for protected/safe states; `--risk`/`--risk-strong` red strictly for
  confirmed risk; `--warn` amber for uncertainty (dynamic-unknown badges get a **dashed**
  border so uncertainty reads as unresolved); `--info`/`--link` blue for low band + wayfinding.
  Geist Sans/Mono via the `geist` package (next/font/local under the hood — self-hosted, zero
  network, matches the privacy posture; `--font-sans`/`--font-mono` wired in `@theme`).
  Motion presets 150–200 ms (`lib/motion.ts`) under `MotionConfig reducedMotion="user"`.
  Radar-grid texture: pure-CSS `@utility radar-grid` (neutral foreground-4% grid lines — not
  teal — swept by a radial mask), rendered as a fixed element behind the shell.
- **App shell:** left sidebar (brand, **org switcher** DropdownMenu, nav: Repos / Analytics
  ("Soon", disabled until 13.4) / Settings, "Local-first · no telemetry" trust footer), top bar
  with **⌘K command palette** (shadcn Command in a CommandDialog: jump to any org, repo, recent
  scan, or page; Ctrl/⌘K listener + Search button), `motion.main` 180 ms content fade.
- **Streaming-safe architecture (the bug found live):** an `await` in the root layout made
  Next flush the shell before pages resolved, turning `notFound()` responses into early-flush
  200s. Fix: the root layout is **synchronous**; the data-dependent shell parts stream in via
  `Suspense` slots (`shell-slots.tsx`: async `ShellSidebar`/`ShellPalette` over a React
  `cache()`-deduped `getShellData()` in `lib/shell-data.ts` — orgs → repos → 3 recent scans
  per repo, bounded, **never throws**: API-down degrades to the minimal shell so the page's own
  branded error boundary stays in charge). Palette open-state is a client context
  (`palette-context.tsx`) shared by the top-bar trigger and the streamed dialog. Second live
  find: this registry's `CommandDialog` does **not** wrap children in a `<Command>` root —
  without it cmdk crashes on open (`subscribe` of undefined); wrapped explicitly.
- **Migration:** hand-rolled `components/ui.tsx` + `nav.tsx` **deleted**; `.card`/`.btn`/`.pill`/
  `.muted`/`.link` CSS classes gone (kept `mono` + `link` as design-system `@utility`s). All
  pages/loading/not-found/error screens now compose shadcn primitives + `components/blocks.tsx`
  (PageHeader/Stat/EmptyState/FullPageNotice). `lib/format.ts` band/tier classes are
  **token-based** (zero hardcoded hex anywhere outside `components/ui/`); trend chart uses
  `var(--risk)`/`var(--safe)`/`var(--risk-strong)`. Favicon + `icon.svg` regenerated teal-on-
  `#0a0e14`.

**Palette audit:** teal appears only on: `not-imported` tier badge, diff "Fixed" heading,
deprioritized trend line, the privacy "opt-in" badge, the local-first shield, and the brand
mark. dynamic-unknown is amber (dashed), never purple/safe-looking. KEV/critical/
imported-and-called are red; high orange; medium amber; low blue.

**Validation:** dashboard `npm run build` + `npm run lint` clean · ruff + format clean ·
`mypy --strict src` clean (58 files) · **pytest 431 passed** (no Python changes). **Live e2e**
(seeded SQLite: acme org with webapp [real-sha 1-finding scan + null-sha 0-finding scan] and
zero-scans repos, empty-org; uvicorn + `next start`): **22/22 SSR assertions PASS** — every
route renders inside the new shell (home, org, empty org, repo, 0-scan repo, scan, empty scan,
diff, settings, api-keys), shell markers on all, branded 404s, zero "0000000", zero legacy
hex/classes in HTML, all four security headers + no `unsafe-eval` (12.3 regression guard).
**⌘K browser e2e (headless Edge via puppeteer-core, nothing added to the repo): 4/4 PASS** —
Ctrl+K opens, typing "webapp" + Enter lands on `/orgs/acme/repos/webapp`, reopening and typing
the sha lands on the seeded scan with the finding rendered. Screenshots eyeballed: sidebar/
switcher/palette/3-card finding all correct. Note (pre-existing, verified against the deployed
v0.2): unknown org/scan return streamed not-found UI with HTTP 200 (loading.tsx streaming);
only unmatched URLs are status-404 — unchanged by this task.

**Open questions:** none blocking. Next: 13.2 — interactive finding cards v2 (progressive
disclosure, evidence drawer, copy button).

---

## Task 12.3 — Dashboard hardening + error/loading polish  (2026-06-11)

**Status:** complete, Validation Gate passing. Closes M12 → **dashboard v0.2** (tag `dashboard-v0.2`).

The "feels secure" floor — correct headers, no raw error screens, no layout jank:

- **Security headers** (`next.config.ts` `headers()`, applied to `/:path*` so every route + the 404
  carries them): `Content-Security-Policy` (default/script/style/img/font/connect `'self'`-based,
  `object-src 'none'`, `frame-ancestors 'none'`, `base-uri`/`form-action 'self'`; **no
  `unsafe-eval`** in production — dev mode conditionally adds it + `ws:` for HMR only),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy: camera=(), microphone=(), geolocation=()`, plus legacy
  `X-Frame-Options: DENY`. (`script-src` keeps `'unsafe-inline'` — Next bootstraps hydration with
  inline scripts; a nonce-based CSP needs middleware and is out of scope per the gate.)
- **Branded error/loading/not-found:** new `Skeleton` + `FullPageNotice` primitives in
  `components/ui.tsx`. Per-segment skeleton `loading.tsx` (never spinners — cold starts look
  intentional) for home, org, repo, scan, diff, settings, api-keys, each mirroring its page's
  layout, with `role="status"` + sr-only text. `not-found.tsx`: branded root (also catches all
  unmatched URLs) + contextual org/repo/scan variants ("…or you don't have access"). Root
  `error.tsx` (client boundary, Next 16 `unstable_retry`) never renders the raw error — message is
  "API may be waking up", digest shown for support correlation only.
- **Identity:** branded `favicon.ico` (generated 32×32 PNG-in-ICO, dark `#0d1117` + green diamond,
  replaces the create-next-app default) + `app/icon.svg`; root metadata: title template
  (`%s · VulnAdvisor`), description, OpenGraph (site_name/title/description/type); per-page
  `<title>` on org (`acme`), repo (`acme/webapp`), scan (`Scan <id8>`), diff, settings, api-keys.
  (Note: a root layout's `title.template` does not apply to `page.tsx` in the same segment —
  documented Next behavior — so home uses the root default title.)
- **Dead-state audit fixes:** repo with 0 scans now teaches (`vulnadvisor scan . --upload`) instead
  of "No scans for this selection" (which is kept for a ref-filter with no matches); scan with 0
  findings says "This scan reported no findings." when unfiltered (filter message only when a
  filter is active); org with 0 repos teaches App-install/upload; org repo rows show "no scans yet"
  instead of "last —"; `degraded_sources` null-guarded.

**Validation:** dashboard `npm run build` + `npm run lint` clean · ruff + format clean ·
`mypy --strict src` clean (58 files) · **pytest 431 passed** (no Python changes). **Live e2e**
(seeded SQLite: acme org with `zero-scans` repo + `webapp` repo holding a null-sha 0-finding scan
and a real-sha 1-finding scan; `empty-org` with no repos; uvicorn + `next start`):
- `curl -I` on `/`, deep routes, and the 404 shows **all four headers**; CSP has **no
  `unsafe-eval`** (asserted).
- SSR assertions all PASS: home lists both orgs · empty org teaches · 0-scan repo teaches ·
  0-finding scan reports honestly + "local scan" badge, zero "0000000" · 1-finding scan renders
  the 3 cards (`CVE-2019-10906`) · filtered-empty message distinct · diff/settings/api-keys render ·
  unmatched URL → branded 404 (HTTP 404) · unknown org/repo/scan → contextual not-found screens.
- **API-down probe:** page streams skeleton + opaque digest, **no ECONNREFUSED/stack text in the
  HTML**; the branded error boundary takes over client-side (verified via the streamed `$RX`
  digest trigger — boundary rendering itself needs a JS browser).
- Favicon served `image/x-icon` with valid ICO signature; `icon.svg` + OG tags verified in SSR HTML.

**Deploy:** Vercel deploys `dashboard/` from main via Git integration (docs/deploy.md) — pushed;
spot-check `https://vulnadvisor.vercel.app` headers/404 after the deploy lands. Tagged
`dashboard-v0.2`.

**Open questions:** none blocking. M12 complete. Next: M13 — Task 13.1 design tokens + app shell
(new npm deps to approve at task start: shadcn/ui + Radix peers, lucide-react, motion, geist).

---

## Task 12.2 — Scan metadata honesty (kill "0000000 main")  (2026-06-11)

**Status:** complete, Validation Gate passing.

No placeholder data rendered as fact, anywhere:

- **CLI — new `output/gitmeta.py`** (stdlib-only): `detect_scan_metadata(path)` returns
  `ScanMetadata(commit_sha, ref)` where either field is **null when honestly unknown — never
  forty zeros**. Precedence: `GITHUB_SHA`/`GITHUB_REF` (CI; validated — a malformed or all-zero
  env SHA is rejected) → `git rev-parse HEAD` / `git symbolic-ref --short HEAD` run defensively
  in the scanned directory (git missing, non-repo, detached HEAD, timeout → null, never a crash).
  `upload_report` defaults `commit_sha`/`ref` to `None` and sends JSON null; `_upload_report` in
  the CLI threads the detected metadata through (`os.environ` placeholder logic deleted).
- **Platform:** `Scan.commit_sha`/`Scan.ref` are now **nullable** (model + `ScanListItem`/
  `ScanDetailOut`/`IngestRequest`/`ScanUploadRequest` schemas; the old `"0"*40` /
  `"refs/heads/main"` body defaults are gone). New Alembic migration `7c41aa90d2e1` (alter to
  nullable; downgrade backfills the old placeholders first). Ingest **normalizes** pre-12.2
  placeholder values on the way in (`_clean_commit_sha`: all-zero/empty → null; `_clean_ref`:
  blank → null), and the diff baseline compares null refs as `IS NULL`, so local scans diff
  against the previous local scan.
- **Dashboard:** `shortSha()`/`shortRef()` now accept null and **guard placeholders** (an
  all-zero SHA renders as if null); `ScanListItem`/`ScanDetail` types nullable. Repo scan rows
  and the scan page header render a neutral gray **"local scan"** badge when no commit is
  recorded; the ref-filter bar skips null refs; the scan subtitle drops the missing segments.

**Validation:** ruff + format clean · `mypy --strict src` clean (58 files) · **pytest 431 passed**
(+17: 12 gitmeta tests — real temp git repo incl. detached HEAD + file-path parent, non-repo,
git-absent, CI-env precedence, zero/malformed SHA rejection; upload null/explicit payloads; CLI
`--upload` sends null metadata from a non-repo dir; platform null-stored + zeros-normalized +
null-ref diff + real-sha-kept + read-API-null tests). **Migration applied to live Postgres**
(docker compose): `alembic upgrade head` clean, `alembic check` no drift, columns verified
nullable. Dashboard `build`/`lint` clean. **Live SSR e2e:** seeded SQLite (null-sha + real-sha
scans), uvicorn + `next start` → repo page and scan page show **"local scan"** with zero
"0000000" anywhere; the real-sha scan shows `aaaaaaa`. **Live CLI e2e:** `vulnadvisor scan
examples/quickstart --upload` from this checkout uploaded with the actual HEAD
(`ce621d5d…`, ref `main`) confirmed via the read API.

**Open questions:** none blocking. Next: 12.3 — dashboard hardening + error/loading polish
(security headers, branded error/loading states, favicon/metadata) → tag `dashboard-v0.2`.

---

## Task 12.1 — Canonical finding identity (CVE-first display)  (2026-06-10)

**Status:** complete, Validation Gate passing. First M12 task.

One display rule on every surface — never again `django==4.2.29PYSEC-2026-52`:

- **New `model/display.py`** (pure, exported from `vulnadvisor.model`): `select_display_id(id,
  aliases)` picks the **lowest-numbered CVE** (by year, then number — numeric, not lexical) from
  the advisory's id + aliases, else the first GHSA id, else the first PYSEC id, else the raw id.
  Defensive: non-string/malformed alias entries are skipped, never raised on. `display_id(advisory)`
  wraps it; `display_title(finding)` formats the canonical `"CVE-2020-28493 · jinja2 2.11.2"`
  (middle-dot separator, `(unpinned)` when no version, **no `==` in display contexts** — `==` stays
  only in fix commands).
- **Adopted in:** terminal 3-card header (`cli/render.py`); JSON report — additive
  `advisory.display_id`, `schema_version` bumped to **1.1** (documented as additive; 1.0 consumers
  can read 1.1); SARIF — human-readable `shortDescription` is now `"<display_id>: <summary>"` while
  **`ruleId` stays the stable raw advisory id** (asserted); platform PR comment — CVE-first
  advisory cell (prefers the report's own `display_id`, computes it for pre-1.1 payloads) and the
  package cell dropped `==`; platform ingest — `SUPPORTED_SCHEMA_VERSIONS = {"1.0", "1.1"}`;
  dashboard — `lib/format.ts` mirrors the exact selection rule (`displayId`/`displayTitle`,
  prefers `advisory.display_id` from 1.1 payloads), `finding-card.tsx` header is now
  `CVE-… · pkg version`, and the diff page's fixed-list rows match.
- No schema/DB change needed on the platform (payloads stored verbatim); no new dependencies.

**Validation:** ruff + format clean · `mypy --strict src` clean (57 files) · **pytest 414 passed**
(+24: 22 table-driven display tests incl. multiple-CVE ordering and malformed-alias cases; platform
ingest accepts **both 1.0 and 1.1** explicitly; PR-comment CVE-first + no-`==` + display_id-preferred
tests). SARIF still validates against the vendored 2.1.0 schema. Terminal/JSON snapshots regenerated
(`CVE-2019-10906 · jinja2 2.10` header; `display_id` additive next to the unchanged raw `id`).
Dashboard `npm run build` + `npm run lint` clean.

**Open questions:** none blocking. Next: 12.2 — scan metadata honesty (kill "0000000 main").

---

## CLI → dashboard upload flow  (2026-06-10)

**Status:** complete, full gate green; live HTTP e2e verified.

End-to-end "scan locally, see it in the dashboard" path (source never leaves the machine — only the
JSON report is sent):

- **Backend:** new `POST /v1/scans` ([routers/ingest.py]) — org comes from the API key (Bearer),
  repo from the body; refactored the store logic into a shared `_store_scan` used by both the
  path-scoped ingest and this key-scoped upload. New `ScanUploadRequest` schema (repo required,
  commit/ref defaulted). Added `api-keys` path aliases for the key endpoints
  (`GET/POST/DELETE /v1/orgs/{org}/api-keys`) alongside the existing `/keys` (out of OpenAPI schema).
- **Dashboard:** new `/orgs/[org]/settings/api-keys` page — a client component generates a key
  (POST through the same-origin `/api` proxy with `credentials: include`), shows the secret **once**
  with a copy button, lists keys, and can revoke. Settings page now links to it.
- **CLI:** `scan --upload` with `--api-key` (env `VULNADVISOR_API_KEY`), `--api-url`
  (env `API_URL`), `--repo` (default: scanned dir name), and `--dashboard-url`
  (env `VULNADVISOR_DASHBOARD_URL`, prints a link). New stdlib-only `output/upload.py`
  (`urllib`, no new wheel dependency; defensive — typed `UploadError`, never leaks tracebacks).
  Uploads the **full** report (not the `--top` display subset); reads `GITHUB_SHA`/`GITHUB_REF` in CI.

**Validation:** ruff + format clean · `mypy --strict` clean (77 files) · pytest **390 passed**
(+13: `/v1/scans` upload, api-keys alias, upload unit tests, CLI `--upload` integration). Dashboard
`build`/`lint` clean (new route compiles). **Live HTTP e2e**: seeded SQLite org+key, booted uvicorn,
ran the real `upload_report` over the wire → 201 with scan id + diff; DB showed the repo, scan, and
both findings stored.

---

## M11 closed — platform tier feature-complete; 11.8 skipped  (2026-06-10)

**Status:** M11 closed out at the maintainer's direction ("validated — skip 11.8, close out M11").

**11.8 (background processing) — SKIPPED, by its own conditional gate.** The task is explicitly
*"skip unless profiling proves it."* Ingest is a bounded parse + bulk insert; the webhook path
delegates the actual reachability analysis to the customer's CI and only persists the uploaded
report. No measured blocking exists, so no Redis/RQ/queue is introduced — this keeps the free-host
footprint minimal. Revisit only if real load profiling shows the ingest/webhook path blocking.

**M11 summary (all done & validated):** 11.1 design (approved) · 11.2 backend skeleton + 8-table
data model + Alembic · 11.3 ingest + scan-to-scan diff · 11.4 read API + trends (tenant-isolated,
keyset pagination) · 11.5 auth (GitHub OAuth sessions + hashed org-scoped API keys) · 11.6 GitHub
App (HMAC webhook + installation sync + 3-card PR comment, live RS256 installation token) · 11.7
Next.js read-only dashboard (dark `#0d1117`). The platform is **bring-your-own-analysis by default**
(source never leaves customer infra), **free-hostable** (Vercel + Neon/Supabase + Fly.io/Render),
and never bloats the published CLI wheel (all server deps live in the non-shipping `platform`
dependency group). Final gate green: ruff/mypy clean, **pytest 374 passed**; dashboard `build`/`lint`
clean + live SSR render verified.

**Next:** no M11 work remains. Outstanding maintainer-only actions from M10 still stand (launch posts
to r/Python + HN — drafts in `docs/reddit-post.md`, `docs/hn-post.md`). Otherwise awaiting direction
(deploy the platform to free infra, or new milestone).

---

## Task 11.7 — Next.js dashboard (read-only UI)  (2026-06-10)

**Status:** complete, Validation Gate passing.

**Environment:** Node was not installed; installed **Node v24.16.0** (winget, user scope) to build and
validate. Scaffolded with `create-next-app` → **Next 16.2.9 + React 19 + Tailwind v4 + TypeScript**,
App Router, ESLint. Lives in `dashboard/` (a separate Vercel-deployable; Python tooling never touches
it; `node_modules`/`.next` gitignored).

**Built** (dark `#0d1117`, GitHub-dark palette; read-only, no business logic in the frontend):
- `lib/api.ts` — server-side typed fetch client; forwards the session cookie to the API (shared host
  in dev) and supports a `DASHBOARD_API_TOKEN` (org-scoped key) for login-less local/preview render;
  `apiGetOrNull` maps 401/404 to null. `lib/types.ts` mirrors the API; `lib/format.ts` has band/tier
  colors + labels.
- Pages: **Home** (`/`, orgs or GitHub sign-in), **Org** (`/orgs/{org}`, repos + counts), **Repo**
  (`/orgs/{org}/repos/{repo}`, 90-day trend chart + branch picker + scans), **Scan**
  (`/scans/{scan}`, the **three cards** per finding — Attack story / Risk / Action with tier,
  call-path evidence, fix; tier/band filters), **Diff** (`/scans/{scan}/diff/{to}`, introduced/fixed),
  **Settings** (`/orgs/{org}/settings`, API keys read-only + App install + cloud-scan status).
- Components: `nav`, `ui` (Card/Badge/Stat/…), `trend-chart` (dependency-free SVG, a11y `role="img"`
  + legend), `finding-card` (the 3 cards).
- Auth model: read pages accept the platform's **session cookie OR Bearer key** (the 11.5 dual auth).

**Bug found + fixed via the live run:** `app/scans/[scan]` and `app/scans/[from]` were sibling
dynamic segments with different slug names — `next build` passed but **runtime 500'd** ("cannot use
different slug names for the same dynamic path"). Nested the diff route under `[scan]` as
`/scans/[scan]/diff/[to]`.

**Validation:** `npm run build` (TypeScript typecheck + production build) clean; `npm run lint`
(ESLint) clean. **End-to-end render verified live**: seeded a SQLite DB (org/repo/scan/finding), ran
the API (uvicorn) + `next start`, and confirmed the SSR HTML contains the seeded org ("Acme Inc"),
the repo trend ("90-day trend"/"Actionable"), and the scan's 3-card finding (`jinja2`,
`IMPORTED-AND-CALLED`, "Attack story", call path `yaml.load`, "Fix now"). Python gate unaffected
(ruff/mypy clean, pytest **374 passed**). Full visual a11y/contrast is a documented manual check
(needs a browser); semantic HTML + high-contrast dark palette + chart `aria-label` are in place.

**Next:** 11.8 — (conditional) background processing — *skip unless profiling proves the ingest/webhook
path blocks*. Otherwise M11 build is essentially complete.

---

## Task 11.6 follow-up — live GitHub App installation token (RS256 JWT)  (2026-06-10)

**Status:** complete, Validation Gate passing. Closes the one deferred piece from 11.6.

Added **PyJWT==2.13.0 + cryptography==48.0.1** to the `platform` dependency group (approved by the
maintainer; still never ships in the published CLI wheel). Implemented
`GitHubApp._installation_token`: sign a short-lived **RS256 JWT** (iss = App id, backdated `iat`,
≤10-min `exp`) with the App private key via `jwt.encode`, then exchange it at
`POST /app/installations/{id}/access_tokens` for the installation token. Clear `GitHubAppError` when
credentials are missing, the installation id is absent, or the private key is malformed. The webhook
PR-comment path is now fully live (given configured App credentials).

**Validation:** ruff + format clean · `mypy --strict` clean (76 files) · pytest **374 passed** (3 new):
`_app_jwt` produces a token that **verifies against the RSA public key** (RS256, correct iss/exp); the
token exchange posts to the right URL with a valid Bearer JWT and returns the installation token (via
a generated RSA keypair + mocked transport); and missing credentials raise `GitHubAppError`.

---

## Task 11.6 — GitHub App: webhook + installation sync + PR diff comment  (2026-06-10)

**Status:** complete, Validation Gate passing. **No new dependencies** (stdlib `hmac` + httpx).

**What was built**
- **`POST /v1/github/webhook`** (`routers/github.py`): HMAC-SHA256 verified against
  `GITHUB_WEBHOOK_SECRET` (`X-Hub-Signature-256`, constant-time compare, **fail-closed** on missing
  secret/header) before any work; bad signature -> 401. Dispatches by `X-GitHub-Event`.
- **Installation sync**: `installation` / `installation_repositories` upsert the Org (by
  `github_org_id`/slug), the Installation, and Repositories (and remove on `repositories_removed`).
  Fully defensive payload parsing.
- **PR comment**: `pull_request` (opened/synchronize/reopened) finds the head scan (by head sha, then
  head ref) and the base scan (base ref), diffs their findings by `(package, advisory_id)`, and posts
  a **reachability-triage comment** of the *introduced* findings (with a hidden marker so it updates
  in place). If no report exists yet, posts a "waiting for a scan report" note so opening a PR always
  yields a comment. `pr_comment.render_pr_comment` is pure; only `not-imported` is treated as safe.
- `GET /v1/github/install` redirects to the App install page. `webhooks.verify_signature` and the
  comment renderer are pure + unit-tested.
- `github_app.py`: the GitHub client is a mockable dependency; `post_or_update_comment` implements the
  find-or-create REST upsert **given** an installation token.

**Deferred (flagged):** minting the installation access token needs a short-lived **RS256 JWT signed
with the App private key** — that requires a crypto dependency (e.g. PyJWT+cryptography) I have not
added. `_installation_token` raises a clear error until the App is provisioned; the entire
webhook -> diff -> comment orchestration is exercised via a faked client, so only the final GitHub
auth handshake is outstanding. Ask me to `uv add` the crypto dep to wire the live path.

**Validation:** ruff + format clean · `mypy --strict` clean (76 files) · pytest **371 passed** (9 new):
bad-signature 401, valid ping 200, installation sync (org/installation/repo upserted), PR opened ->
diff comment surfacing the introduced finding (`requests`) with "1 new reachable finding", pending
comment when no report, unsynced-repo no-op, install redirect, and pure `verify_signature` /
`render_pr_comment` tests.

**Next:** 11.7 — Next.js dashboard (read-only UI over the API).

---

## Task 11.5 — Auth: GitHub OAuth + API keys  (2026-06-10)

**Status:** complete, Validation Gate passing. **No new dependencies** (httpx + stdlib `hmac`).

**What was built**
- **GitHub OAuth login** (`routers/auth.py` + `github_oauth.py`): `GET /v1/auth/github/login`
  (redirects to GitHub with a CSRF `state`, also set as a cookie), `GET /v1/auth/github/callback`
  (verifies state, exchanges the code, **upserts the user by `github_user_id`**, sets the session
  cookie, redirects to the dashboard), `POST /v1/auth/logout`. The GitHub client is a FastAPI
  dependency so tests run with a fake — **no network**.
- **Signed-cookie sessions** (`sessions.py`): cookie value is `"<user_id>.<hmac-sha256>"` signed with
  `SECRET_KEY`, verified with `hmac.compare_digest`. No server-side session store.
- **Dual auth** (`security.py`): `get_current_user` now resolves a **session cookie OR a Bearer API
  key** (session first, key fallback) — so the dashboard uses cookies while CLI keys keep working for
  reads; all prior tests stayed green. Ingest still uses the org-scoped `CurrentApiKey`.
- **API-key management** (`routers/keys.py`): `GET /v1/orgs/{org}/keys` (metadata only — never the
  hash/secret), `POST` (mint; **secret returned exactly once**; owner/admin only via
  `access.require_admin`), `DELETE .../{id}` (revoke, idempotent). New schemas `ApiKeyOut`/
  `ApiKeyCreate`/`ApiKeyCreated`.
- Config: `secret_key`, `github_client_id`/`_secret`/`_redirect_uri`, `dashboard_url` (env-only; dev
  defaults; the dev `secret_key` is clearly marked to override in production).

**Validation:** ruff + format clean · `mypy --strict` clean (72 files) · pytest **362 passed** (8 new).
Auth tests cover the login redirect (+state cookie), the callback creating a user whose **session
cookie then authenticates `/v1/me`**, bad-CSRF-state 400, and logout -> 401. Key tests cover
create-returns-secret-once (and that secret authorizing an ingest), list-omits-hash/secret,
**revoke -> the key is rejected (401)** with `revoked_at` surfaced, non-admin create -> 403, unknown
key -> 404, and cross-org -> 404.

**Next:** 11.6 — GitHub App: HMAC-verified webhook, installation sync, PR comment with the 3-card diff.

---

## Task 11.4 — Read API + trends  (2026-06-10)

**Status:** complete, Validation Gate passing.

**What was built** — the full read surface over stored scans, all strictly org-scoped:

- `access.py`: `require_org`/`require_repo`/`require_scan` — a user only sees data for orgs they're a
  member of; **non-members get 404** (we never leak another tenant's org/repo/scan existence).
- `routers/read.py`: `GET /v1/orgs`, `GET /v1/orgs/{org}` (with repo/member counts),
  `GET /v1/orgs/{org}/repos`, `GET /v1/orgs/{org}/repos/{repo}`,
  `GET /v1/orgs/{org}/repos/{repo}/scans` (**keyset pagination** on `(created_at, id)` with an opaque
  cursor; `?ref`/`?limit`), `GET /v1/scans/{id}`, `GET /v1/scans/{id}/findings`
  (`?tier`/`?band`/`?min_priority`, priority-desc; each finding is the stored `payload` verbatim),
  `GET /v1/scans/{a}/diff/{b}` (introduced/fixed finding objects + unchanged count), and
  `GET /v1/orgs/{org}/repos/{repo}/trend?window=Nd` (per-day actionable/deprioritized/reachable-called
  from each day's latest scan).
- `trends.py`: `summarize_tiers` — **sound categorization**: the only deprioritized tier is
  `not-imported`; everything else (`imported`, `dynamic-unknown`, `imported-and-called`, and any
  `unknown`/older tier) counts as actionable. `reachable_called` = `imported-and-called`. Pure +
  unit-tested.
- Read endpoints authenticate via the existing user resolver (Bearer key -> creating user); OAuth
  session login is still 11.5.

**Validation:** ruff + format clean · `mypy --strict` clean (68 files) · pytest **354 passed** (read
tests cover orgs/repos, pagination across pages with no overlap, scan detail + finding filters, diff,
per-day trend, bad-window 400, and **tenant isolation** — cross-org org/scan reads return 404). Also
**smoke-tested against real Postgres** (compose): ingest + keyset pagination + JSONB payload
round-trip + trend + diff all correct on PG, not just SQLite.

**Next:** 11.5 — Auth: GitHub OAuth (dashboard session) + API key issue/revoke endpoints.

---

## Task 11.3 — Ingest API + diff (the value spine)  (2026-06-10)

**Status:** complete, Validation Gate passing.

**What was built** — `POST /v1/orgs/{org_slug}/repos/{repo_name}/scans`: CI/CLI/runner uploads the
`vulnadvisor scan --format json` report it already produced (never source). The platform validates,
denormalizes findings, and diffs vs the previous scan on the same ref, returning
`{scan_id, summary, diff_summary}`.

- `reports.py` (pure, defensive per CLAUDE.md): `parse_report` validates `schema_version` (only
  `1.0`), requires each finding's `dependency.name`/`advisory.id`/`score.band`/`score.value`, and
  rejects malformed input with a clear `ReportValidationError` (-> HTTP 422) instead of storing
  garbage. The **full finding object is stored verbatim as `payload`** (CLI/platform never diverge);
  denormalized columns are for querying only. `diff_finding_keys` diffs by identity
  `(package, advisory_id)` -> introduced/fixed/unchanged.
- `routers/ingest.py`: org lookup (404 if missing) + **org-scoped API-key check** (403 if the key's
  org != path org); upserts the `Repository` (so CI can publish without a prior GitHub App install);
  finds the previous scan on the ref as the diff baseline *before* inserting; writes the `Scan` +
  `Finding` rows; returns the diff. 201 on success.
- `security.py`: refactored to a shared `_resolve_api_key`; added `get_current_api_key`/`CurrentApiKey`
  (org-scoped ingest auth) alongside the existing user resolver.
- Schemas: `IngestRequest` (`commit_sha`, `ref`, `pr_number?`, `source`, `report`), `DiffSummary`,
  `IngestResponse`.

**Validation:** ruff + format clean · `mypy --strict` clean (65 files) · pytest **343 passed**
(10 new, hermetic on in-memory SQLite). The ingest tests feed **real engine-built reports**
(`build_report` over real `score_match` findings) so they exercise the exact JSON the CLI emits:
persist-and-first-diff (introduced=all), second-scan diff (1 introduced / 1 fixed / 1 unchanged),
per-ref scoping, empty report, and rejections (401 no key, 403 cross-org, 404 unknown org, 422
unsupported/missing schema + malformed finding).

**Next:** 11.4 — Read API + trends (orgs/repos/scans/findings/trend, pagination, strict org-scoping).

---

## Task 11.2 — Platform backend skeleton + data model  (2026-06-10)

**Status:** complete, Validation Gate passing. First M11 task (started on the maintainer's explicit
direction; the "real CLI traction" half of the M11 gate is noted as not-yet-demonstrated).

**What was built** — a new monorepo package `platform/vulnadvisor_platform/`, deliberately separate
from the published CLI so `pip install vulnadvisor` stays at 3 runtime deps (server deps live in a
`platform` dependency group, which never ships in the wheel; `[tool.uv] default-groups` syncs it for
contributors).

- **FastAPI app** (`app.py`): `GET /healthz` -> `{status, version}` (no auth) and `GET /v1/me` ->
  authenticated user + their orgs/roles.
- **SQLAlchemy 2.x async models** (`models.py`) for all 8 design tables — `orgs, users, memberships,
  repositories, api_keys, installations, scans, findings` — with jsonb columns
  (`summary`/`payload`/`degraded_sources` via `JSON().with_variant(JSONB, "postgresql")`, portable to
  SQLite for tests) and the 3 design indexes (`findings(scan_id)`, `findings(package, advisory_id)`,
  `scans(repo_id, created_at)`). Annotated-declarative `UuidPk`/`CreatedAt` shared columns.
- **Async engine/session** (`db.py`, lazy from settings), **config** (`config.py`, env-only via
  pydantic-settings; `DATABASE_URL`), **minimal API-key auth** (`security.py`): SHA-256-hashed,
  revocable Bearer keys resolving the creating user — the production-shaped half OAuth (11.5) builds on.
- **Alembic** (async `env.py`): initial migration **autogenerated against live Postgres** then
  applied; `alembic check` reports no drift.
- **docker-compose.yml** (postgres:16, healthcheck), `.env.example` (un-ignored in `.gitignore`).

**Decisions** (asked the maintainer first): separate `platform/` package + own dep group; Docker
available so the migration gate ran live; minimal API-key Bearer auth now (full OAuth = 11.5). Used
`Annotated[T, Depends(...)]` deps (avoids ruff B008, matches the core's Typer idiom).

**Validation:** ruff + format clean · `mypy --strict` clean (62 files) · pytest **333 passed**
(325 core + 8 new platform, hermetic on in-memory SQLite) · `alembic upgrade head` on a clean
Postgres + `alembic check` clean · all 8 tables confirmed in PG. Published CLI wheel unchanged
(still packages only `src/vulnadvisor`).

**Next:** 11.3 — Ingest API + diff (the value spine).

---

## scan `--top N` flag + release-workflow auth fixes  (2026-06-09)

**Status:** complete, Validation Gate passing.

**`--top N`** (new `scan` option): limits *output* to the N highest-priority findings. Pure display
limit on the already-ranked list (`order_findings`) — **no scoring/ranking change**. Applied to all
three formats (terminal/JSON/SARIF) via `shown = report.findings[:top]`; `--fail-on` still gates over
**every** finding, so a display cap can never weaken the exit-code gate. Validation via Typer
`min=1` (a `--top 0` is a usage error). Default is no limit. 4 new CLI tests (truncation in
JSON + terminal, gate-not-weakened, min validation); pytest 325 passed.

**Release workflow (`release.yml`) auth fixes** while shipping 1.0: the publish job's `checkout`
failed on the **private** repo. Added `token: ${{ secrets.GITHUB_TOKEN }}` (v1.0.1) and, the real
fix, `contents: read` to the job `permissions` block (v1.0.2) — an explicit `permissions:` block had
narrowed the token to `id-token: write` and dropped the default read scope.

**PUBLISHED to PyPI.** After checkout was fixed, the `v1.0.3` run failed with "file already exists"
because `pyproject.toml` still said `1.0.0` (an earlier run had already published `1.0.0`). Bumped
the version to **`1.0.3`** (first release carrying `scan --top` + the workflow fixes), deleted and
re-pushed the `v1.0.3` tag at the bumped commit, and the run published the wheel + sdist. Verified
live: `uvx vulnadvisor --version` -> `vulnadvisor 1.0.3` from PyPI, and `scan --help` shows `--top`.
Tags pushed during the rollout: `v1.0.0` (stale), `v1.0.1`, `v1.0.2`, `v1.0.3` (the published one).

---

## Task 10.5 — Publish to PyPI + go live: reversible prep done; irreversible steps handed off  (2026-06-09)

**Status:** reversible prep complete, Validation Gate passing. **The irreversible publish is
maintainer-gated and NOT done by me** — per task.md ("the maintainer pushes the tag") and the
standing rule on outward-facing/irreversible actions. No tag was pushed and nothing was posted.

**Blocker surfaced (important):** a `v1.0` tag already exists locally **and on the remote**, but it
points to `f555caa` (Task 9.1) — old code that predates `release.yml`. For a `push`-tag event GitHub
uses the workflow file from the tagged commit, which there has no `release.yml`, so it **never
triggered a publish**. Confirmed: PyPI has no `vulnadvisor` project (404), and the GitHub releases/runs
API returns 404 (private repo, unauthenticated). Conclusion: nothing has shipped; the stale `v1.0`
tag must **not** be reused. The runbook releases as **`v1.0.0`** (matches the pyproject version and
the `v*` trigger) so no published ref is force-moved.

**What I built (all reversible, committed):**
- `.github/ISSUE_TEMPLATE/` — `false_negative.yml` (dedicated, highest-priority: a missed reachable
  vuln is release-blocking), `bug_report.yml`, `feature_request.yml`, `config.yml` (routes general
  feedback to Discussions; routes tool-vulnerability reports to the security policy).
- `.github/PULL_REQUEST_TEMPLATE.md` — with a required soundness check for any `callgraph/` /
  `reachability/` change (no new false negatives) plus the gate checklist.
- `SECURITY.md` — private-disclosure flow for vulns **in the tool itself**, and the design
  guarantees (analyzes via `ast`, never executes the target; local-only; no telemetry).
- `docs/RELEASE.md` — the maintainer runbook: one-time PyPI Trusted-Publishing setup
  (`Parthav99/vulnadvisor`, workflow `release.yml`, environment `pypi`), the stale-`v1.0`
  resolution, a reversible pre-flight (gate + clean-venv install + live-benchmark FN check), and the
  exact irreversible tag-push + launch-post steps.
- `CHANGELOG.md` — the 1.0.0 release link retargeted from `v1.0` to `v1.0.0`.

**Verified locally (mirrors `release.yml`):** `uv build` produces `vulnadvisor-1.0.0` sdist + wheel;
installing the wheel in a clean venv and running `vulnadvisor --version` prints `vulnadvisor 1.0.0`.
`pyproject.toml` URLs and `release.yml` (Trusted Publishing on `v*`, `pypi` environment) are correct
as-is. The launch post already leads with the real live numbers (paperless 37% / BookWyrm 10% /
Mathesar 14%, 0 FN) before the hermetic 54%.

**Validation:** ruff clean · format clean · `mypy --strict src` clean (55 files) · pytest 321 passed.

**Handoff — what only the maintainer can do (see `docs/RELEASE.md`):** reserve `vulnadvisor` on PyPI
+ configure Trusted Publishing; create the `pypi` GitHub environment; push the `v1.0.0` tag (triggers
the publish); verify `uvx vulnadvisor` from PyPI; cut the GitHub Release; enable Discussions + create
the `feedback`/`false-negative` labels; post to r/Python and HN.

---

## Task 10.4 — Public-API call-path resolution (IMPORTED-AND-CALLED on real advisories)  (2026-06-09)

**Status:** complete, Validation Gate passing. (M10 — optional/recommended; strengthens the marquee call-path demo.)

**Result:** the call-path demo now fires when user code calls a **public API** that reaches an
*internal* vulnerable symbol — e.g. `parse_config -> yaml.load`. Closes the Task 6.1 gap (the live
run found 0 IMPORTED-AND-CALLED because real advisories patch internal functions the user never
calls directly). Demonstrated on **3 real advisories** with the full path shown, with the soundness
gate (zero false AND-CALLED) intact.

**What changed**
- New `callgraph/public_api.py`: a curated, hand-verified map for marquee packages — PyYAML
  (`load`/`load_all`/`unsafe_load` -> `make_python_instance`/`construct_python_*`, CVE-2020-14343),
  requests (`get`/`post`/... -> `resolve_redirects`/`rebuild_auth`, CVE-2018-18074), PyJWT
  (`decode` -> `_verify_signature`, CVE-2022-29217). Two soundness guards: a rule contributes its
  public APIs **only when the advisory's own vulnerable symbols intersect the rule's internal
  symbols** (so an unrelated advisory on the same package never flags the API), and `safe_args`
  clears a provably-safe call (`yaml.load(x, Loader=SafeLoader)`).
- `callgraph/call_paths.py`: `find_vulnerable_call_paths` gains a `guarded_apis` map (public API ->
  safe-arg identifiers); `_vuln_call_name` clears a matched public API when the call references a
  safe-path argument. Threaded through the per-file node builder.
- `reachability/tiering.py`: `refine_reachability` augments the searched symbol set with
  `public_apis_reaching(dependency.name, advisory_symbols)` and passes `safe_args_for(...)`.

**Why these choices**
- Curated public-API map (vs. a shallow intra-library call graph): tractable, fully sound, and the
  rule only fires on an advisory whose *own* symbols match — it never invents a path. The
  `safe_args` guard keeps precision at the call-argument level, not just the API name (so safe usage
  is correctly not reported, which is what the soundness gate checks).
- Matching covers `pkg.api(...)` and `from pkg import api; api(...)`; the three packages were chosen
  partly because their dangerous public API is called in exactly those forms (and PyYAML/PyJWT map
  to `yaml`/`jwt` via the curated import-name table).

**Validation evidence**
- New `tests/test_public_api_callpaths.py` (10 cases): yaml.load / requests.get / jwt.decode each
  show the full path ending at the public API; soundness — `yaml.safe_load`, `yaml.load` with a safe
  `Loader`, and an unrelated advisory (`scan_to_next_token`) are NOT reported; plus unit tests for
  the curated map's intersection requirement.
- ruff check clean; ruff format --check clean; `mypy --strict src` clean (55 files); **pytest 321
  passed**; hermetic benchmark unchanged (54%, 0 FN, 0 new false AND-CALLED).

**Open questions**
- The live `--live` benchmark still reports 0 IMPORTED-AND-CALLED: its snippet computes *package*-
  level reachability only (it has no per-advisory vulnerable-symbol dataset in the throwaway venv),
  so it never exercises `refine_reachability`. The feature is proven via the scan's reachability
  step (the fixtures); wiring the symbol dataset into the live run would be a separate enhancement.

---

## Task 10.3 — First-party dynamic-import resolution + bounded loader detection  (2026-06-09)

**Status:** complete, Validation Gate passing. (M10 — make noise reduction real on real code; gates publish 10.5.)

**Headline result:** the live benchmark now shows **real, sound noise reduction on real apps** —
paperless **37%** (59/159), BookWyrm **10%** (4/41), Mathesar **14%** (2/14) — while the other 10
apps stay conservative (0%), and **all 13 repos / 1,210 advisories have zero false negatives and
zero missed reachable criticals**. Hermetic corpus unchanged (54%, 0 FN).

**The investigation (decisions surfaced to the user):**
1. The first-party-import classifier alone moves **nothing** on real apps: empirically, their
   blockers are runtime `eval`/`exec`/opaque `import_module`, not resolvable first-party imports
   (redash `exec`s user code; loaders are env-extensible). Conservatism there is *sound*.
2. Curating deprioritizing apps surfaced latent **false-negative vectors** the old engine (and even
   the benchmark FN-guard) missed: Django `INSTALLED_APPS` string-loading, custom file loaders
   (searx's `load_module` wrapping `imp.load_source`), bare `import_module(x)` (a detection gap),
   `pkgutil` discovery. The engine was only "safe" before because it deprioritized *nothing*.
   **User chose: add bounded loader detection, then curate** (no false negatives).

**What changed (engine, all sound — only ever add caution or add imports):**
- `model/imports.py`: `DynamicImportSite` gains `target_root`, `first_party_relative`, `runtime`
  (all content-only/cacheable) + `is_provably_first_party()`; `ImportGraph.unproven_dynamic_sites()`
  returns sites that genuinely force caution (runtime AND not provably first-party-only).
- `callgraph/import_graph.py`: (a) classify each dynamic-import target — a constant first-party
  prefix / leading-dot / `__name__`-prefix is provably first-party, so a loader that only reaches
  the project's own modules no longer escalates third-party deps; (b) **bounded loader detection** —
  match the bare callee name, so `from importlib import import_module` then `import_module(x)` is
  caught (was a gap), plus `load_source`/`spec_from_file_location`/`exec_module`/`walk_packages`/
  `iter_modules`; file loaders are never "provably first-party"; (c) **non-runtime scoping** — a
  `docs/`/`setup.py`/`conf.py` `eval`/`exec` is build-time, never the deployed app, so it does not
  force caution (static imports there are still counted); (d) **Django `INSTALLED_APPS`** literals
  (and split-settings `*_APPS` lists) become synthetic import sites, so framework-loaded apps are
  IMPORTED, never wrongly NOT-IMPORTED.
- `reachability/tiering.py`: escalate on `unproven_dynamic_sites()` instead of all dynamic sites.
- `store/analysis_cache.py`: analysis-version prefix in the cache key (bumped to 4) so a schema
  change invalidates stale entries instead of deserializing less-conservative results.
- `benchmarks/manifest.py`: **always rebuild the wheel** (it was silently benchmarking the stale
  Task-10.2 wheel — the bug that first showed paperless at 0%); **strengthened FN-guard** — a
  NOT-IMPORTED dep is a suspect false negative if its import name appears as a static/INSTALLED_APPS
  root, a module-reference string literal anywhere in source, or in packaging metadata (catches
  dynamic-import / INSTALLED_APPS / entry-point loading); added paperless, BookWyrm, Mathesar.
- `benchmarks/report.py`: live "soundness" framing rewritten to *bimodal* (conservative on
  dynamic-dispatch apps, deprioritizes on analyzable ones; 0 FN across both).
- `docs/launch-post.md`: real-app noise numbers (paperless 37% etc.) alongside the 54% static figure.

**Why these choices**
- Every engine change is monotonic toward soundness: it either *adds* caution (more dynamic sites
  detected) or *adds* imports (INSTALLED_APPS), or relaxes caution only where provably safe
  (first-party-only targets, build-time-only files). It can never newly hide a reachable finding.
- The cheap dev-env probe gave wrong import-name mappings for uninstalled packages (e.g. mapped
  `pycryptodome`→`pycryptodome` instead of `Crypto`); the per-repo venv (latest install) is the
  authoritative mapping, so candidate selection was confirmed via the real pipeline + FN-guard.

**Validation evidence**
- 11 fixtures for first-party targets (constant/relative/`__name__`-prefix vs opaque/exec/third-party
  constant); 4 for bounded loaders (bare `import_module`, `load_source`, `spec_from_file_location`,
  `pkgutil`); INSTALLED_APPS literal + split-settings; non-runtime `eval` vs runtime `eval`.
- `uv run python -m benchmarks --live` → **13 repos, 1,210 advisories, 65 deprioritized (5%),
  false-negatives 0, missed-criticals 0, exit 0**; paperless/BookWyrm/Mathesar at 37%/10%/14%.
- `uv run python -m benchmarks` (hermetic) → **54%**, 0 FN, exit 0 (unchanged).
- ruff check clean; ruff format --check clean; `mypy --strict src` clean (54 files); **pytest 311
  passed**.

**Open questions**
- IMPORTED-AND-CALLED is still 0 across the live corpus (call-path demo gap) — that is Task 10.4
  (optional, pre-launch nice-to-have). The reachability *tiering* (NOT-IMPORTED noise reduction) is
  what 10.3 proves on real code.

---

## Task 10.2 — Live benchmark on real public repos  (2026-06-09)

**Status:** complete, Validation Gate passing. (M10 — replace the synthetic 54% with real, publishable evidence.)

**Headline result:** the live run is a **soundness proof** across **10 real applications** (redash,
Superset, NetBox, Saleor, AWX, Frappe, IntelOwl, CTFd, django.nV, healthchecks), pinned to older
tags with known-vulnerable dependencies: **996 real OSV advisories triaged, zero false negatives,
zero missed reachable criticals.** The hermetic **54%** noise-reduction figure is kept as the
clearly-labeled *static-corpus* result (reproducible via `python -m benchmarks`).

**Two decisions (user):**
1. **Baseline source → OSV-direct.** `pip-audit` structurally cannot audit the corpus we need: its
   `-r` mode shells out to `pip install --dry-run --report`, which must *build a wheel* for every
   dependency to read metadata, and decade-old vulnerable versions (e.g. `pystache`) fail to build
   on modern Python (`use_2to3 is invalid`). So 12/13 baselines came back empty. We now query OSV
   directly from pinned `name==version` lines — the *same database* pip-audit/Dependabot draw from,
   minus the wheel-building fragility.
2. **Reframe the launch honestly** (no engine change). Real apps show ~0% deprioritization because
   their plugin-loader dynamic imports (`importlib`/`__import__`/`exec`) globally block the
   `NOT_IMPORTED` verdict — the soundness rule at `reachability/tiering.py` escalates every unproven
   finding to a cautious tier rather than risk a false "safe." The live run therefore demonstrates
   *soundness/conservatism on real code*; the 54% (static, fully-analyzable corpus) demonstrates
   *noise reduction*. Both are published, each clearly labeled.

**What changed**
- Rewrote `benchmarks/manifest.py`: `_osv_baseline()` (parse pinned reqs → `OSVClient.query` per
  dep, persisted SQLite cache at `benchmarks/.osv-cache.sqlite` so re-runs hit zero network);
  curated `MANIFEST` to 10 real apps at vulnerable tags; reachability still computed locally inside
  a throwaway per-repo `uv venv`. **Mapping fix:** install the *latest* version of each flagged
  package (import name is version-stable and latest has prebuilt wheels) instead of the unbuildable
  pinned-vulnerable version — restores HIGH-confidence package→import mapping. Per-package
  false-negative guard retained (a `NOT_IMPORTED` whose import name appears in the graph →
  `reachable_truth=True` → counted as a release-blocking FN).
- `benchmarks/report.py`: added a `kind` framing (`"noise"` vs `"soundness"`); the live report leads
  with the soundness headline + an explanation of the conservative dynamic-dispatch behavior.
- `benchmarks/__main__.py`: `--live` renders with `kind="soundness"` → `benchmarks/REPORT.live.md`.
- `docs/launch-post.md`: rewrote "The result" → "The results" presenting both numbers honestly
  (996-advisory soundness proof + 54% static noise reduction); corrected the baseline description.

**Why these choices**
- OSV-direct keeps the baseline faithful to "what a naive scanner shows" while being robust on the
  exact old corpus that defeats build-based auditors — and needs only one public API (OSV).
- Installing *latest* for mapping is sound: reachability depends only on the version-stable import
  name, never on the installed version; the vulnerable version is recorded from the manifest pin.
- Dropped zulip from the manifest: its 5,645-file checkout reliably fails inside the harness's temp
  environment (clone itself is fine standalone); the other 10 returned identical counts across two
  runs, so 996 is reproducible. mailu/jupyterhub/graphite-web were unpinned (no `==` → no baseline)
  and the sentry 9.1.2 tag does not exist — all replaced by CTFd + healthchecks.

**Validation evidence**
- `uv run python -m benchmarks --live` → end-to-end on **10 real repos**, 996 advisories,
  false-negatives **0**, missed-criticals **0**, exit **0**; wrote `benchmarks/REPORT.live.md`.
- `uv run python -m benchmarks` (hermetic) → **54%** (39→18), 0 FN, exit 0; wrote `REPORT.md`.
- ruff check clean; ruff format --check clean (84 files); `mypy --strict src` clean (54 files);
  **pytest 280 passed**.

**Open questions**
- A future, separate, soundness-critical task could make dynamic imports that provably target
  first-party modules stop poisoning third-party `NOT_IMPORTED` verdicts (redash's loaders only
  reach `redash.*` plugins) — this would unlock real noise reduction on real apps. Deliberately
  *not* done now (engine change, release-blocking if wrong); flagged for post-launch.

---

## Task 10.1 — Package, document, publish  (2026-06-09)

**Status:** complete, Validation Gate passing. (M10 — launch readiness.)

**Decision (user):** license the core **Apache-2.0** (permissive + patent grant).

**Scope note:** made the project *publish-ready* but did **not** upload to PyPI — that needs the
maintainer's account/token and is irreversible. A `release.yml` workflow publishes on tag via PyPI
Trusted Publishing once the maintainer configures the publisher.

**What changed**
- Packaging: `pyproject.toml` gains classifiers, real repo URLs, Issues/Changelog links; console
  script `vulnadvisor` already wired. Added `src/vulnadvisor/py.typed` (typed library; also makes
  `mypy` see the package from `benchmarks/`).
- Legal: `LICENSE` (full Apache-2.0 text), `NOTICE`.
- Docs: rewrote `README.md` (install via pip/uvx, <5-min quickstart, plain-English layer, tiers,
  deterministic scoring, output formats, GitHub Actions snippet, **privacy** section);
  `CONTRIBUTING.md`; `CHANGELOG.md` (1.0.0); `docs/launch-post.md` built on the M8 benchmark.
- Example: `examples/quickstart/` (PyYAML used -> IMPORTED; unused requests -> deprioritized) for
  the quickstart and the CI smoke test.
- CI: extended `ci.yml` to an OS x Python matrix (ubuntu/windows x 3.12/3.13) plus a **package**
  job that builds the wheel, installs it into a *clean* venv with pip, and runs the installed
  console script end-to-end. Added `release.yml` (build + Trusted-Publishing to PyPI on `v*` tags).

**Why these choices**
- Honesty over hype in the docs: a clean `uvx` install can't read the target project's installed
  metadata, so an unused dep stays the cautious `DYNAMIC-UNKNOWN` (not `NOT-IMPORTED`) — documented
  with a tip to install in-project. And `IMPORTED-AND-CALLED` needs the backfilled symbol dataset;
  advisories whose fix touches only library-internal symbols stay `IMPORTED` (the Task 6.1
  limitation) — stated plainly rather than papered over.

**Validation evidence**
- **Clean install in a fresh environment works end-to-end** (verified locally, mirrored in CI): an
  isolated install of the built wheel runs `vulnadvisor --version` and a real `scan
  examples/quickstart` that hits live OSV and prints ranked JSON/three-card output.
- Quickstart reproduces a real scan in well under 5 minutes (`uvx vulnadvisor scan
  examples/quickstart`).
- Wheel ships `py.typed` + entry point; sdist ships `LICENSE` + `README`.
- Gate: `ruff check` / `ruff format --check` clean, `mypy --strict src` clean (54 files),
  `pytest` 280 passed.

**Open questions / before going public**
- Confirm the GitHub org/repo slug in URLs is final; set up PyPI Trusted Publishing for the `pypi`
  environment; then push a tag to release. Reserve the `vulnadvisor` name on PyPI.

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
