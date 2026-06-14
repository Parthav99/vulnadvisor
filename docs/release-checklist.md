# VulnAdvisor — Release checklist (M12 → M17 audit)

> **What this is:** the single inventory of everything that gates the `v2.0.0` and `v2.1.0`
> releases. It separates what is **proven hermetically** (re-runnable here, with no credentials)
> from what is **deferred / credential-gated** (a live run the maintainer must execute with a real
> model key and/or real GitHub credentials).
>
> **Audited:** 2026-06-14, against `main` at the time of the M12–M17 gap-closing pass.
> **Bottom line:** the automated gate is fully green, all cross-cutting invariants hold, and every
> deferred item below is **code-complete** — only live verification remains. No genuine code gap
> blocks either tag.

---

## 0. Status at a glance

| Item | Milestone | State | Blocks tag |
|---|---|---|---|
| Full automated gate (ruff/mypy/pytest + dashboard) | all | ✅ green hermetically | — |
| Cross-cutting invariants (schema / SARIF / migrations / wheel deps / no-telemetry) | all | ✅ verified hermetically | — |
| Copilot red-team live run | 15.1 | ⏳ code-complete, live-gated (model key) | — |
| Copilot chat e2e | 15.2 | ⏳ code-complete, live-gated (model key) | — |
| SAST finding-card browser e2e | 16.4 | ⏳ code-complete, live-gated (stack) | **v2.0.0** |
| GitHub code-scanning SARIF upload | 16.4 | ⏳ code-complete, live-gated (GitHub) | **v2.0.0** |
| SAST benchmark zero-missed gate | 16.5 | ✅ green hermetically (`--sast`) | — |
| SCA+SAST+pyscan perf run (warm/cold, real OSS) | 16.5 | ⏳ code-complete, live-gated (network + pyscan binary) | — |
| `vulnadvisor fix` live (real model authors a diff) | 17.1 / 17.3 | ⏳ code-complete, live-gated (model key) | **v2.1.0** |
| 17.2 in-line suggestion live e2e (GitHub App path) | 17.2 | ⏳ code-complete, live-gated (App + model key) | **v2.1.0** |
| 17.4 zero-setup suggestion live e2e (`GITHUB_TOKEN`) | 17.4 | ⏳ code-complete, live-gated (scratch repo + model key) | **v2.1.0** |
| 17.4 Part 3 OAuth setup-PR live spot-check | 17.4 P3 | ⏳ code-complete, live-gated (OAuth login) | **v2.1.0** |

"Code-complete" = the logic is implemented and proven hermetically (scripted/faked client, real
subprocess/rescan, snapshot tests); the only thing not yet done is running it against live
credentials. None of the items below is a code gap.

---

## 1. Re-run the hermetic gate (no credentials needed)

These all pass today. Run from the repo root unless noted.

```bash
# Python core + platform
uv run ruff check
uv run ruff format --check
uv run mypy --strict src
uv run mypy --strict platform/vulnadvisor_platform
uv run pytest -q                     # 819 passed, 1 skipped (665+1 root, 154 platform)

# Dashboard
cd dashboard
npm run lint
npm test                             # 64/64
npm run build
```

**Proves it passed:** ruff "All checks passed!" + "190 files already formatted"; mypy "Success: no
issues found" on both targets; pytest "819 passed, 1 skipped"; dashboard lint clean, "tests 64 …
pass 64 … fail 0", build "Compiled successfully".

> Note: PROGRESS labels the combined pytest total (819) as "src"; the true split is `tests/` = 665
> passed + 1 skipped and `platform/tests/` = 154 passed. A cosmetic labelling quirk, not a defect.

---

## 2. Re-verify the cross-cutting invariants (no credentials needed)

```bash
# JSON schema_version 1.0/1.1/1.2 all parse on the platform
uv run pytest platform/tests -q -k "ingest or schema or parse_report"   # 17 passed

# SARIF (incl. code findings) validates against the bundled 2.1.0 schema
uv run pytest tests -q -k "sarif"                                        # 4 passed

# Core wheel has exactly 3 runtime deps; mcp is extra-only
uv run pytest tests/test_mcp_server.py -q -k "core_wheel_runtime_deps"   # asserts {packaging,pydantic,typer}

# Every Alembic migration additive + no drift vs a live Postgres
docker compose -f platform/docker-compose.yml up -d
cd platform && uv run alembic upgrade head && uv run alembic check       # "No new upgrade operations detected."

# No telemetry / network only to documented APIs (manual audit)
#   outbound hosts in src/: api.osv.dev, api.first.org (EPSS), cisa.gov (KEV),
#   api.github.com (GHSA/App/PR), api.anthropic.com / api.openai.com / openrouter.ai
#   (the user's own model key), + the user's own configured platform URL. No analytics SDKs.
```

All five verified on 2026-06-14. The migration chain is linear (single head `e2d5a8f3c6b1`); every
`upgrade()` is additive (relax-to-nullable or `add_column` with a `server_default`); `drop_*` calls
exist only in `downgrade()`.

---

## 3. Deferred / credential-gated runbooks

Each entry: **what it is → prerequisites → exact commands → what output proves it passed →
code-complete vs gap**.

### 3.1 Copilot red-team live run (Task 15.1)
- **What:** runs the production system prompt + production tool schemas against a live model with
  seeded malicious advisory text; asserts the injections do not alter behaviour. ≥5 cases snapshot.
- **Prereqs:** any funded model key. The previously supplied OpenAI key had **zero credits**
  (`insufficient_quota`); a free **OpenRouter** key is sufficient.
- **Run (from `dashboard/`):**
  ```bash
  # pick ONE:
  ANTHROPIC_API_KEY=sk-ant-...  node scripts/copilot-redteam.ts
  OPENAI_API_KEY=sk-...         node scripts/copilot-redteam.ts
  OPENROUTER_API_KEY=sk-or-...  node scripts/copilot-redteam.ts   # provider follows the key prefix
  ```
- **Proves it passed:** the script writes ≥5 snapshots to `dashboard/scripts/redteam-snapshots/`,
  prints per-case PASS, and **exits 0**. Any case where the model obeyed an injected instruction
  (e.g. emitted an "all clear", re-ranked, leaked the prompt, or targeted another org) → non-zero
  exit. (`exit 2` means no key was provided — not a failure of the suite.)
- **Status:** **code-complete.** The harness, prompt, tool schemas, and pass/fail assertions are
  all in place and unit-tested; only the live inference call is unrun.

### 3.2 Copilot chat e2e (Task 15.2)
- **What:** in the dashboard, ask "What should I fix first?" on a seeded org → the copilot cites the
  actual top-priority finding and the deep link opens its expanded card.
- **Prereqs:** the local stack seeded with an org + scan (the 15.x live runs used `c:\tmp\va151`),
  `uvicorn` (platform) + `next start` (dashboard), and a model key. Either set the **deployment
  fallback** key in the dashboard env (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`), or paste a
  personal **BYOM** key in Settings → AI copilot (a free OpenRouter `sk-or-…` key works).
- **Run:** open the seeded org, click "How can I help?", ask "What should I fix first?".
- **Proves it passed:** the streamed answer names the top finding by `CVE · package`, and clicking
  its citation expands + scrolls to that card (`?finding=` deep link). The structural half (panel
  a11y, deep-link build↔match contract, streaming) is already covered by the headless-Edge
  13/13 + SSR e2e; only the live ask→answer is unrun.
- **Status:** **code-complete.** Blocked solely on a working model key (same blocker as 3.1).

### 3.3 SAST finding-card browser e2e (Task 16.4) — **gates v2.0.0**
- **What:** a seeded `schema_version 1.2` report with a SAST/"code" finding renders end-to-end in
  the dashboard `CodeFindingCard` (3-card story; evidence drawer shows the source→sink taint path).
- **Prereqs:** local stack + seeded SQLite (16.4 used a mixed-fixture upload), headless browser.
- **Run:**
  ```bash
  # 1) produce a 1.2 report with a code finding
  uv run vulnadvisor scan <mixed-fixture> --sast-only --format json > report.json
  # 2) upload it to a seeded org/repo (device login or API key), then
  # 3) open the scan page and assert the CodeFindingCard renders + the taint-path drawer opens
  ```
- **Proves it passed:** the scan page shows the CWE·title·`file:line` collapsed row, expands to the
  three cards, and the evidence drawer renders the `source → … → sink (file:line)` chain. Ingest of
  a 1.2 code finding + the component build + `lib/finding.test.ts` already pass; only the live
  browser render is unrun.
- **Status:** **code-complete.** Structural path proven by unit tests + the ingest test.

### 3.4 GitHub code-scanning SARIF upload (Task 16.4) — **gates v2.0.0**
- **What:** GitHub's code-scanning ingester accepts VulnAdvisor SARIF that includes first-party
  "code" findings (namespaced `ruleId`, CWE taxonomy, `codeFlow`/`threadFlow`).
- **Prereqs:** a GitHub repo with code scanning enabled; `gh` authenticated, or an Actions run.
- **Run:**
  ```bash
  uv run vulnadvisor scan . --format sarif > vulnadvisor.sarif
  # In a workflow:
  #   - uses: github/codeql-action/upload-sarif@v3
  #     with: { sarif_file: vulnadvisor.sarif }
  # Or locally via the API:
  gh api -X POST /repos/<owner>/<repo>/code-scanning/sarifs \
     -f commit_sha=$(git rev-parse HEAD) -f ref=refs/heads/main \
     -f sarif="$(gzip -c vulnadvisor.sarif | base64 -w0)"
  ```
- **Proves it passed:** the upload returns a processing URL and the findings appear under the repo's
  Security → Code scanning alerts (code findings included, with the taint path as the code flow).
  The SARIF already validates against the bundled `fixtures/schemas/sarif-2.1.0.json` (Draft7),
  including the code-finding shape — only GitHub's live acceptance is unrun.
- **Status:** **code-complete.** SARIF generation is done and schema-valid; the upload is a maintainer
  action.

### 3.5 Full SCA+SAST+pyscan perf run (Task 16.5)
- **What:** warm/cold wall-time for a full SCA+SAST scan over 2–3 real OSS Python apps, side-by-side
  with pyscan on the same repos.
- **Prereqs:** network (for the SCA/OSV/EPSS half); the **pyscan** Rust binary on `PATH` for the
  side-by-side column (omitted as "n/a" if absent).
- **Run:**
  ```bash
  uv run python -m benchmarks --sast --perf     # SAST wall time, offline (always runnable)
  uv run python -m benchmarks --live            # SCA over pinned public repos (needs network)
  ```
- **Proves it passed:** `SAST-REPORT.md` regenerates with the perf table; the full warm scan lands
  under the documented ≤30 s warm budget; pyscan's wall time appears alongside (or "n/a"). The
  release-blocking **zero-missed** SAST gate already passes offline today
  (`python -m benchmarks --sast` → 100% recall, exit 0).
- **Status:** **code-complete.** The offline SAST half + the gate run today; only the
  network/pyscan side-by-side is unrun.

### 3.6 `vulnadvisor fix` live (Tasks 17.1 / 17.3)
- **What:** a real model authors a unified diff that passes the full local validation loop
  (apply → syntax → ruff → mypy → tests → rescan-clean), end-to-end.
- **Prereqs:** any model key. Provider auto-detects from the prefix: `sk-or-` → OpenRouter (a free
  key is enough), `sk-ant-` → Anthropic, `sk-`/`sk-proj-` → OpenAI. Key precedence:
  `OPENROUTER_API_KEY` → `OPENAI_API_KEY` → `ANTHROPIC_API_KEY`.
- **Run:**
  ```bash
  export OPENROUTER_API_KEY=sk-or-...
  uv run vulnadvisor scan <fixture> --sast-only          # to get a finding id (<file>:<line>:<kind>)
  uv run vulnadvisor fix <finding-id> --path <fixture>   # prints the validated diff (no write)
  uv run vulnadvisor fix <finding-id> --path <fixture> --apply   # writes it; rescan is clean
  ```
- **Proves it passed:** a validated unified diff is printed (or "No safe fix found after N
  attempts" honestly when none validates); `--apply` writes it and a re-scan shows the finding
  gone. The full loop, prompt, parsing, every validation step, and the network audit (only the
  chosen model host is contacted) are proven hermetically with a scripted client; only the model's
  own patch authorship needs a funded key.
- **Status:** **code-complete.**

### 3.7 In-line suggestion live e2e — GitHub App path (Task 17.2) — **gates v2.1.0**
- **What:** a PR with a seeded vuln → CI runs `vulnadvisor fix --suggest-json` and uploads the
  validated-fix doc alongside the report → the **GitHub App** posts one-click in-line `suggestion`
  comments anchored to the vulnerable lines → "Commit suggestion" → next scan shows it fixed.
- **Prereqs:** a provisioned GitHub App (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`,
  `GITHUB_WEBHOOK_SECRET`, `PUBLIC_API_URL`) installed on a scratch repo; a model key in CI.
- **Run (CI on the scratch repo):**
  ```bash
  uv run vulnadvisor fix --suggest-json fixes.json --path .
  uv run vulnadvisor scan . --upload --suggestions fixes.json
  # the App webhook handler posts the in-line COMMENT review on the PR head sha
  ```
- **Proves it passed:** the App posts a COMMENT review (never REQUEST_CHANGES) with a
  ` ```suggestion ` block == the validated hunk + the 3-card story in `<details>`; on
  `synchronize` it prunes its own prior `<!-- vulnadvisor:fix -->` comments and reposts; clicking
  "Commit suggestion" then re-scanning clears the finding. Anchoring, idempotency, the COMMENT
  event, and the prune-then-repost are all proven against a fake GitHub transport.
- **Status:** **code-complete.**

### 3.8 Zero-setup suggestion live e2e — `GITHUB_TOKEN` path (Task 17.4) — **gates v2.1.0**
- **What:** the same payoff with **no GitHub App** — the generated workflow runs `vulnadvisor
  suggest` and posts in-line suggestions straight from Actions using the built-in `GITHUB_TOKEN`.
- **Prereqs:** a scratch repo with the generated workflow (from "set up repo"), `permissions:
  pull-requests: write` (already in the rendered workflow), and **one** model-key secret
  (`OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — a free OpenRouter key works).
- **Run:** open a PR that introduces a seeded vuln; the workflow's "Suggest validated fixes" step
  runs `vulnadvisor suggest` on `pull_request` events.
- **Proves it passed:** in-line suggestion comments appear on the PR (posted by
  `github-actions[bot]`); "Commit suggestion" applies the fix; the next run prunes the old comment
  and posts nothing new (finding fixed). Event parsing (`GITHUB_EVENT_PATH`/`GITHUB_SHA`), posting,
  pruning, pagination, and 404-tolerance are all proven against a fake GitHub.
- **Status:** **code-complete.**

### 3.9 OAuth setup-PR live spot-check (Task 17.4 Part 3) — **gates v2.1.0**
- **What:** "Sign in with GitHub → set up repo" opens the workflow setup-PR using the **logged-in
  user's OAuth token** (no App install), requesting `repo`+`workflow` scope only at the "set up"
  click (incremental authorization).
- **Prereqs:** GitHub OAuth app configured; a logged-in user; a scratch repo they can write to.
- **Run:** log in (`/v1/auth/github/login`), click "set up repo" → triggers
  `…/login?setup=1` for the elevated scope → the platform opens the setup-PR via
  `open_setup_pr_with_token`.
- **Proves it passed:** the setup-PR (`vulnadvisor/setup` branch, the `.github/workflows/*.yml`
  file) opens on the scratch repo authored as the user; re-clicking updates the same PR (idempotent,
  never duplicates); a read-only token yields a 409 ("grant repository access"). Scope-upgrade,
  encrypted-at-rest token storage, credential selection (App-then-OAuth), and the choreography are
  all proven hermetically; the token encryption migration is applied live with no drift.
- **Status:** **code-complete.** Cosmetic follow-up noted in PROGRESS (the PR-body footer still
  reads "Opened by the VulnAdvisor GitHub App" on the OAuth path) — left unparameterized to avoid
  snapshot churn; not a release blocker.

---

## 4. Tag gates

Neither tag's gate is fully green **hermetically** — by design, both end-of-milestone definitions
require a live e2e the maintainer must run with credentials. They are **not** cut in this audit.

### `v2.0.0` (CLI v2.0 — "triages your code, not just your deps")
Per task.md 16.4 ("Tag v2.0.0") and the PROGRESS deferral, the blockers are:
1. **SAST finding-card browser e2e** (§3.3) — live verification only.
2. **GitHub code-scanning accepts the SARIF with code findings** (§3.4) — live verification only.
3. **16.5 SAST benchmark zero-missed gate** — ✅ already green hermetically
   (`python -m benchmarks --sast`, exit 0).

**Verdict:** both remaining blockers are **live verifications the maintainer must run**; there is no
code gap. Once §3.3 and §3.4 are observed green, cut:
```bash
git tag -a v2.0.0 -m "CLI v2.0 — reachability-aware SAST + unified SCA/SAST triage"
git push origin v2.0.0
```

### `v2.1.0` (CLI v2.1 — validated fixes + PR suggestions, BYOM, zero-App)
Per task.md (the v2.1.0 tag moved to 17.4) and the PROGRESS deferrals, the blockers are:
1. **`vulnadvisor fix` live** (§3.6) — provider-flexible loop, live verification only.
2. **17.2 in-line suggestion live e2e** (App path, §3.7) — live verification only.
3. **17.4 zero-setup suggestion live e2e** (`GITHUB_TOKEN`, §3.8) — live verification only.
4. **17.4 Part 3 OAuth setup-PR spot-check** (§3.9) — live verification only.

(Task 17.5 — proposed fix in the dashboard card — ships independently as `dashboard-v1.1` and does
**not** gate the v2.1.0 CLI tag. It is also not yet implemented; out of scope for this audit.)

**Verdict:** every blocker is a **live, credential-gated verification**; there is no code gap. Once
§3.6–§3.9 are observed green, cut:
```bash
git tag -a v2.1.0 -m "CLI v2.1 — validated fixes + zero-setup PR suggestions (BYOM, no App required)"
git push origin v2.1.0
```

---

## 5. Auditor's conclusion

The M12–M17 codebase is in a releasable state pending live verification. The hermetic gate is green,
the five cross-cutting invariants hold, and the SAST release-blocking zero-missed gate passes. Every
deferred item is **code-complete**: each is proven hermetically with scripted/faked clients, real
subprocess/rescan, snapshot tests, and a live-applied additive migration. **No genuine in-code gap
or regression was found.** The only work remaining before `v2.0.0` and `v2.1.0` is the maintainer
executing the credential-gated runbooks in §3.
