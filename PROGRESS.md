# PROGRESS

Running log of state + decisions. Newest entry on top. Updated after every task.

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
