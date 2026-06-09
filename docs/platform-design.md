# VulnAdvisor Platform — Design (M11, for review)

> **Status: APPROVED 2026-06-09 — gated behind the M10 launch.** The API surface below is accepted;
> no platform code is written until M10 (live benchmark + PyPI publish + launch) ships and there is
> real CLI traction. Task 11.1's gate ("API surface reviewed and approved") is satisfied.

The platform monetizes *teams* once developers already use the CLI. It does **not** replace the
CLI or change the engine — it wraps the exact same `vulnadvisor` library so verdicts are identical
whether you run locally or view them in the dashboard.

---

## 1. Guiding principles (carried from the CLI)

1. **Source code never leaves customer infrastructure by default.** This is the product's trust
   pillar; a naive "give us your private repos and we'll clone + scan them" breaks it. So:
   - **Analysis happens where the code already is** — in the customer's CI (the CLI uploads its
     JSON report) or via a **self-hosted runner**. The platform stores *findings + metadata*, never
     source. Cloud-side cloning of private source is an explicit, opt-in mode, never the default.
2. **Deterministic priority stays in the engine.** The API serves the engine's `ScoredFinding`; the
   platform never recomputes or reorders priority.
3. **Same models end to end.** The API's finding payload is the existing JSON report
   (`schema_version` 1.0) so the CLI, JSON output, and platform never diverge.
4. **Soundness is preserved.** `degraded_sources` and tiers are surfaced verbatim; the dashboard
   never renders a finding as "safe" that the engine left uncertain.
5. **Incremental infra.** Start synchronous + Postgres only. Add Redis + RQ **only** when profiling
   shows the API blocking on scans. No Kubernetes.

---

## 2. Architecture

```
Developer CLI ──(vulnadvisor scan --format json)──┐
GitHub CI (Action) ──upload report──────────────► │
Self-hosted runner ──upload report──────────────► ├─► Ingest API ─► Postgres
                                                  │        │
GitHub App (PR webhook) ─► enqueue scan ──────────┘        ├─► Dashboard API ─► Next.js (read)
                                                           └─► GitHub App ─► PR comment (3 cards)
```

- **Engine reuse:** the backend imports `vulnadvisor` (`scan_project`, the JSON report builder) as
  a library. For the default "bring-your-own-analysis" mode it only *parses and stores* a report
  the client already produced. For the opt-in cloud-scan/self-hosted-runner mode it *runs* the
  engine.
- **Backend:** FastAPI (async), Pydantic v2 models reused from the core where possible.
- **DB:** Postgres (SQLAlchemy 2.x + Alembic migrations). No ORM lock-in beyond that.
- **Frontend:** Next.js (App Router) + Tailwind + shadcn/ui, dark theme `#0d1117`.
- **Auth:** GitHub OAuth for the dashboard (session cookie); scoped **API keys** for CI/CLI
  uploads; GitHub App installation tokens for PR comments.

---

## 3. Data model (Postgres)

| Table | Key columns | Notes |
|-------|-------------|-------|
| `orgs` | `id`, `slug`, `name`, `github_org_id`, `plan` | A billing/tenant boundary. |
| `users` | `id`, `github_user_id`, `login`, `email`, `avatar_url` | |
| `memberships` | `user_id`, `org_id`, `role` (`owner`/`admin`/`member`) | Tenant access control. |
| `repositories` | `id`, `org_id`, `name`, `default_branch`, `github_repo_id`, `is_private` | |
| `api_keys` | `id`, `org_id`, `name`, `hash`, `prefix`, `created_by`, `last_used_at`, `revoked_at` | Only the hash is stored. Used for report uploads. |
| `installations` | `id`, `org_id`, `github_installation_id`, `account_login` | GitHub App install. |
| `scans` | `id`, `repo_id`, `commit_sha`, `ref`, `pr_number?`, `source` (`ci`/`runner`/`cloud`/`pr`), `tool_version`, `status`, `degraded_sources`, `summary` (jsonb: total + by_band), `created_at` | One uploaded/produced report. |
| `findings` | `id`, `scan_id`, `advisory_id`, `package`, `version`, `tier`, `band`, `priority`, `payload` (jsonb = the JSON report finding incl. call paths/fix) | `payload` is the source of truth; columns are denormalized for querying/trends. |

Indexes: `findings(scan_id)`, `findings(package, advisory_id)`, `scans(repo_id, created_at)`.
Tenant isolation enforced at the query layer (every query is org-scoped via the authenticated
principal); optionally Postgres RLS later.

---

## 4. API surface (the thing under review)

REST, JSON, versioned under `/v1`. Auth: `Authorization: Bearer <api_key>` for ingest;
session cookie for dashboard; HMAC-verified GitHub webhooks. All list endpoints are org-scoped and
paginated (`?limit&cursor`).

### Health / meta
- `GET /healthz` → `{status, version}` (no auth).
- `GET /v1/me` → the authenticated user + their orgs/roles.

### Orgs & members (dashboard, session auth)
- `GET /v1/orgs` → orgs the user belongs to.
- `GET /v1/orgs/{org}` → org detail (plan, counts).
- `GET /v1/orgs/{org}/members` · `POST` (invite) · `DELETE /members/{user}` (owner/admin only).

### API keys (CI/CLI credentials)
- `GET /v1/orgs/{org}/keys` → list (prefix + metadata, never the secret).
- `POST /v1/orgs/{org}/keys` → create; returns the secret **once**.
- `DELETE /v1/orgs/{org}/keys/{id}` → revoke.

### Repositories
- `GET /v1/orgs/{org}/repos` · `GET /v1/orgs/{org}/repos/{repo}`.
- `GET /v1/orgs/{org}/repos/{repo}/trend?window=90d` → per-day actionable/deprioritized counts and
  reachable-called totals (the "are we getting safer" chart).

### Scans & findings (read)
- `GET /v1/orgs/{org}/repos/{repo}/scans?ref=&limit=&cursor=` → scan list.
- `GET /v1/scans/{scan}` → scan detail (summary, `degraded_sources`, status).
- `GET /v1/scans/{scan}/findings?tier=&band=&min_priority=` → findings, priority-desc. Each finding
  is the **existing JSON-report finding object** (dependency, advisory, epss, in_kev, score,
  reachability + call_paths, fix). Optional `explanation` (Card A) when enabled.
- `GET /v1/scans/{a}/diff/{b}` → introduced / fixed / unchanged findings between two scans (drives
  the PR comment).

### Ingest (the core write path — API-key auth)
- `POST /v1/orgs/{org}/repos/{repo}/scans`
  - Body: `{commit_sha, ref, pr_number?, report}` where `report` is the **`vulnadvisor scan
    --format json`** document (validated against `schema_version`).
  - The platform validates, denormalizes into `findings`, computes the diff vs the previous scan on
    that ref, returns `{scan_id, summary, diff_summary}`.
  - This is how CI/CLI/self-hosted-runner publish results **without** sending source.

### GitHub App (webhooks + PR comments)
- `POST /v1/github/webhook` → HMAC-verified. On `pull_request` (opened/synchronize): create a
  pending scan, request analysis (runner/CI), and on report arrival post/update a PR comment
  summarizing new reachable findings as the 3 cards (collapsed for noise). On `installation`
  events: upsert `installations`/`repositories`.
- `GET /v1/github/install` → start the App installation flow.

### Optional cloud-scan (opt-in only)
- `POST /v1/orgs/{org}/repos/{repo}/cloud-scan` → enqueue an engine run against a ref. Disabled
  unless the org explicitly opts in (because it means cloud-side source access).

---

## 5. Dashboard (Next.js, dark `#0d1117`)

- **Org overview** — repos, total actionable findings, trend sparkline, last scan status.
- **Repo view** — trend chart (actionable vs deprioritized over time), latest scan, branch picker.
- **Scan detail** — the ranked **three cards** per finding (reusing the exact rendering semantics:
  Attack story / Risk / Action with the call-path evidence and tier), filters by tier/band.
- **PR view** — the introduced/fixed diff for a pull request.
- **Settings** — members, API keys, GitHub App install, cloud-scan opt-in.

Read-only against the Dashboard API; no business logic in the frontend.

---

## 6. Background processing (deferred by rule)

Start **synchronous**: ingest is fast (parse + insert). PR-triggered analysis is delegated to the
runner/CI, so the API doesn't block on scanning. Add **Redis + RQ** *only* if profiling shows the
ingest/diff path or webhook handler blocking. No queue, no Redis, no K8s until measured need.

---

## 7. Security & privacy

- API keys stored hashed (prefix shown for identification); shown in full once.
- GitHub webhooks HMAC-verified; App tokens short-lived per installation.
- Strict tenant scoping on every query; consider Postgres RLS as defense-in-depth.
- **Privacy statement for hosted:** the platform stores findings + dependency metadata, not source,
  unless an org opts into cloud-scan. Self-hosted runner keeps analysis fully inside customer infra.
- Secrets via environment/secret manager only; no secrets in code or DB in plaintext.

---

## 8. Proposed sub-task breakdown (each gets its own task + gate)

> Per the M11 gate, the milestone is broken into independently-validated pieces. Nothing here is
> built until the API surface above is approved.

- **11.2 — Backend skeleton + data model.** FastAPI app, SQLAlchemy models, Alembic migration,
  `/healthz`, `/v1/me`; Postgres via docker-compose for dev. *Gate:* migrations apply on a clean DB;
  health + auth round-trip tested; mypy/ruff/pytest green.
- **11.3 — Ingest API + diff.** The `POST .../scans` write path reusing the core JSON schema;
  scan-to-scan diff. *Gate:* uploading a real `vulnadvisor --format json` report persists findings
  and returns the correct diff (tested against fixtures); rejects malformed/old-schema reports.
- **11.4 — Read API + trends.** Orgs/repos/scans/findings/trend endpoints, pagination, org scoping.
  *Gate:* tenant isolation tested (no cross-org reads); trend math verified.
- **11.5 — Auth: GitHub OAuth + API keys.** Session login, key issue/revoke. *Gate:* key hashing +
  revocation tested; unauthorized requests rejected.
- **11.6 — GitHub App.** Webhook verification, installation sync, PR comment with the 3-card diff.
  *Gate:* signed webhook fixtures drive a PR comment; bad signatures rejected.
- **11.7 — Dashboard.** Next.js read-only UI over the API (overview, repo trend, scan 3-cards, PR
  diff, settings). *Gate:* renders a seeded org end-to-end; a11y/contrast on the dark theme.
- **11.8 — (conditional) Background processing.** Redis + RQ, only if 11.3/11.6 profiling shows
  blocking. *Gate:* the blocking path is measurably non-blocking; failure/retry tested.

---

## 9. Open questions for the reviewer

1. **Default analysis location:** confirm "bring-your-own-analysis (CI/runner uploads reports), no
   cloud-side source access by default" — this preserves the trust pillar. Agree?
2. **Auth for the dashboard:** GitHub OAuth only to start (matches the GitHub App), or also
   email/password? Recommend GitHub-only initially.
3. **First slice to build after approval:** recommend 11.2 → 11.3 (skeleton + ingest) since ingest
   is the value spine; the GitHub App and dashboard follow.
4. **Hosting/runtime target** (affects nothing in the API, but informs 11.2 docker/compose): any
   preference (Fly.io / Render / a VPS)?
5. **Tenancy depth:** is org = GitHub org sufficient, or do we need sub-teams/projects now?
