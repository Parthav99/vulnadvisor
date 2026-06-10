# VulnAdvisor dashboard

A read-only Next.js (App Router) dashboard over the VulnAdvisor platform API — dark theme
(`#0d1117`), no business logic in the frontend. Deployable free on Vercel.

## Views

- **Home** (`/`) — your organizations (or a GitHub sign-in prompt).
- **Org** (`/orgs/{org}`) — repos, member/repo counts, link to settings.
- **Repo** (`/orgs/{org}/repos/{repo}`) — 90-day reachability trend (actionable vs deprioritized,
  reachable-called marked), branch picker, scan list.
- **Scan** (`/scans/{scan}`) — the signature **three cards** per finding (Attack story / Risk /
  Action) with the reachability tier, call-path evidence, and fix; filter by tier/band.
- **Diff** (`/scans/{from}/diff/{to}`) — findings introduced / fixed between two scans.
- **Settings** (`/orgs/{org}/settings`) — API keys (read-only), GitHub App install, cloud-scan
  status.

## Run locally

The dashboard renders server-side and forwards the session cookie to the API. In dev both run on
`localhost`, so the cookie set by the API's OAuth flow is shared.

```bash
cp .env.example .env.local   # set API_URL / NEXT_PUBLIC_API_URL (and optionally DASHBOARD_API_TOKEN)
npm install
npm run dev                  # http://localhost:3000  (API expected at http://localhost:8000)
```

`DASHBOARD_API_TOKEN` (an org-scoped API key) lets the dashboard render without an interactive login —
useful for local dev and previews.

## Validate

```bash
npm run build   # TypeScript typecheck + production build
npm run lint    # ESLint (next core-web-vitals + typescript)
```
