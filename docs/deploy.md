# Deploying VulnAdvisor (full stack)

A step-by-step runbook to put the hosted platform live on **free infra**:

- **Postgres** → Neon (free tier)
- **Backend (FastAPI)** → Fly.io (free shared-cpu, 256MB)
- **Dashboard (Next.js)** → Vercel (free), already at `https://vulnadvisor.vercel.app`

> **Privacy stance (unchanged):** the platform stores findings + metadata only. Source code never
> leaves customer infra — the CLI/CI uploads `vulnadvisor scan --format json`. Nothing here changes that.

You only do this once. Re-deploys are just `fly deploy` (backend) and a Vercel redeploy (frontend).

**Prerequisites**

```bash
# Fly CLI
curl -L https://fly.io/install.sh | sh     # macOS/Linux
# Windows (PowerShell): iwr https://fly.io/install.ps1 -useb | iex
fly auth login

# Vercel CLI (optional — you can use the dashboard UI instead)
npm i -g vercel
vercel login
```

You also need a GitHub account for the OAuth app / GitHub App (Step 2c).

---

## 1. Neon — free Postgres → `DATABASE_URL`

1. Sign in at <https://neon.tech> and **Create project** (pick the region nearest your Fly region,
   e.g. AWS `us-east-1` ↔ Fly `iad`).
2. On the project dashboard, open **Connection Details** and copy the **connection string**. It looks
   like:

   ```
   postgresql://myuser:mypassword@ep-cool-name-123456.us-east-1.aws.neon.tech/neondb?sslmode=require
   ```

3. **Convert it to the async driver this app uses.** The backend talks to Postgres via `asyncpg`, so
   the scheme must be `postgresql+asyncpg://` and the `sslmode` query param must be dropped (asyncpg
   doesn't accept it; the `.neon.tech` host negotiates TLS automatically). Transform:

   | From (Neon gives you)        | To (what the app needs)              |
   | ---------------------------- | ------------------------------------ |
   | `postgresql://…`             | `postgresql+asyncpg://…`             |
   | `…/neondb?sslmode=require`   | `…/neondb`  *(drop `?sslmode=...`)*  |

   Final value to keep handy for Step 2:

   ```
   postgresql+asyncpg://myuser:mypassword@ep-cool-name-123456.us-east-1.aws.neon.tech/neondb
   ```

   > Neon's free tier auto-suspends an idle database; the first request after idle reconnects in a
   > second or two. That pairs well with Fly's `auto_stop_machines`.

---

## 2. Fly.io — backend

Run all commands from the **repo root** (where `Dockerfile` and `fly.toml` live).

### 2a. Create the app (no deploy yet)

`fly.toml` already defines the app (`vulnadvisor-api`), the 256MB VM, and the `/healthz` check, so
reuse it rather than letting `launch` regenerate it:

```bash
fly launch --no-deploy --copy-config --name vulnadvisor-api --region iad
```

- If `vulnadvisor-api` is taken, pick another name and update `app = "..."` in `fly.toml`.
- Change `--region` to your nearest ([fly.io/docs/reference/regions](https://fly.io/docs/reference/regions/));
  keep it close to the Neon region. Also update `primary_region` in `fly.toml` to match.
- When asked to add a Postgres/Redis database, **say no** — we use Neon.

### 2b. Set the database + app secrets

Use the Neon URL from Step 1. Generate a strong `SECRET_KEY` (signs session cookies):

```bash
fly secrets set \
  DATABASE_URL="postgresql+asyncpg://myuser:mypassword@ep-cool-name-123456.us-east-1.aws.neon.tech/neondb" \
  SECRET_KEY="$(openssl rand -hex 32)" \
  DASHBOARD_URL="https://vulnadvisor.vercel.app"
```

> Windows PowerShell: replace `$(openssl rand -hex 32)` with a 64-char hex string, e.g.
> `python -c "import secrets; print(secrets.token_hex(32))"`.

`DASHBOARD_URL` is where the backend sends the browser after a successful GitHub login — point it at
your Vercel URL.

### 2c. (Optional but recommended) GitHub login + PR comments

The dashboard's GitHub sign-in and the PR-comment bot need GitHub credentials. Skip this for a first
smoke test (you can still upload scans with an API key), then come back.

1. **OAuth app** (dashboard login) — <https://github.com/settings/developers> → **New OAuth App**:
   - Homepage URL: `https://vulnadvisor.vercel.app`
   - Authorization callback URL: `https://vulnadvisor-api.fly.dev/v1/auth/github/callback`
   - Copy the **Client ID** and generate a **Client secret**.

2. **GitHub App** (webhooks + PR comments) — <https://github.com/settings/apps> → **New GitHub App**:
   - Webhook URL: `https://vulnadvisor-api.fly.dev/v1/github/webhook`
   - Webhook secret: generate one (`openssl rand -hex 32`) and keep it.
   - Permissions: **Pull requests: Read & write**, **Contents: Read-only**, **Metadata: Read-only**.
   - Subscribe to events: **Pull request**, **Installation**.
   - Note the **App ID** and the **App slug** (from the app's public URL), then **Generate a private
     key** (downloads a `.pem`).

3. Set them as secrets (replace the placeholders; the private key is passed whole):

   ```bash
   fly secrets set \
     GITHUB_CLIENT_ID="Iv1.abc123" \
     GITHUB_CLIENT_SECRET="your-oauth-client-secret" \
     GITHUB_REDIRECT_URI="https://vulnadvisor-api.fly.dev/v1/auth/github/callback" \
     GITHUB_WEBHOOK_SECRET="your-webhook-secret" \
     GITHUB_APP_ID="123456" \
     GITHUB_APP_SLUG="vulnadvisor" \
     GITHUB_APP_PRIVATE_KEY="$(cat ~/Downloads/vulnadvisor.private-key.pem)"
   ```

   > Windows PowerShell: `GITHUB_APP_PRIVATE_KEY="$(Get-Content -Raw ~\Downloads\vulnadvisor.private-key.pem)"`.

### 2d. Deploy

```bash
fly deploy
```

The container runs `alembic upgrade head` on boot (creating the schema in Neon on the first deploy),
then starts uvicorn. Verify it's live:

```bash
fly status
curl https://vulnadvisor-api.fly.dev/healthz
# -> {"status":"ok","version":"0.1.0"}
```

If the health check fails, inspect logs: `fly logs`. The most common first-deploy error is a bad
`DATABASE_URL` — re-check the `postgresql+asyncpg://` scheme and that `?sslmode=...` was removed.

### 2e. Issue an API key for CI/CLI uploads (optional)

Once you've signed in to the dashboard (Step 4) and created an org, mint a key from
**Settings → API keys**, or via the API. CI then uploads reports with:

```bash
vulnadvisor scan --format json > report.json
curl -X POST https://vulnadvisor-api.fly.dev/v1/orgs/<org>/repos/<repo>/scans \
  -H "Authorization: Bearer va_xxx.yyy" \
  -H "Content-Type: application/json" \
  --data @report.json
```

---

## 3. Vercel — point the dashboard at the backend

The dashboard reads two URLs:

| Variable               | Used by                       | Value                                  |
| ---------------------- | ----------------------------- | -------------------------------------- |
| `API_URL`              | server-side rendering (SSR)   | `https://vulnadvisor-api.fly.dev`      |
| `NEXT_PUBLIC_API_URL`  | browser links (login/install) | `https://vulnadvisor-api.fly.dev`      |

Set both for the **Production** environment. Via the CLI (run inside `dashboard/`):

```bash
cd dashboard
vercel link                         # link this folder to your Vercel project (one-time)

printf 'https://vulnadvisor-api.fly.dev' | vercel env add NEXT_PUBLIC_API_URL production
printf 'https://vulnadvisor-api.fly.dev' | vercel env add API_URL production
```

Or via the UI: **Vercel → your project → Settings → Environment Variables**, add both with the
Production scope.

> Do **not** set `DASHBOARD_API_TOKEN` in production — it's a dev/preview convenience that renders the
> dashboard without an interactive login. In production, users authenticate via GitHub OAuth.

---

## 4. Redeploy Vercel to connect everything

Environment-variable changes only take effect on a new build. Trigger one:

```bash
# from dashboard/ (after `vercel link`)
vercel --prod
```

Or push any commit to the branch Vercel auto-builds, or hit **Redeploy** in the Vercel dashboard.

### Verify the full loop

1. Open <https://vulnadvisor.vercel.app> → click **Sign in with GitHub** → authorize.
2. You should be redirected back to the dashboard (this confirms `DASHBOARD_URL` on Fly and the OAuth
   callback URL are correct).
3. Install the GitHub App on a repo, or push a scan with an API key (Step 2e), then open the repo in
   the dashboard to see the **90-day trend** and the **three cards**.

---

## Re-deploying later

- **Backend:** `fly deploy` from the repo root. Migrations run automatically on boot.
- **Frontend:** push to the tracked branch (Vercel auto-builds) or `vercel --prod` from `dashboard/`.
- **Rotate a secret:** `fly secrets set NAME=value` (triggers a rolling restart).

## Troubleshooting

| Symptom                                        | Likely cause / fix                                                                 |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- |
| `/healthz` 503 / app won't boot                | Bad `DATABASE_URL`. Must be `postgresql+asyncpg://…` with **no** `?sslmode=`. `fly logs`. |
| Login redirects to `localhost:3000`            | `DASHBOARD_URL` secret not set to the Vercel URL on Fly.                            |
| OAuth "redirect_uri mismatch"                  | OAuth app callback URL ≠ `GITHUB_REDIRECT_URI` secret. Make them identical.         |
| Dashboard shows "sign in" but login works once | `NEXT_PUBLIC_API_URL`/`API_URL` not set, or Vercel not redeployed after setting them. |
| PR comments never appear                       | GitHub App not installed on the repo, or `GITHUB_WEBHOOK_SECRET` mismatch (check `fly logs`). |
| Neon "too many connections"                    | Free tier is small; the app uses a single worker. Don't raise uvicorn workers on 256MB. |
