# VulnAdvisor — M12+ Strategy: Critical Review, Stack Decisions, Market Positioning

> Companion to the new `task.md` (M12–M18). This is the *why*; `task.md` is the *what/when*.
> Written 2026-06-10, after M11 closed.

---

## 0. Inputs

Positioning below draws on two sources: the maintainer's Gemini Deep Research report
(`Comprehensive Market Analysis.txt` — restored 2026-06-10 after an earlier mis-save; cited
as *[Gemini]*) and fresh June-2026 web research (links at the bottom). Where the two
disagree with this plan's direction, the disagreement is called out explicitly (§4a).

---

## 1. Critical review of the current architecture

### What is genuinely strong (protect it)

- **The engine is the asset.** Sound confidence tiers, deterministic scoring, demand-driven
  call graph with framework entry-point plugins (FastAPI/Django), the advisory→symbol dataset,
  defensive parsing everywhere, 390 passing tests, `mypy --strict` clean. This is rare
  discipline for a pre-seed codebase and it is exactly what makes the SAST pivot *cheap* (§3).
- **The trust posture.** Local-first, no telemetry, bring-your-own-analysis platform (only the
  JSON report is uploaded, never source). Every competitor that matters is cloud-first and
  closed. This is the wedge — do not erode it casually.
- **Clean separation.** CLI wheel ships 3 runtime deps; platform deps live in a non-shipping
  group; dashboard is a separate Vercel deployable. The free-tier hosting story
  (Vercel + Neon + Fly/Render) holds.

### What is weak (the honest list)

1. **The dashboard is an internal tool wearing a product's URL.** Hand-rolled CSS on raw
   Tailwind, no design system, no iconography, no motion, a dependency-free SVG chart that
   cannot grow into analytics. "Read-only over the API" was the right M11 scope; it is not a
   fundable face.
2. **Display-layer correctness bugs that read as carelessness** (fatal in a *security* product):
   - **"0000000 main"** on scan rows: the CLI upload defaults `commit_sha` to a placeholder;
     `shortSha()` happily renders seven zeros next to the ref. Root cause is in the upload
     default, not the UI — fix it at the source (auto-detect git metadata; render an honest
     "local scan" badge when absent).
   - **`django==4.2.29PYSEC-2026-52`**: the finding header concatenates `name==version` flush
     against the advisory id with no canonical display identity. We need a *single*
     `display_id` rule (CVE-first, alias-aware) used by terminal, JSON, dashboard, and PR
     comments — not four ad-hoc formats.
   - **Attack story truncation**: Card A lives in a one-third grid cell; LLM stories are
     paragraphs. The three-card metaphor is right; the fixed-size layout is wrong. Cards must
     be progressive-disclosure (collapsed verdict → expandable full story).
3. **Onboarding is a funnel with no floor.** Today's first-value path: read README → install
   CLI → sign in → mint API key → copy it → re-run scan with flags → refresh dashboard. That is
   seven steps and two context switches. The GitHub App exists but installing it is
   self-service archaeology. Target: **under 3 minutes, one context, zero copy-paste**.
4. **No aggregate analytics.** The read API serves entities (orgs/repos/scans/findings) and a
   single trend endpoint. There is no severity distribution, tier split, top-risky-packages,
   or fix-latency surface — nothing a VP of Eng screenshots into a board deck.
5. **Scope ends at third-party packages.** The market is converging on "SCA + SAST + AI fix"
   platforms (§4). We have the hardest part of a Python SAST engine already built (call graph,
   entry points, soundness discipline) and currently sell none of it.

### Tensions to manage in this phase (decided up front)

- **Privacy vs. LLM fixes.** Fix suggestions require code context. Resolution: fixes are
  generated *where the code already lives* (the user's CI runner or laptop, via the CLI with
  the user's own key) by default. Any cloud-side code access is per-org opt-in
  (`allow_code_upload`), loudly documented. Privacy stays a feature, not a casualty.
- **Soundness vs. SAST noise.** Taint analysis is famously FP-prone. We apply the same rule as
  reachability: never binary, always tiered (`CONFIRMED-FLOW` / `POSSIBLE-FLOW` /
  `DYNAMIC-UNKNOWN` / `SANITIZED`), evidence always shown, and the fixture gate keeps zero
  false negatives release-blocking.
- **Free tier vs. growth.** Neon free = 0.5 GB; findings payloads are JSONB-verbatim. Add
  retention/compaction before it bites (M13.3 gate). Render/Fly free instances sleep — the
  onboarding flow must tolerate cold starts (loading states, not errors).
- **Speed vs. depth.** *[Gemini]* is blunt and right: CI is a constrained environment, and
  Rust-based rivals (pyscan: ~6.9 s / ~45 MB where pip-audit takes 60 s / 433 MB) plus
  Astral's `uv audit`+`ty` roadmap make raw speed an existential axis. If a scan adds minutes
  to CI, accuracy won't save it. Consequence in the plan: incremental caching is treated as
  load-bearing, and M16.5's gate includes an explicit wall-time budget benchmarked against
  pyscan — published, not hand-waved.

---

## 2. Stack recommendations (free, premium-capable)

Keep the foundation — Next.js 16 + React 19 + Tailwind v4, FastAPI + Postgres, Typer CLI —
it is modern and right. Add, don't replace:

| Need | Choice | Why (and why not alternatives) |
|---|---|---|
| Design system | **shadcn/ui** (+ Radix primitives) | Copy-in components, zero runtime lock-in, MIT, the de-facto premium look in 2026. Full theme control beats MUI/Mantine's opinions. |
| Charts | **shadcn charts (Recharts under the hood)** | Donut/area/bar with the same design tokens as the rest of the UI. Tremor was the alternative; shadcn charts win on theme consistency. |
| Icons | **lucide-react** | Pairs with shadcn; consistent stroke weight. |
| Typography | **Geist Sans + Geist Mono** (next/font) | Premium-neutral; mono variant flatters CVE ids, SHAs, call paths. |
| Motion | **motion** (Framer Motion) | Micro-interactions only: card expand, chart entrance, status pulse. No scroll-jacking. |
| Product tour | **driver.js** | ~5 kB, MIT, no React lock-in; react-joyride is heavier and stagnant. |
| Chat/agent UI | **Vercel AI SDK** (`ai` package) | Streaming, tool-use, Anthropic provider, runs on Vercel free tier as a route handler. |
| Client data (interactive views only) | **TanStack Query** | Keep RSC for reads; Query only where the UI mutates/polls (chat, onboarding wizard). |
| SAST engine | **Our own, on stdlib `ast` + the existing call graph** | This is the moat. Adopting Semgrep's engine would surrender differentiation and inherit its weakness (no cross-file taint in OSS, weak dynamic-Python handling). Bandit is used as the *benchmark comparator*, not a component. |
| LLM fixes | **Anthropic API, structured outputs (pydantic)** | Already the explanation layer; same BYO-key trust model. Agent loop is ~200 lines, not a framework. |
| Hosting | unchanged: Vercel + Neon + Fly/Render | All free tiers hold through M18 with the retention task. |

Visual direction — the "security vibe" without the clichés: keep the `#0d1117` family, deepen
the base (`#0a0e14`), one guarded accent (cyan-green `#2dd4bf`-ish) used *only* for
protected/safe states, red strictly for confirmed risk. A faint radar-grid texture, a
shield-status hero ("Protected — 3 reachable findings under watch"), generous whitespace,
`⌘K` command palette. The aesthetic of a SOC console, not a crypto landing page.

---

## 3. The pivot, sharpened: "reachability-aware SAST + validated fixes"

The user-facing pitch for M16–M17, and why it is *defensible*:

Every SAST tool can find `yaml.load(request.data)`. VulnAdvisor is positioned to be the only
open tool that (a) proves the flow from a real framework entry point using the **same call
graph** that powers dependency reachability, (b) ranks it with the **same deterministic
engine** so first-party and third-party risk live on one prioritized list, and (c) ships a fix
that is **machine-validated** (patch applies → lint/type/tests pass → re-scan proves the
finding is gone) rather than vibes-based autofix. CodeRabbit reviews diffs without an engine
under it; Corgea/ZeroPath have engines but are closed, cloud-only, and code leaves the
machine. Nobody owns "open-source, local-first, Python-deep, unified SCA+SAST with evidence."

The build cost is low *because* of M0–M10: sources = the framework entry-point plugins we
already have; propagation = the demand-driven call graph we already have; ranking = the engine
we already have. The new work is the taint rule pack and the validation harness.

---

## 4. Market intelligence (Gemini Deep Research + June-2026 web research)

*[Gemini]'s verdict on novelty, verbatim in spirit:* the reachability concept is the ASPM
battleground, not novel — but VulnAdvisor's specific architecture (four-tier confidence
escalation, deterministic EPSS/KEV scoring, local-first dataset backfill, strict separation
of LLM narrative from deterministic gating) is "distinct, defensible novelty within the
Python ecosystem." The open-core GTM (free CLI → platform tier) is "the most lucrative
capitalization strategy in the cybersecurity startup sector" (Semgrep/Snyk precedent).

- **Endor Labs** — function-level reachability across 40+ languages, claims up to 97% noise
  reduction. Closed, enterprise-priced, cloud. *Gap we exploit: open-source + local-first +
  Python depth; Endor is a breadth play.*
- **Snyk** — reachability for Java/JS/Python, proprietary DB (claims CVEs ~47 days before
  NVD). Noise complaints persist; closed. *Gap: evidence-first UX (they hide the why), trust.*
- **Semgrep** — reachability built on its SAST engine, so it **cannot scan dependency code**:
  direct-deps-only reachability, documented weakness on dynamic Python. *Gap: our tiered
  soundness on exactly the dynamic-Python cases they punt on.*
- **Socket** — supply-chain-attack behavioral focus, not reachability depth. Different lane.
- **Aikido** — broad AppSec bundle + AutoFix; reviewers rate its reachability below Endor's.
  *Gap: depth and proof.*
- **CodeRabbit / Qodo / Bugbot** — AI PR review; CodeRabbit's Autofix (early access 2026)
  spawns an agent to commit fixes, Pro-only. None are grounded in a reachability engine; FP
  rate is the #1 complaint category. *Gap: engine-grounded suggestions + validation harness.*
- **Corgea / ZeroPath** — AI-native SAST with autofix (Corgea claims +90% fix accuracy;
  ZeroPath claims 2x findings at 75% fewer FPs). Both closed, cloud-only. *Gap: open-source,
  BYO-key, code-never-leaves. Also: their accuracy claims are self-reported — our published,
  reproducible benchmark harness (M18) is itself a differentiator.*

Direct CLI-arena threats *[Gemini]* — the ones that can hurt us fastest:

- **pyscan (Rust)** — ~6.9 s / ~45 MB scans, single async OSV batch query, now shipping
  import-level reachability *heuristics*. It owns the speed axis. *Gap we exploit:
  heuristics vs our proven call paths and tiered soundness — but we must publish honest
  wall-time numbers next to theirs (M16.5/M18.1) or lose the CI argument by default.*
- **`uv audit` + `ty` (Astral)** — the package manager under our own product has a stated
  roadmap toward Rust-native static reachability. If the package manager does reachability
  natively, third-party scanners get squeezed. *Response: depth they won't build soon
  (function-level paths, symbol dataset, taint/SAST, validated fixes) and PR-native delivery;
  watch this roadmap every quarter.*
- **ca9** — the architectural twin: local-first, AST import tracing, OSV cache, tiered
  verdicts (REACHABLE / UNREACHABLE-static / UNREACHABLE-dynamic / INCONCLUSIVE), **dynamic
  runtime evidence via coverage.py**, and an **MCP server** so Claude/Cursor can triage.
  *Gaps we exploit: our function-level dataset moat, deterministic EPSS/KEV scoring, and the
  platform/PR layer. Gaps THEY expose in us: coverage overlay and MCP — both now in task.md
  (16.6, 15.3) so the twin has no feature we lack.*
- **OX Security / Black Duck** — runtime-correlated "code projection" and legacy SCA + BDSA
  respectively; both enterprise-heavy, Java-centric reachability. Different buyer.
- **Pattern across the market:** teams stack tools (CodeRabbit + SonarQube + Snyk). The wedge
  is not "another scanner" — it is *one deterministic priority list with evidence, from one
  engine, that ends in a validated fix.*

### 4a. Where the Gemini report disagrees with this plan — and the ruling

*[Gemini]* recommends **abandoning the Next.js dashboard** ("dashboard fatigue… dangerously
oversaturated, bordering on useless") in favor of a headless API + GitHub App only. The
maintainer's directive is the opposite: a premium UI overhaul. Ruling — both are partly
right, and the plan threads them:

1. **PR-first delivery is the law.** The report is correct that developers act where they
   code. M14 therefore makes the GitHub App + setup-PR the primary onboarding path, and M17
   puts fixes in-line in PRs. A developer must get full value without ever opening the
   dashboard.
2. **The dashboard's buyer is not the developer.** It exists for the security lead, the VP
   screenshotting analytics into a board deck, and the investor demo — the open-core
   monetization layer *[Gemini]* itself endorses (inter-project aggregation, RBAC, policy)
   needs a face. A fundable startup demos a product, not a JSON endpoint.
3. **Cost containment.** The M13 design-system approach (shadcn copy-in, one chart kit, free
   hosting) caps the frontend engineering tax the report warns about. If traction data ever
   shows the dashboard unused while PR comments thrive, M13's scope is the first to cut.

### 4b. Engine roadmap items the report adds (now in task.md)

- **Coverage overlay** (Task 16.6): ingest `coverage.py` JSON to resolve `DYNAMIC-UNKNOWN`
  with runtime evidence — static structure + dynamic truth, the report's #1 "tremendous
  improvement" and ca9 parity.
- **Framework entry-point breadth** (Task 16.3): Celery `@task`, Flask blueprints, Django
  signals as recognized entry points — missing entry points are catastrophic false negatives.
- **Cross-file taint** — the report's #3 improvement is exactly M16. Independent validation
  of the pivot.
- **FFI/native-extension awareness** (noted in 16.1 design doc as explicit scope decision):
  calls crossing into C/Rust extensions must escalate, never silently terminate the trace.
  Full cross-language call graphs (PyXSieve-style) are out of scope this phase.
- **MCP server** (Task 15.3): expose findings/triage as MCP tools for Claude Code/Cursor —
  cheap, on-trend, and closes ca9's only unique feature.

The moat narrative for investors (bake into every demo): (1) the advisory→vulnerable-symbol
dataset compounds with usage; (2) the unified call graph powers SCA *and* SAST — replicating
it means rebuilding both; (3) trust posture that incumbents structurally can't copy without
cannibalizing their cloud platforms.

**Sources:**
[Endor Labs — Top 10 SCA tools 2026](https://www.endorlabs.com/learn/best-sca-tools-05b7a) ·
[Socket — Comparing reachability analysis providers](https://socket.dev/blog/comparing-reachability-analysis-providers) ·
[Coana — Comparing reachability providers](https://www.coana.tech/resources/article/comparing-reachability-analysis-providers) ·
[AppSec Santa — Socket alternatives 2026](https://appsecsanta.com/sca-tools/socket-alternatives) ·
[Aikido — CodeRabbit alternatives 2026](https://www.aikido.dev/blog/coderabbit-alternatives) ·
[CodeAnt — Best AI code review tools 2026](https://www.codeant.ai/blogs/best-ai-code-review-tools) ·
[Corgea — AI SAST](https://corgea.com/products/ai-sast/) ·
[ZeroPath](https://zeropath.com/) ·
[Arnica — Top agentic SAST tools 2026](https://www.arnica.io/blog/top-6-ai-sast-tools-for-2026-the-quick-guide-to-agentic-static-application-security-testing)

---

## 5. Sequencing rationale (why task.md is ordered this way)

M12 (correctness) before beauty: shipping a redesign on top of "0000000 main" polishes a bug.
M13 (design system + analytics) is one milestone because charts must be born inside the design
system, not retrofitted. M14 (onboarding) lands once the product is worth onboarding into.
M15 (copilot) is small and reuses the read API; it also pressure-tests prompt-injection
defenses *before* the fix agent exists. M16–M17 (SAST → fix agent) is the pivot, deliberately
late enough that the engine work is uninterrupted and early enough to headline the M18 launch.
If a fundraising conversation needs the SAST story sooner, M15 swaps after M16 with no
dependency breakage — that is the only safe reordering.
