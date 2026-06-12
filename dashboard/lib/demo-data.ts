// File: dashboard/lib/demo-data.ts
// The /demo organization (Task 14.3): a seeded, read-only dataset typed against the real
// API types so the demo pages render through the exact same components as the product.
// No I/O — demo routes import this module and never touch lib/api, which is what makes
// /demo public, auth-free, and mutation-free by construction (asserted in lib/demo.test.ts).
//
// Honesty rule: everything derivable is derived. The analytics overview and package
// ranking are computed from the findings below, so the demo can never show numbers its
// own finding cards contradict.

import type {
  AnalyticsOverview,
  Finding,
  OrgDetail,
  PackageRisk,
  Repo,
  ResolutionResponse,
  ScanDetail,
  TrendPoint,
} from "./types";

export const DEMO_ORG: OrgDetail = {
  id: "demo-org",
  slug: "demo",
  name: "Acme Robotics (demo)",
  plan: "free",
  role: "viewer",
  repo_count: 3,
  member_count: 4,
};

// ---------------------------------------------------------------------------
// Findings (the engine-output shapes the real ingest stores verbatim).
// ---------------------------------------------------------------------------

function finding(f: Finding): Finding {
  return f;
}

const JINJA2_KEV = finding({
  dependency: { name: "jinja2", version: "2.10", is_direct: true },
  advisory: {
    id: "GHSA-462w-v97r-4m45",
    display_id: "CVE-2019-10906",
    aliases: ["CVE-2019-10906", "PYSEC-2019-217"],
    summary: "Jinja2 sandbox escape via str.format_map allows execution outside the sandbox.",
    cvss_base: 8.6,
  },
  epss: { probability: 0.118, percentile: 0.95 },
  in_kev: true,
  score: {
    value: 95,
    band: "critical",
    verdict:
      "Your invoice renderer feeds customer-supplied template strings into jinja2's sandbox, and this bug lets that input escape the sandbox and run code on the billing host.",
    rationale:
      "Reachable with a confirmed call path, listed in CISA KEV (exploited in the wild), and high EPSS — the deterministic ceiling of the scale.",
  },
  reachability: {
    tier: "imported-and-called",
    reason: "A concrete call path from your code reaches the vulnerable symbol.",
    evidence: [{ file: "app/templates.py", line: 7 }],
    call_paths: [
      "app.billing.render_invoice -> app.templates.render -> jinja2.Environment.from_string (app/billing.py:48)",
    ],
  },
  fix: { command: 'uv pip install "jinja2>=2.10.1"', fixed_version: "2.10.1", has_fix: true },
});

const PYYAML_CALLED = finding({
  dependency: { name: "pyyaml", version: "5.3.1", is_direct: true },
  advisory: {
    id: "GHSA-8q59-q68h-6hv4",
    display_id: "CVE-2020-14343",
    aliases: ["CVE-2020-14343", "PYSEC-2021-142"],
    summary:
      "PyYAML full_load processes untrusted YAML into arbitrary Python object construction.",
    cvss_base: 9.8,
  },
  epss: { probability: 0.031, percentile: 0.87 },
  in_kev: false,
  score: {
    value: 82,
    band: "high",
    verdict:
      "Your settings loader parses YAML with yaml.load — a crafted config file can construct arbitrary Python objects and execute code during parsing.",
    rationale: "Confirmed call path to the vulnerable loader; no KEV listing yet.",
  },
  reachability: {
    tier: "imported-and-called",
    reason: "A concrete call path from your code reaches the vulnerable symbol.",
    evidence: [{ file: "app/config.py", line: 4 }],
    call_paths: ["app.config.load_settings -> yaml.load (app/config.py:31)"],
  },
  fix: { command: 'uv pip install "pyyaml>=5.4"', fixed_version: "5.4", has_fix: true },
});

const REQUESTS_IMPORTED = finding({
  dependency: { name: "requests", version: "2.25.0", is_direct: true },
  advisory: {
    id: "GHSA-j8r2-6x86-q33q",
    display_id: "CVE-2023-32681",
    aliases: ["CVE-2023-32681", "PYSEC-2023-74"],
    summary: "Requests leaks Proxy-Authorization headers to destination servers on redirects.",
    cvss_base: 6.1,
  },
  epss: { probability: 0.004, percentile: 0.62 },
  in_kev: false,
  score: {
    value: 55,
    band: "medium",
    verdict:
      "requests is imported by your HTTP client module; no call into the vulnerable redirect-with-proxy path was confirmed, so this stays actionable but below the confirmed-path findings.",
    rationale: "Imported with no confirmed call path — escalated over not-imported, never silently dropped.",
  },
  reachability: {
    tier: "imported",
    reason: "The vulnerable module is imported; no confirmed call to the vulnerable symbol.",
    evidence: [{ file: "app/client.py", line: 3 }],
    call_paths: [],
  },
  fix: { command: 'uv pip install "requests>=2.31.0"', fixed_version: "2.31.0", has_fix: true },
});

const URLLIB3_NOT_IMPORTED = finding({
  dependency: { name: "urllib3", version: "1.26.4", is_direct: false },
  advisory: {
    id: "GHSA-q2q7-5pp4-w6pg",
    display_id: "CVE-2021-33503",
    aliases: ["CVE-2021-33503", "PYSEC-2021-108"],
    summary: "urllib3 catastrophic backtracking in URL authority parsing (ReDoS).",
    cvss_base: 7.5,
  },
  epss: { probability: 0.002, percentile: 0.55 },
  in_kev: false,
  score: {
    value: 18,
    band: "low",
    verdict:
      "urllib3 arrives as a transitive dependency of requests and your code never imports it directly — nothing of yours reaches the vulnerable parser.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "urllib3>=1.26.5"', fixed_version: "1.26.5", has_fix: true },
});

const CERTIFI_NOT_IMPORTED = finding({
  dependency: { name: "certifi", version: "2022.12.7", is_direct: false },
  advisory: {
    id: "GHSA-xqr8-7jwr-rhp7",
    display_id: "CVE-2023-37920",
    aliases: ["CVE-2023-37920", "PYSEC-2023-135"],
    summary: "certifi shipped e-Tugra root certificates that were later distrusted.",
    cvss_base: 9.8,
  },
  epss: { probability: 0.001, percentile: 0.32 },
  in_kev: false,
  score: {
    value: 12,
    band: "low",
    verdict:
      "certifi is a transitive certificate bundle your code never imports directly; the distrusted roots matter only to code that loads this bundle.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: {
    command: 'uv pip install "certifi>=2023.7.22"',
    fixed_version: "2023.7.22",
    has_fix: true,
  },
});

// Present in the previous payments-api scan, fixed since — feeds the resolution story.
const FLASK_FIXED_SINCE = finding({
  dependency: { name: "flask", version: "2.0.1", is_direct: true },
  advisory: {
    id: "GHSA-m2qf-hxjv-5gpq",
    display_id: "CVE-2023-30861",
    aliases: ["CVE-2023-30861", "PYSEC-2023-62"],
    summary: "Flask may cache responses containing session cookies behind certain proxies.",
    cvss_base: 7.5,
  },
  epss: { probability: 0.006, percentile: 0.68 },
  in_kev: false,
  score: {
    value: 60,
    band: "medium",
    verdict:
      "Flask serves your API responses; behind a caching proxy this bug can leak one user's session cookie into another user's cached response.",
    rationale: "Imported with no confirmed call path into the vulnerable caching branch.",
  },
  reachability: {
    tier: "imported",
    reason: "The vulnerable module is imported; no confirmed call to the vulnerable symbol.",
    evidence: [{ file: "app/web.py", line: 1 }],
    call_paths: [],
  },
  fix: { command: 'uv pip install "flask>=2.3.2"', fixed_version: "2.3.2", has_fix: true },
});

const PILLOW_IMPORTED = finding({
  dependency: { name: "pillow", version: "9.4.0", is_direct: true },
  advisory: {
    id: "GHSA-3f63-hfp8-52jq",
    display_id: "CVE-2023-50447",
    aliases: ["CVE-2023-50447", "PYSEC-2024-23"],
    summary: "Pillow PIL.ImageMath.eval evaluates crafted environment keys as code.",
    cvss_base: 8.1,
  },
  epss: { probability: 0.022, percentile: 0.83 },
  in_kev: false,
  score: {
    value: 72,
    band: "high",
    verdict:
      "Pillow processes every thumbnail in the pipeline; the vulnerable ImageMath.eval is in the imported package, though no call from your code was confirmed.",
    rationale: "Imported, high EPSS — kept loud until a call path is ruled in or out.",
  },
  reachability: {
    tier: "imported",
    reason: "The vulnerable module is imported; no confirmed call to the vulnerable symbol.",
    evidence: [{ file: "etl/thumbnails.py", line: 5 }],
    call_paths: [],
  },
  fix: { command: 'uv pip install "pillow>=10.2.0"', fixed_version: "10.2.0", has_fix: true },
});

const LXML_DYNAMIC = finding({
  dependency: { name: "lxml", version: "4.9.0", is_direct: true },
  advisory: {
    id: "GHSA-wrxv-2j5q-m38w",
    display_id: "CVE-2022-2309",
    aliases: ["CVE-2022-2309", "PYSEC-2022-230"],
    summary: "lxml NULL-pointer dereference when parsing crafted input in the iterwalk API.",
    cvss_base: 7.5,
  },
  epss: { probability: 0.003, percentile: 0.58 },
  in_kev: false,
  score: {
    value: 58,
    band: "medium",
    verdict:
      "Your loader plugins are imported with importlib.import_module from a config value, so static analysis cannot prove whether the lxml parser is reached — this stays unresolved, never silently safe.",
    rationale: "Dynamic import blocks certainty — escalated to actionable per the soundness rules.",
  },
  reachability: {
    tier: "dynamic-unknown",
    reason:
      "Dynamic import (importlib.import_module in etl/plugins.py:19) prevents proving or ruling out a path to the vulnerable symbol.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "lxml>=4.9.1"', fixed_version: "4.9.1", has_fix: true },
});

const IDNA_NOT_IMPORTED = finding({
  dependency: { name: "idna", version: "3.4", is_direct: false },
  advisory: {
    id: "GHSA-jjg7-2v4v-x38h",
    display_id: "CVE-2024-3651",
    aliases: ["CVE-2024-3651", "PYSEC-2024-60"],
    summary: "idna quadratic-complexity denial of service on crafted hostnames.",
    cvss_base: 6.2,
  },
  epss: { probability: 0.001, percentile: 0.28 },
  in_kev: false,
  score: {
    value: 14,
    band: "low",
    verdict:
      "idna is a transitive dependency the pipeline never imports directly — nothing reaches the vulnerable encoder.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "idna>=3.7"', fixed_version: "3.7", has_fix: true },
});

const PYGMENTS_NOT_IMPORTED = finding({
  dependency: { name: "pygments", version: "2.11.0", is_direct: false },
  advisory: {
    id: "GHSA-mrwq-x4v8-fh7p",
    display_id: "CVE-2022-40896",
    aliases: ["CVE-2022-40896", "PYSEC-2023-117"],
    summary: "Pygments SmithyLexer catastrophic backtracking (ReDoS) on crafted input.",
    cvss_base: 5.5,
  },
  epss: { probability: 0.001, percentile: 0.21 },
  in_kev: false,
  score: {
    value: 10,
    band: "low",
    verdict:
      "pygments rides in with a doc tool and is never imported by the pipeline code itself.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "pygments>=2.15.0"', fixed_version: "2.15.0", has_fix: true },
});

const WERKZEUG_NOT_IMPORTED = finding({
  dependency: { name: "werkzeug", version: "2.2.2", is_direct: false },
  advisory: {
    id: "GHSA-2g68-c3qc-8985",
    display_id: "CVE-2024-34069",
    aliases: ["CVE-2024-34069", "PYSEC-2024-58"],
    summary: "Werkzeug debugger can be tricked into executing code under certain conditions.",
    cvss_base: 7.1,
  },
  epss: { probability: 0.005, percentile: 0.65 },
  in_kev: false,
  score: {
    value: 25,
    band: "low",
    verdict:
      "werkzeug is pulled in by a dev dependency and never imported by these CLI tools — the debugger never runs here.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "werkzeug>=3.0.3"', fixed_version: "3.0.3", has_fix: true },
});

const CRYPTOGRAPHY_NOT_IMPORTED = finding({
  dependency: { name: "cryptography", version: "41.0.0", is_direct: false },
  advisory: {
    id: "GHSA-jfhm-5ghh-2f97",
    display_id: "CVE-2023-49083",
    aliases: ["CVE-2023-49083", "PYSEC-2023-254"],
    summary: "cryptography NULL-pointer dereference when loading crafted PKCS#7 certificates.",
    cvss_base: 5.9,
  },
  epss: { probability: 0.002, percentile: 0.49 },
  in_kev: false,
  score: {
    value: 20,
    band: "low",
    verdict:
      "cryptography is transitive here and these tools never import it — no path to the PKCS#7 loader exists.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: {
    command: 'uv pip install "cryptography>=41.0.6"',
    fixed_version: "41.0.6",
    has_fix: true,
  },
});

const AIOHTTP_NOT_IMPORTED = finding({
  dependency: { name: "aiohttp", version: "3.8.4", is_direct: false },
  advisory: {
    id: "GHSA-q3qx-c6g2-7pw2",
    display_id: "CVE-2023-49081",
    aliases: ["CVE-2023-49081", "PYSEC-2023-246"],
    summary: "aiohttp HTTP request smuggling via crafted version strings.",
    cvss_base: 7.5,
  },
  epss: { probability: 0.003, percentile: 0.57 },
  in_kev: false,
  score: {
    value: 22,
    band: "low",
    verdict:
      "aiohttp ships with an async helper library these synchronous tools never import.",
    rationale: "Not imported anywhere in the scanned code — confidently deprioritized.",
  },
  reachability: {
    tier: "not-imported",
    reason: "The package is never imported by the scanned code.",
    evidence: [],
    call_paths: [],
  },
  fix: { command: 'uv pip install "aiohttp>=3.9.0"', fixed_version: "3.9.0", has_fix: true },
});

// ---------------------------------------------------------------------------
// Scans + repos (dates computed relative to "now" so the demo never looks stale).
// ---------------------------------------------------------------------------

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

function summarize(findings: Finding[]): { total: number; by_band: Record<string, number> } {
  const by_band: Record<string, number> = {};
  for (const f of findings) by_band[f.score.band] = (by_band[f.score.band] ?? 0) + 1;
  return { total: findings.length, by_band };
}

export interface DemoScan {
  detail: ScanDetail;
  findings: Finding[];
  repo: string;
}

function demoScan(
  id: string,
  repo: string,
  sha: string,
  createdDaysAgo: number,
  findings: Finding[],
): DemoScan {
  return {
    repo,
    findings,
    detail: {
      id,
      repo_id: `demo-${repo}`,
      commit_sha: sha,
      ref: "refs/heads/main",
      pr_number: null,
      source: "ci",
      status: "complete",
      tool_version: "0.9.0",
      degraded_sources: [],
      summary: summarize(findings),
      created_at: daysAgo(createdDaysAgo),
    },
  };
}

const PAYMENTS_LATEST = demoScan(
  "demo-scan-payments-2",
  "payments-api",
  "8f4e2a17c9b35d60a1e8f72b4c5d9013a6b8e2f4",
  1,
  [JINJA2_KEV, PYYAML_CALLED, REQUESTS_IMPORTED, URLLIB3_NOT_IMPORTED, CERTIFI_NOT_IMPORTED],
);

const PAYMENTS_PREVIOUS = demoScan(
  "demo-scan-payments-1",
  "payments-api",
  "3b9d6c0fa2e84715d3c6b9f01a4e7d28c5f0a9b1",
  6,
  [
    JINJA2_KEV,
    PYYAML_CALLED,
    FLASK_FIXED_SINCE,
    REQUESTS_IMPORTED,
    URLLIB3_NOT_IMPORTED,
    CERTIFI_NOT_IMPORTED,
  ],
);

const ETL_LATEST = demoScan(
  "demo-scan-etl-1",
  "etl-pipeline",
  "c71a5e93b2d04f86a9c3e1b75d8f2406b9e4c7a2",
  2,
  [PILLOW_IMPORTED, LXML_DYNAMIC, IDNA_NOT_IMPORTED, PYGMENTS_NOT_IMPORTED],
);

const TOOLS_LATEST = demoScan(
  "demo-scan-tools-1",
  "internal-tools",
  "e2c8b417f5a90d63c1b7e4a28f5d90c3a7b1e6d9",
  3,
  [WERKZEUG_NOT_IMPORTED, AIOHTTP_NOT_IMPORTED, CRYPTOGRAPHY_NOT_IMPORTED],
);

export const DEMO_SCANS: DemoScan[] = [
  PAYMENTS_LATEST,
  PAYMENTS_PREVIOUS,
  ETL_LATEST,
  TOOLS_LATEST,
];

/** Latest scan per repo — the basis for every org-level aggregate, like the real API. */
const LATEST_SCANS: DemoScan[] = [PAYMENTS_LATEST, ETL_LATEST, TOOLS_LATEST];

/** The scan the product tour's "open a finding" leg lands on. */
export const DEMO_TOUR_SCAN_ID = PAYMENTS_LATEST.detail.id;

export const DEMO_REPOS: Repo[] = [
  {
    id: "demo-payments-api",
    name: "payments-api",
    default_branch: "main",
    is_private: true,
    scan_count: 2,
    last_scan_at: PAYMENTS_LATEST.detail.created_at,
    github_linked: true,
    setup_status: "receiving-scans",
    setup_pr_url: null,
  },
  {
    id: "demo-etl-pipeline",
    name: "etl-pipeline",
    default_branch: "main",
    is_private: true,
    scan_count: 1,
    last_scan_at: ETL_LATEST.detail.created_at,
    github_linked: true,
    setup_status: "receiving-scans",
    setup_pr_url: null,
  },
  {
    id: "demo-internal-tools",
    name: "internal-tools",
    default_branch: "main",
    is_private: false,
    scan_count: 1,
    last_scan_at: TOOLS_LATEST.detail.created_at,
    github_linked: true,
    setup_status: "receiving-scans",
    setup_pr_url: null,
  },
];

export function demoRepo(name: string): Repo | null {
  return DEMO_REPOS.find((r) => r.name === name) ?? null;
}

export function demoScansForRepo(name: string): DemoScan[] {
  return DEMO_SCANS.filter((s) => s.repo === name).sort((a, b) =>
    b.detail.created_at.localeCompare(a.detail.created_at),
  );
}

export function demoScanById(id: string): DemoScan | null {
  return DEMO_SCANS.find((s) => s.detail.id === id) ?? null;
}

// ---------------------------------------------------------------------------
// Analytics — derived from the findings, mirroring the platform's semantics:
// only `not-imported` deprioritizes; everything else is actionable.
// ---------------------------------------------------------------------------

const ACTIONABLE = (f: Finding) => (f.reachability?.tier ?? "unknown") !== "not-imported";

export const DEMO_OVERVIEW: AnalyticsOverview = (() => {
  const all = LATEST_SCANS.flatMap((s) => s.findings);
  const by_band: Record<string, number> = {};
  const by_tier: Record<string, number> = {};
  for (const f of all) {
    by_band[f.score.band] = (by_band[f.score.band] ?? 0) + 1;
    const tier = f.reachability?.tier ?? "unknown";
    by_tier[tier] = (by_tier[tier] ?? 0) + 1;
  }
  return {
    org_id: DEMO_ORG.id,
    repo_count: DEMO_REPOS.length,
    repos_at_risk: LATEST_SCANS.filter((s) => s.findings.some(ACTIONABLE)).length,
    total_findings: all.length,
    actionable: all.filter(ACTIONABLE).length,
    deprioritized: all.filter((f) => !ACTIONABLE(f)).length,
    reachable_called: all.filter((f) => f.reachability?.tier === "imported-and-called").length,
    kev_count: all.filter((f) => f.in_kev).length,
    by_band,
    by_tier,
  };
})();

export const DEMO_PACKAGES: PackageRisk[] = (() => {
  const byPackage = new Map<string, { findings: Finding[]; repos: Set<string>; scan: string }>();
  for (const scan of LATEST_SCANS) {
    for (const f of scan.findings) {
      const entry = byPackage.get(f.dependency.name) ?? {
        findings: [],
        repos: new Set<string>(),
        scan: scan.detail.id,
      };
      entry.findings.push(f);
      entry.repos.add(scan.repo);
      byPackage.set(f.dependency.name, entry);
    }
  }
  return Array.from(byPackage.entries())
    .map(([pkg, entry]) => {
      const top = entry.findings.reduce((a, b) => (b.score.value > a.score.value ? b : a));
      return {
        package: pkg,
        max_priority: top.score.value,
        band: top.score.band,
        finding_count: entry.findings.length,
        repo_count: entry.repos.size,
        top_scan_id: entry.scan,
      };
    })
    .sort((a, b) => b.max_priority - a.max_priority)
    .slice(0, 8);
})();

// Trend: a plausible 90-day history whose final point matches today's derived totals,
// so the chart never contradicts the KPI strip.
function trendSeries(
  shape: [daysBack: number, actionable: number, deprioritized: number, called: number][],
): TrendPoint[] {
  return shape.map(([back, actionable, deprioritized, called]) => ({
    date: daysAgo(back).slice(0, 10),
    actionable,
    deprioritized,
    reachable_called: called,
  }));
}

export const DEMO_ORG_TREND: TrendPoint[] = trendSeries([
  [88, 9, 3, 4],
  [74, 9, 4, 4],
  [60, 8, 5, 3],
  [46, 8, 5, 3],
  [32, 7, 6, 3],
  [18, 6, 6, 2],
  [6, 6, 7, 2],
  [1, DEMO_OVERVIEW.actionable, DEMO_OVERVIEW.deprioritized, DEMO_OVERVIEW.reachable_called],
]);

export const DEMO_REPO_TRENDS: Record<string, TrendPoint[]> = {
  "payments-api": trendSeries([
    [88, 5, 1, 3],
    [60, 4, 2, 2],
    [32, 4, 2, 2],
    [6, 4, 2, 2],
    [1, 3, 2, 2],
  ]),
  "etl-pipeline": trendSeries([
    [74, 3, 1, 1],
    [46, 3, 2, 1],
    [18, 2, 2, 0],
    [2, 2, 2, 0],
  ]),
  "internal-tools": trendSeries([
    [60, 1, 2, 0],
    [32, 0, 3, 0],
    [3, 0, 3, 0],
  ]),
};

export const DEMO_RESOLUTION: ResolutionResponse = {
  org_id: DEMO_ORG.id,
  overall: { resolved_count: 3, median_days: 4.5 },
  bands: {
    critical: { resolved_count: 0, median_days: null },
    high: { resolved_count: 1, median_days: 6 },
    medium: { resolved_count: 2, median_days: 4 },
    low: { resolved_count: 0, median_days: null },
    info: { resolved_count: 0, median_days: null },
  },
};
