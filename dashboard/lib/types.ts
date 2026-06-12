// Types mirroring the VulnAdvisor platform API (read endpoints).

export interface Org {
  id: string;
  slug: string;
  name: string;
  plan: string;
  role: string;
}

export interface OrgDetail extends Org {
  repo_count: number;
  member_count: number;
}

export interface Repo {
  id: string;
  name: string;
  default_branch: string;
  is_private: boolean;
  scan_count: number;
  last_scan_at: string | null;
  // Onboarding (Task 14.2): "not-set-up" | "pr-open" | "pr-merged" | "receiving-scans".
  github_linked: boolean;
  setup_status: string;
  setup_pr_url: string | null;
}

// Result of POST /v1/orgs/{org}/repos/{repo}/setup-pr (Task 14.2).
export interface SetupPrResponse {
  pr_number: number;
  pr_url: string;
  created: boolean;
}

export interface ScanSummary {
  total?: number;
  by_band?: Record<string, number>;
}

export interface ScanListItem {
  id: string;
  commit_sha: string | null;
  ref: string | null;
  pr_number: number | null;
  source: string;
  status: string;
  tool_version: string;
  summary: ScanSummary;
  created_at: string;
}

export interface ScanPage {
  items: ScanListItem[];
  next_cursor: string | null;
}

export interface ScanDetail {
  id: string;
  repo_id: string;
  commit_sha: string | null;
  ref: string | null;
  pr_number: number | null;
  source: string;
  status: string;
  tool_version: string;
  degraded_sources: string[];
  summary: ScanSummary;
  created_at: string;
}

export interface Finding {
  dependency: { name: string; version: string | null; source?: string; is_direct?: boolean };
  advisory: {
    id: string;
    display_id?: string;
    aliases?: string[];
    cve_ids?: string[];
    summary?: string | null;
    cvss_base?: number | null;
  };
  epss: { probability: number; percentile: number } | null;
  in_kev: boolean;
  score: { value: number; band: string; verdict: string; rationale: string; cvss_known?: boolean };
  reachability: {
    tier: string;
    reason: string;
    evidence?: { file: string; line: number }[];
    call_paths?: string[];
  } | null;
  fix: { command: string | null; fixed_version: string | null; has_fix: boolean };
}

export interface FindingsResponse {
  scan_id: string;
  count: number;
  findings: Finding[];
}

export interface TrendPoint {
  date: string;
  actionable: number;
  deprioritized: number;
  reachable_called: number;
}

export interface TrendResponse {
  repo_id: string;
  window_days: number;
  points: TrendPoint[];
}

// Org analytics (Task 13.3 endpoints).

export interface AnalyticsOverview {
  org_id: string;
  repo_count: number;
  repos_at_risk: number;
  total_findings: number;
  actionable: number;
  deprioritized: number;
  reachable_called: number;
  kev_count: number;
  by_band: Record<string, number>;
  by_tier: Record<string, number>;
}

export interface OrgTrendResponse {
  org_id: string;
  window_days: number;
  points: TrendPoint[];
}

export interface PackageRisk {
  package: string;
  max_priority: number;
  band: string;
  finding_count: number;
  repo_count: number;
  top_scan_id: string | null;
}

export interface PackagesResponse {
  org_id: string;
  packages: PackageRisk[];
}

export interface ResolutionStats {
  resolved_count: number;
  median_days: number | null;
}

export interface ResolutionResponse {
  org_id: string;
  overall: ResolutionStats;
  bands: Record<string, ResolutionStats>;
}

export interface DiffResponse {
  from_scan_id: string;
  to_scan_id: string;
  introduced: Finding[];
  fixed: Finding[];
  unchanged: number;
}

// Device-flow activation (Task 14.1).

export interface DeviceApproved {
  user_code: string;
  org_slug: string;
  client_name: string | null;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

// Returned only once, at creation — the only time the full secret is exposed.
export interface ApiKeyCreated {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  secret: string;
}
