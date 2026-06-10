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
}

export interface ScanSummary {
  total?: number;
  by_band?: Record<string, number>;
}

export interface ScanListItem {
  id: string;
  commit_sha: string;
  ref: string;
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
  commit_sha: string;
  ref: string;
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

export interface DiffResponse {
  from_scan_id: string;
  to_scan_id: string;
  introduced: Finding[];
  fixed: Finding[];
  unchanged: number;
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
