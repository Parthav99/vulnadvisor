// File: dashboard/lib/copilot-ui.ts
// Pure helpers for the copilot UI (Task 15.2) — org/context derivation from the pathname,
// suggested prompts, and the deep-link contract that ties a cited finding to its expanded
// card. No React, no window: unit-tested in lib/copilot-ui.test.ts and shared by the panel
// (link building) and the scan page (focus matching), so the two never drift.

/** Suggested prompts shown in an empty conversation. */
export const SUGGESTED_PROMPTS: readonly string[] = [
  "What should I fix first?",
  "Why is this deprioritized?",
  "Explain this call path",
];

/** The org slug if the path is under an org, else null (the launcher needs an org). */
export function orgSlugFromPathname(pathname: string): string | null {
  const m = /^\/orgs\/([^/]+)(?:\/|$)/.exec(pathname);
  return m ? decodeURIComponent(m[1]) : null;
}

/** Short human label for the "current page" context chip + the `page` field sent to the API. */
export function pageContextLabel(pathname: string): string | null {
  const org = orgSlugFromPathname(pathname);
  if (org === null) return null;
  const rest = pathname.slice(`/orgs/${org}`.length).replace(/^\/+|\/+$/g, "");
  if (rest === "") return `${org} overview`;
  const [section, ...tail] = rest.split("/");
  switch (section) {
    case "analytics":
      return `${org} analytics`;
    case "settings":
      return `${org} settings`;
    case "repos":
      return tail.length > 0 ? `repository ${decodeURIComponent(tail[0])}` : `${org} repositories`;
    default:
      return `${org} ${section}`;
  }
}

/**
 * Deep link to a finding's expanded card. The copilot is instructed (system prompt) to cite
 * findings with exactly this shape, using the `advisory_id` and `scan_id` from tool results —
 * both exact strings from tool data, so the link is reliable. The scan page reads `?finding=`
 * and expands + scrolls the matching card (see {@link matchesFocus}).
 */
export function findingHref(scanId: string, advisoryId: string): string {
  return `/scans/${encodeURIComponent(scanId)}?finding=${encodeURIComponent(advisoryId)}`;
}

/**
 * Does this finding match a `?finding=` focus token? Tolerant of id/alias/CVE/package for a
 * dependency finding, and of CWE / rule kind / `file:line` for a first-party code finding.
 */
export function matchesFocus(
  finding: {
    finding_type?: string;
    dependency?: { name: string };
    advisory?: { id: string; display_id?: string; aliases?: string[]; cve_ids?: string[] };
    rule?: { cwe: string; kind: string };
    location?: { file: string; line: number };
  },
  focus: string,
): boolean {
  const needle = focus.trim().toLowerCase();
  if (needle === "") return false;
  const { advisory, dependency, rule, location } = finding;
  const candidates: (string | undefined)[] =
    finding.finding_type === "code" && rule && location
      ? [rule.cwe, rule.kind, `${location.file}:${location.line}`]
      : [
          advisory?.id,
          advisory?.display_id,
          dependency?.name,
          ...(advisory?.aliases ?? []),
          ...(advisory?.cve_ids ?? []),
        ];
  return candidates.some((c) => typeof c === "string" && c.toLowerCase() === needle);
}

/** True for in-app links the panel should route client-side (and close the panel on click). */
export function isInternalHref(href: string): boolean {
  return href.startsWith("/") && !href.startsWith("//");
}
