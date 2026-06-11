import { cache } from "react";
import { apiGetOrNull } from "@/lib/api";
import { shortRef, shortSha } from "@/lib/format";
import type { Org, Repo, ScanPage } from "@/lib/types";

// Data the app shell needs on every page: the org switcher list and the ⌘K
// command-palette index (orgs → repos → recent scans). Fetched server-side so it
// works with both session-cookie and DASHBOARD_API_TOKEN auth.

export interface ShellRepo {
  org: string;
  name: string;
}

export interface ShellScan {
  id: string;
  org: string;
  repo: string;
  label: string;
  createdAt: string;
}

export interface ShellData {
  signedIn: boolean;
  orgs: Org[];
  repos: ShellRepo[];
  scans: ShellScan[];
}

const EMPTY: ShellData = { signedIn: false, orgs: [], repos: [], scans: [] };

// Bounds keep the palette index cheap on large orgs; ⌘K is a jump list, not a search API.
const MAX_ORGS = 10;
const MAX_REPOS = 30;
const SCANS_PER_REPO = 3;

/**
 * Never throws: a shell error would bypass the branded route error boundary, so an
 * unreachable API degrades to the minimal signed-out shell and the page's own fetch
 * surfaces the real error state. Wrapped in React cache() so the sidebar and the
 * command palette share one fetch per request.
 */
export const getShellData = cache(async function getShellData(): Promise<ShellData> {
  try {
    const orgs = await apiGetOrNull<Org[]>("/v1/orgs");
    if (orgs === null) return EMPTY;

    const limitedOrgs = orgs.slice(0, MAX_ORGS);
    const repoLists = await Promise.all(
      limitedOrgs.map((org) => apiGetOrNull<Repo[]>(`/v1/orgs/${org.slug}/repos`)),
    );
    const repos: ShellRepo[] = limitedOrgs
      .flatMap((org, i) => (repoLists[i] ?? []).map((repo) => ({ org: org.slug, name: repo.name })))
      .slice(0, MAX_REPOS);

    const scanPages = await Promise.all(
      repos.map((repo) =>
        apiGetOrNull<ScanPage>(
          `/v1/orgs/${repo.org}/repos/${repo.name}/scans?limit=${SCANS_PER_REPO}`,
        ),
      ),
    );
    const scans: ShellScan[] = repos.flatMap((repo, i) =>
      (scanPages[i]?.items ?? []).map((scan) => {
        const sha = shortSha(scan.commit_sha);
        const ref = shortRef(scan.ref);
        return {
          id: scan.id,
          org: repo.org,
          repo: repo.name,
          label: sha ? `${sha}${ref ? ` · ${ref}` : ""}` : "local scan",
          createdAt: scan.created_at,
        };
      }),
    );

    return { signedIn: true, orgs, repos, scans };
  } catch {
    return EMPTY;
  }
});
