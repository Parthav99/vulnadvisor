"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SetupChip } from "@/components/setup-chip";
import type { Repo, SetupPrResponse } from "@/lib/types";

async function errorMessage(res: Response): Promise<string> {
  if (res.status === 403) return "Only org owners or admins can open setup PRs.";
  if (res.status === 502) {
    return "GitHub rejected the request — check the App installation and try again.";
  }
  try {
    const body = (await res.json()) as { detail?: string };
    if (typeof body.detail === "string" && body.detail) return body.detail;
  } catch {
    // fall through to the generic message
  }
  return `Could not open the setup PR (HTTP ${res.status}).`;
}

export function RepoSetupRow({ orgSlug, repo }: { orgSlug: string; repo: Repo }) {
  const [status, setStatus] = useState(repo.setup_status);
  const [prUrl, setPrUrl] = useState(repo.setup_pr_url);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatedInPlace, setUpdatedInPlace] = useState(false);

  async function openSetupPr() {
    setBusy(true);
    setError(null);
    try {
      // Same-origin /api proxy (next.config.ts) so the session cookie is sent.
      const res = await fetch(
        `/api/v1/orgs/${encodeURIComponent(orgSlug)}/repos/${encodeURIComponent(repo.name)}/setup-pr`,
        { method: "POST", credentials: "include" },
      );
      if (!res.ok) {
        setError(await errorMessage(res));
        return;
      }
      const data = (await res.json()) as SetupPrResponse;
      setStatus("pr-open");
      setPrUrl(data.pr_url || null);
      setUpdatedInPlace(!data.created);
    } catch {
      setError("Network error reaching the API.");
    } finally {
      setBusy(false);
    }
  }

  const showButton = repo.github_linked && status !== "receiving-scans";

  return (
    <Card size="sm" className="flex-row items-center justify-between">
      <CardContent>
        <div className="flex items-center gap-2">
          <span className="mono font-semibold">{repo.name}</span>
          <SetupChip status={status} />
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          {repo.is_private ? "private" : "public"} · default {repo.default_branch}
          {!repo.github_linked ? " · CLI uploads only (not synced from GitHub)" : null}
        </div>
        {error ? <p className="mt-1 text-xs text-risk">{error}</p> : null}
        {updatedInPlace ? (
          <p className="mt-1 text-xs text-muted-foreground">Existing setup PR updated in place.</p>
        ) : null}
      </CardContent>
      <CardContent className="flex items-center gap-2">
        {prUrl ? (
          <Button asChild variant="outline" size="sm">
            <a href={prUrl} target="_blank" rel="noreferrer">
              View PR
            </a>
          </Button>
        ) : null}
        {showButton ? (
          <Button variant="outline" size="sm" onClick={openSetupPr} disabled={busy}>
            {busy ? "Opening…" : status === "pr-open" ? "Update setup PR" : "Open setup PR"}
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}
