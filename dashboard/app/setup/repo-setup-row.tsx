"use client";

import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SetupChip } from "@/components/setup-chip";
import { oauthPopupReturned, SETUP_OAUTH_PATH } from "@/lib/setup";
import type { Repo, SetupPrResponse } from "@/lib/types";

async function errorMessage(res: Response): Promise<string> {
  if (res.status === 403) return "Only org owners or admins can open setup PRs.";
  // Prefer the backend's detail — for a 502 it now carries GitHub's own reason (e.g. a missing
  // `workflows`/`contents` App permission), which is what you actually need to fix.
  let detail: string | undefined;
  try {
    const body = (await res.json()) as { detail?: string };
    if (typeof body.detail === "string" && body.detail) detail = body.detail;
  } catch {
    // no JSON body — fall through to a status-based message
  }
  if (detail) return detail;
  if (res.status === 502) {
    return "GitHub rejected the request — check the App installation and try again.";
  }
  return `Could not open the setup PR (HTTP ${res.status}).`;
}

export function RepoSetupRow({ orgSlug, repo }: { orgSlug: string; repo: Repo }) {
  const [status, setStatus] = useState(repo.setup_status);
  const [prUrl, setPrUrl] = useState(repo.setup_pr_url);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatedInPlace, setUpdatedInPlace] = useState(false);
  // null = not attempted this session; true/false = the last response's secret_set.
  const [secretSet, setSecretSet] = useState<boolean | null>(null);
  // The platform lacks a write-capable GitHub token (a 409, or secret_set=false). We offer
  // one-click incremental consent instead of sending the user to GitHub Settings.
  const [needsConsent, setNeedsConsent] = useState(false);
  const pollRef = useRef<number | null>(null);

  // Stop polling the consent popup if the row unmounts mid-flow.
  useEffect(() => {
    return () => {
      if (pollRef.current !== null) window.clearInterval(pollRef.current);
    };
  }, []);

  async function openSetupPr() {
    setBusy(true);
    setError(null);
    try {
      // Same-origin /api proxy (next.config.ts) so the session cookie is sent.
      const res = await fetch(
        `/api/v1/orgs/${encodeURIComponent(orgSlug)}/repos/${encodeURIComponent(repo.name)}/setup-pr`,
        { method: "POST", credentials: "include" },
      );
      if (res.status === 409) {
        // No write-capable GitHub token yet — offer consent rather than a raw error.
        setNeedsConsent(true);
        setError(null);
        return;
      }
      if (!res.ok) {
        setError(await errorMessage(res));
        return;
      }
      const data = (await res.json()) as SetupPrResponse;
      setStatus("pr-open");
      setPrUrl(data.pr_url || null);
      setUpdatedInPlace(!data.created);
      setSecretSet(data.secret_set);
      // Secret auto-written -> done; otherwise offer consent so we can set it for them.
      setNeedsConsent(!data.secret_set);
    } catch {
      setError("Network error reaching the API.");
    } finally {
      setBusy(false);
    }
  }

  function grantAccess() {
    // Pop the existing incremental-auth flow; auto-retry the setup-PR POST when it returns, so the
    // user never has to touch GitHub Settings or come back and click again.
    const popup = window.open(SETUP_OAUTH_PATH, "vulnadvisor-oauth", "width=600,height=720");
    if (!popup) {
      setError("Enable pop-ups for this site to grant repository access.");
      return;
    }
    setBusy(true);
    setError(null);
    const timer = window.setInterval(() => {
      if (popup.closed) {
        window.clearInterval(timer);
        pollRef.current = null;
        void openSetupPr();
        return;
      }
      let returned = false;
      try {
        returned = oauthPopupReturned(
          popup.location.origin,
          popup.location.href,
          window.location.origin,
        );
      } catch {
        return; // cross-origin (on github.com) — keep waiting
      }
      if (returned) {
        window.clearInterval(timer);
        pollRef.current = null;
        popup.close();
        void openSetupPr();
      }
    }, 500);
    pollRef.current = timer;
  }

  const showOpenButton = repo.github_linked && status !== "receiving-scans";

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
        {secretSet === true ? (
          <p className="mt-1 text-xs text-safe">Repository secret configured automatically.</p>
        ) : null}
        {needsConsent ? (
          <p className="mt-1 text-xs text-muted-foreground">
            {prUrl
              ? "Grant repository access to set the VULNADVISOR_API_KEY secret automatically — no GitHub Settings."
              : "VulnAdvisor needs repository access to open the PR and set its secret — one click, no GitHub Settings."}
          </p>
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
        {needsConsent ? (
          <Button size="sm" onClick={grantAccess} disabled={busy}>
            {busy ? "Waiting…" : "Grant repository access"}
          </Button>
        ) : null}
        {showOpenButton && !needsConsent ? (
          <Button variant="outline" size="sm" onClick={openSetupPr} disabled={busy}>
            {busy ? "Opening…" : status === "pr-open" ? "Update setup PR" : "Open setup PR"}
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}
