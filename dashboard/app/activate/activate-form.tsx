"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { DeviceApproved, Org } from "@/lib/types";

function errorMessage(status: number): string {
  switch (status) {
    case 404:
      return "That code was not found. Check it and try again.";
    case 400:
      return "That code has expired. Run `vulnadvisor login` again for a fresh one.";
    case 409:
      return "That code was already used. Run `vulnadvisor login` again for a fresh one.";
    default:
      return `Could not approve the code (HTTP ${status}).`;
  }
}

export function ActivateForm({ orgs, initialCode }: { orgs: Org[]; initialCode: string }) {
  const [code, setCode] = useState(initialCode);
  const [orgSlug, setOrgSlug] = useState(orgs[0]?.slug ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approved, setApproved] = useState<DeviceApproved | null>(null);

  async function approve(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    const trimmed = code.trim();
    if (!trimmed) {
      setError("Enter the code shown in your terminal.");
      return;
    }
    if (!orgSlug) {
      setError("Pick the organization this device should upload to.");
      return;
    }
    setSubmitting(true);
    try {
      // Same-origin /api proxy (next.config.ts) so the session cookie is sent.
      const res = await fetch("/api/v1/device/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ user_code: trimmed, org_slug: orgSlug }),
      });
      if (!res.ok) {
        setError(errorMessage(res.status));
        return;
      }
      setApproved((await res.json()) as DeviceApproved);
    } catch {
      setError("Network error reaching the API.");
    } finally {
      setSubmitting(false);
    }
  }

  if (approved) {
    return (
      <Card>
        <CardContent>
          <p className="font-semibold text-safe">Device connected ✓</p>
          <p className="mt-1 text-sm text-muted-foreground">
            {approved.client_name ? (
              <>
                <span className="mono">{approved.client_name}</span> is now linked to{" "}
              </>
            ) : (
              "The device is now linked to "
            )}
            <span className="mono">{approved.org_slug}</span>. Return to your terminal — the CLI
            will pick up its key automatically.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <form onSubmit={approve} className="grid gap-3">
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">Device code</span>
            <Input
              className="mono tracking-widest uppercase"
              placeholder="XXXX-XXXX"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              disabled={submitting}
              autoFocus
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">Organization</span>
            <select
              className="border-input h-9 rounded-md border bg-transparent px-3 text-sm shadow-xs outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              value={orgSlug}
              onChange={(e) => setOrgSlug(e.target.value)}
              disabled={submitting}
            >
              {orgs.map((org) => (
                <option key={org.id} value={org.slug} className="bg-background">
                  {org.name} ({org.slug})
                </option>
              ))}
            </select>
          </label>
          {error ? <p className="text-sm text-risk">{error}</p> : null}
          <Button variant="outline" type="submit" disabled={submitting}>
            {submitting ? "Approving…" : "Approve device"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
