"use client";

import { useState } from "react";
import { EmptyState } from "@/components/blocks";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { formatDate } from "@/lib/format";
import type { ApiKey, ApiKeyCreated } from "@/lib/types";

// Calls go through the same-origin /api proxy (next.config.ts) so the session cookie is sent.
function apiBase(slug: string): string {
  return `/api/v1/orgs/${encodeURIComponent(slug)}/api-keys`;
}

export function KeysManager({ slug, initialKeys }: { slug: string; initialKeys: ApiKey[] }) {
  const [keys, setKeys] = useState<ApiKey[]>(initialKeys);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);

  async function createKey(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setCreated(null);
    setCopied(false);
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Give the key a name.");
      return;
    }
    setCreating(true);
    try {
      const res = await fetch(apiBase(slug), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name: trimmed }),
      });
      if (!res.ok) {
        setError(
          res.status === 403
            ? "You need the owner or admin role to create keys."
            : `Could not create key (HTTP ${res.status}).`,
        );
        return;
      }
      const key = (await res.json()) as ApiKeyCreated;
      setCreated(key);
      setName("");
      setKeys((prev) => [
        {
          id: key.id,
          name: key.name,
          prefix: key.prefix,
          created_at: key.created_at,
          last_used_at: null,
          revoked_at: null,
        },
        ...prev,
      ]);
    } catch {
      setError("Network error reaching the API.");
    } finally {
      setCreating(false);
    }
  }

  async function copySecret() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  async function revokeKey(id: string) {
    setError(null);
    try {
      const res = await fetch(`${apiBase(slug)}/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok && res.status !== 404) {
        setError(`Could not revoke key (HTTP ${res.status}).`);
        return;
      }
      setKeys((prev) =>
        prev.map((k) => (k.id === id ? { ...k, revoked_at: new Date().toISOString() } : k)),
      );
    } catch {
      setError("Network error reaching the API.");
    }
  }

  return (
    <div>
      <form onSubmit={createKey} className="mb-4 flex flex-wrap items-center gap-2">
        <Input
          className="min-w-48 flex-1"
          placeholder="Key name (e.g. ci-github-actions)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={creating}
        />
        <Button variant="outline" type="submit" disabled={creating}>
          {creating ? "Generating…" : "Generate key"}
        </Button>
      </form>

      {error ? <p className="mb-3 text-sm text-risk">{error}</p> : null}

      {created ? (
        <Card size="sm" className="mb-4 ring-foreground/25">
          <CardContent>
            <p className="mb-1 text-sm font-semibold">
              Copy this key now — it is shown only once.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <code className="mono rounded bg-background px-2 py-1 text-xs break-all">
                {created.secret}
              </code>
              <Button variant="outline" size="sm" type="button" onClick={copySecret}>
                {copied ? "Copied ✓" : "Copy"}
              </Button>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Use it as <span className="mono">Authorization: Bearer &lt;key&gt;</span>, or run{" "}
              <span className="mono">vulnadvisor scan . --upload --api-key &lt;key&gt;</span>.
            </p>
          </CardContent>
        </Card>
      ) : null}

      {keys.length === 0 ? (
        <EmptyState>No API keys yet. Generate one above to upload scans from CI.</EmptyState>
      ) : (
        <ul className="grid gap-2">
          {keys.map((key) => (
            <li key={key.id}>
              <Card size="sm" className="flex-row items-center justify-between">
                <CardContent>
                  <span className="font-semibold">{key.name}</span>{" "}
                  <span className="mono text-xs text-muted-foreground">{key.prefix}…</span>
                  {key.revoked_at ? <span className="ml-2 text-xs text-risk">revoked</span> : null}
                </CardContent>
                <CardContent className="flex items-center gap-3">
                  <div className="text-right text-xs text-muted-foreground">
                    <div>created {formatDate(key.created_at)}</div>
                    <div>last used {formatDate(key.last_used_at)}</div>
                  </div>
                  {key.revoked_at ? null : (
                    <button
                      className="text-xs text-risk hover:underline"
                      type="button"
                      onClick={() => revokeKey(key.id)}
                    >
                      Revoke
                    </button>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
