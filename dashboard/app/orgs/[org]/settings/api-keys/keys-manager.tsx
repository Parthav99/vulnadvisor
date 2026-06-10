"use client";

import { useState } from "react";
import { Card, EmptyState } from "@/components/ui";
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
        <input
          className="min-w-48 flex-1 rounded-md border border-[#30363d] bg-[#0d1117] px-3 py-2 text-sm text-[#e6edf3] outline-none focus:border-[#3fb950]"
          placeholder="Key name (e.g. ci-github-actions)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={creating}
        />
        <button className="btn" type="submit" disabled={creating}>
          {creating ? "Generating…" : "Generate key"}
        </button>
      </form>

      {error ? <p className="mb-3 text-sm text-[#ff7b72]">{error}</p> : null}

      {created ? (
        <Card className="mb-4 border-[#3fb950]">
          <p className="mb-1 text-sm font-semibold text-[#56d364]">
            Copy this key now — it is shown only once.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="mono break-all rounded bg-[#0d1117] px-2 py-1 text-xs text-[#e6edf3]">
              {created.secret}
            </code>
            <button className="btn" type="button" onClick={copySecret}>
              {copied ? "Copied ✓" : "Copy"}
            </button>
          </div>
          <p className="muted mt-2 text-xs">
            Use it as <span className="mono">Authorization: Bearer &lt;key&gt;</span>, or run{" "}
            <span className="mono">vulnadvisor scan . --upload --api-key &lt;key&gt;</span>.
          </p>
        </Card>
      ) : null}

      {keys.length === 0 ? (
        <EmptyState>No API keys yet. Generate one above to upload scans from CI.</EmptyState>
      ) : (
        <ul className="grid gap-2">
          {keys.map((key) => (
            <li key={key.id}>
              <Card className="flex items-center justify-between">
                <div>
                  <span className="font-semibold">{key.name}</span>{" "}
                  <span className="muted mono text-xs">{key.prefix}…</span>
                  {key.revoked_at ? (
                    <span className="ml-2 text-xs text-[#ff7b72]">revoked</span>
                  ) : null}
                </div>
                <div className="flex items-center gap-3">
                  <div className="muted text-right text-xs">
                    <div>created {formatDate(key.created_at)}</div>
                    <div>last used {formatDate(key.last_used_at)}</div>
                  </div>
                  {key.revoked_at ? null : (
                    <button
                      className="text-xs text-[#ff7b72] hover:underline"
                      type="button"
                      onClick={() => revokeKey(key.id)}
                    >
                      Revoke
                    </button>
                  )}
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
