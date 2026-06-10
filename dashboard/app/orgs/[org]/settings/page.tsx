import { notFound } from "next/navigation";
import { apiGetOrNull, installUrl } from "@/lib/api";
import { Card, EmptyState, PageHeader } from "@/components/ui";
import { formatDate } from "@/lib/format";
import type { ApiKey, OrgDetail } from "@/lib/types";

export default async function SettingsPage({ params }: { params: Promise<{ org: string }> }) {
  const { org: slug } = await params;
  const org = await apiGetOrNull<OrgDetail>(`/v1/orgs/${slug}`);
  if (org === null) notFound();
  const keys = (await apiGetOrNull<ApiKey[]>(`/v1/orgs/${slug}/keys`)) ?? [];

  return (
    <div>
      <PageHeader title={`${org.name} · settings`} subtitle={`${org.slug} · your role: ${org.role}`} />

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">GitHub App</h2>
        <Card className="flex items-center justify-between">
          <span className="muted text-sm">
            Install the VulnAdvisor GitHub App to get PR comments and repository sync.
          </span>
          <a className="btn" href={installUrl()}>
            Install / configure
          </a>
        </Card>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">API keys</h2>
        {keys.length === 0 ? (
          <EmptyState>
            No API keys yet. Create one with the CLI/API to upload scan reports from CI.
          </EmptyState>
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
                  <div className="muted text-right text-xs">
                    <div>created {formatDate(key.created_at)}</div>
                    <div>last used {formatDate(key.last_used_at)}</div>
                  </div>
                </Card>
              </li>
            ))}
          </ul>
        )}
        <p className="muted mt-2 text-xs">
          Keys are managed via the API/CLI; this dashboard is read-only.
        </p>
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">Cloud scanning</h2>
        <Card className="flex items-center justify-between">
          <span className="muted text-sm">
            Cloud-side scanning is <span className="text-[#e6edf3]">disabled</span> — source code
            never leaves your infrastructure. CI uploads JSON reports only.
          </span>
          <span className="pill border-[#3fb950] text-[#56d364]">opt-in</span>
        </Card>
      </section>
    </div>
  );
}
