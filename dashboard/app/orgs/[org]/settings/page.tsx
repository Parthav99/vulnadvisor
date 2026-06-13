import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull, installUrl } from "@/lib/api";
import { ByomConfigDialog } from "@/components/copilot/byom-config";
import { EmptyState, PageHeader } from "@/components/blocks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatDate } from "@/lib/format";
import type { ApiKey, OrgDetail } from "@/lib/types";

export async function generateMetadata({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  return { title: `Settings · ${org}` };
}

export default async function SettingsPage({ params }: { params: Promise<{ org: string }> }) {
  const { org: slug } = await params;
  const org = await apiGetOrNull<OrgDetail>(`/v1/orgs/${slug}`);
  if (org === null) notFound();
  const keys = (await apiGetOrNull<ApiKey[]>(`/v1/orgs/${slug}/keys`)) ?? [];

  return (
    <div>
      <PageHeader title={`${org.name} · settings`} subtitle={`${org.slug} · your role: ${org.role}`} />

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          GitHub App
        </h2>
        <Card size="sm" className="flex-row items-center justify-between">
          <CardContent className="text-sm text-muted-foreground">
            Install the VulnAdvisor GitHub App to get PR comments and repository sync, then{" "}
            <Link className="link" href="/setup">
              set up scanning
            </Link>{" "}
            with one click per repo.
          </CardContent>
          <CardContent>
            <Button asChild variant="outline">
              <a href={installUrl()}>Install / configure</a>
            </Button>
          </CardContent>
        </Card>
      </section>

      <section className="mb-6">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
            API keys
          </h2>
          <Button asChild variant="outline" size="sm">
            <Link href={`/orgs/${slug}/settings/api-keys`}>Manage keys</Link>
          </Button>
        </div>
        {keys.length === 0 ? (
          <EmptyState>
            No API keys yet.{" "}
            <Link className="link" href={`/orgs/${slug}/settings/api-keys`}>
              Generate one
            </Link>{" "}
            to upload scan reports from CI.
          </EmptyState>
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
                  <CardContent className="text-right text-xs text-muted-foreground">
                    <div>created {formatDate(key.created_at)}</div>
                    <div>last used {formatDate(key.last_used_at)}</div>
                  </CardContent>
                </Card>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          AI copilot
        </h2>
        <Card size="sm" className="flex-row items-center justify-between">
          <CardContent className="text-sm text-muted-foreground">
            Use your own model key for the triage copilot — stored only in your browser,
            never on our servers. A free OpenRouter key works.
          </CardContent>
          <CardContent>
            <ByomConfigDialog orgSlug={org.slug} />
          </CardContent>
        </Card>
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          Cloud scanning
        </h2>
        <Card size="sm" className="flex-row items-center justify-between">
          <CardContent className="text-sm text-muted-foreground">
            Cloud-side scanning is <span className="text-foreground">disabled</span> — source code
            never leaves your infrastructure. CI uploads JSON reports only.
          </CardContent>
          <CardContent>
            <Badge variant="outline" className="border-safe/50 text-safe">
              opt-in
            </Badge>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
