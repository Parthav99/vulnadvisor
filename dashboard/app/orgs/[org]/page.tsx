import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader, Stat } from "@/components/blocks";
import { Card, CardContent } from "@/components/ui/card";
import { formatDate } from "@/lib/format";
import type { OrgDetail, Repo } from "@/lib/types";

export async function generateMetadata({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  return { title: org };
}

export default async function OrgPage({ params }: { params: Promise<{ org: string }> }) {
  const { org: slug } = await params;
  const org = await apiGetOrNull<OrgDetail>(`/v1/orgs/${slug}`);
  if (org === null) notFound();
  const repos = (await apiGetOrNull<Repo[]>(`/v1/orgs/${slug}/repos`)) ?? [];

  return (
    <div>
      <PageHeader
        title={org.name}
        subtitle={
          <>
            {org.slug} · your role: {org.role} ·{" "}
            <Link href={`/orgs/${slug}/settings`} className="link">
              Settings
            </Link>
          </>
        }
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat label="Repositories" value={org.repo_count} />
        <Stat label="Members" value={org.member_count} />
        <Stat label="Plan" value={org.plan} />
      </div>

      <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
        Repositories
      </h2>
      {repos.length === 0 ? (
        <EmptyState>
          No repositories have reported scans yet. Install the GitHub App or upload a report with{" "}
          <code className="mono text-foreground">vulnadvisor scan . --upload</code>.
        </EmptyState>
      ) : (
        <ul className="grid gap-3">
          {repos.map((repo) => (
            <li key={repo.id}>
              <Link href={`/orgs/${slug}/repos/${repo.name}`} className="block">
                <Card
                  size="sm"
                  className="flex-row items-center justify-between transition-shadow hover:ring-ring/40"
                >
                  <CardContent>
                    <div className="mono font-semibold">{repo.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {repo.is_private ? "private" : "public"} · default {repo.default_branch}
                    </div>
                  </CardContent>
                  <CardContent className="text-right text-sm text-muted-foreground">
                    <div>{repo.scan_count} scans</div>
                    <div>
                      {repo.last_scan_at ? `last ${formatDate(repo.last_scan_at)}` : "no scans yet"}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
