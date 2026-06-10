import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { Card, EmptyState, PageHeader, Stat } from "@/components/ui";
import { formatDate } from "@/lib/format";
import type { OrgDetail, Repo } from "@/lib/types";

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

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">Repositories</h2>
      {repos.length === 0 ? (
        <EmptyState>No repositories have reported scans yet.</EmptyState>
      ) : (
        <ul className="grid gap-3">
          {repos.map((repo) => (
            <li key={repo.id}>
              <Link href={`/orgs/${slug}/repos/${repo.name}`} className="block">
                <Card className="flex items-center justify-between hover:border-[#58a6ff]">
                  <div>
                    <div className="mono font-semibold">{repo.name}</div>
                    <div className="muted text-sm">
                      {repo.is_private ? "private" : "public"} · default {repo.default_branch}
                    </div>
                  </div>
                  <div className="muted text-right text-sm">
                    <div>{repo.scan_count} scans</div>
                    <div>last {formatDate(repo.last_scan_at)}</div>
                  </div>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
