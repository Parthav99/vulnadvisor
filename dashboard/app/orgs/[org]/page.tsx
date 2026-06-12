import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader, Stat } from "@/components/blocks";
import { PostureHero } from "@/components/posture-hero";
import { SetupChip } from "@/components/setup-chip";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatDate } from "@/lib/format";
import { computePosture } from "@/lib/posture";
import type { AnalyticsOverview, OrgDetail, Repo } from "@/lib/types";

export async function generateMetadata({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  return { title: org };
}

export default async function OrgPage({ params }: { params: Promise<{ org: string }> }) {
  const { org: slug } = await params;
  const org = await apiGetOrNull<OrgDetail>(`/v1/orgs/${slug}`);
  if (org === null) notFound();
  const [repos, overview] = await Promise.all([
    apiGetOrNull<Repo[]>(`/v1/orgs/${slug}/repos`).then((r) => r ?? []),
    apiGetOrNull<AnalyticsOverview>(`/v1/orgs/${slug}/analytics/overview`),
  ]);
  const scannedRepos = repos.filter((r) => r.scan_count > 0).length;

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

      {overview ? <PostureHero posture={computePosture(overview, scannedRepos)} /> : null}

      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat label="Repositories" value={org.repo_count} />
        <Stat label="Members" value={org.member_count} />
        <Stat label="Plan" value={org.plan} />
      </div>

      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          Repositories
        </h2>
        <Button asChild variant="outline" size="sm">
          <Link href="/setup">Set up scanning</Link>
        </Button>
      </div>
      {repos.length === 0 ? (
        <EmptyState>
          <p>No repositories have reported scans yet.</p>
          <div className="mt-4">
            <Button asChild variant="outline">
              <Link href="/setup">Set up scanning</Link>
            </Button>
          </div>
        </EmptyState>
      ) : (
        <ul className="grid gap-3" data-tour="repo-list">
          {repos.map((repo) => (
            <li key={repo.id}>
              <Link href={`/orgs/${slug}/repos/${repo.name}`} className="block">
                <Card
                  size="sm"
                  className="flex-row items-center justify-between transition-shadow hover:ring-ring/40"
                >
                  <CardContent>
                    <div className="flex items-center gap-2">
                      <span className="mono font-semibold">{repo.name}</span>
                      <SetupChip status={repo.setup_status} />
                    </div>
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
