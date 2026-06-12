// File: dashboard/app/demo/page.tsx
// Demo org home — the same composition as /orgs/{org} (posture hero, stats, repo rows)
// rendered from the seeded dataset. Read-only: rows link to demo scans, nothing mutates.
import Link from "next/link";
import { EmptyState, PageHeader, Stat } from "@/components/blocks";
import { PostureHero } from "@/components/posture-hero";
import { SetupChip } from "@/components/setup-chip";
import { Card, CardContent } from "@/components/ui/card";
import { DEMO_ORG, DEMO_OVERVIEW, DEMO_REPOS } from "@/lib/demo-data";
import { formatDate } from "@/lib/format";
import { computePosture } from "@/lib/posture";

export default function DemoOrgPage() {
  const scannedRepos = DEMO_REPOS.filter((r) => r.scan_count > 0).length;

  return (
    <div>
      <PageHeader
        title={DEMO_ORG.name}
        subtitle={`${DEMO_ORG.slug} · your role: ${DEMO_ORG.role} · read-only demo`}
      />

      <PostureHero posture={computePosture(DEMO_OVERVIEW, scannedRepos)} />

      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat label="Repositories" value={DEMO_ORG.repo_count} />
        <Stat label="Members" value={DEMO_ORG.member_count} />
        <Stat label="Plan" value={DEMO_ORG.plan} />
      </div>

      <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
        Repositories
      </h2>
      {DEMO_REPOS.length === 0 ? (
        <EmptyState>The demo dataset is empty — this should never happen.</EmptyState>
      ) : (
        <ul className="grid gap-3" data-tour="repo-list">
          {DEMO_REPOS.map((repo) => (
            <li key={repo.id}>
              <Link href={`/demo/repos/${repo.name}`} className="block">
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
