// File: dashboard/app/demo/repos/[repo]/page.tsx
// Demo repo page — trend + scan list from the seeded dataset, same components as the
// real /orgs/{org}/repos/{repo} page.
import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/blocks";
import { TrendAreaChart } from "@/components/analytics-charts";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { DEMO_REPO_TRENDS, demoRepo, demoScansForRepo } from "@/lib/demo-data";
import { bandClass, formatDate, shortRef, shortSha } from "@/lib/format";

export async function generateMetadata({ params }: { params: Promise<{ repo: string }> }) {
  const { repo } = await params;
  return { title: `demo/${repo}` };
}

export default async function DemoRepoPage({ params }: { params: Promise<{ repo: string }> }) {
  const { repo: repoName } = await params;
  const repo = demoRepo(repoName);
  if (repo === null) notFound();
  const scans = demoScansForRepo(repoName);
  const points = DEMO_REPO_TRENDS[repoName] ?? [];

  return (
    <div>
      <PageHeader
        title={<span className="mono">{repo.name}</span>}
        subtitle={
          <>
            <Link href="/demo" className="link">
              demo
            </Link>{" "}
            · default {repo.default_branch} · {repo.scan_count} scans
          </>
        }
      />

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          90-day trend
        </h2>
        <Card size="sm">
          <CardContent>
            {points.length > 0 ? (
              <TrendAreaChart
                points={points}
                ariaLabel="Actionable versus deprioritized findings over time"
              />
            ) : (
              <p className="text-sm text-muted-foreground">No scans in this window yet.</p>
            )}
          </CardContent>
        </Card>
      </section>

      <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
        Scans
      </h2>
      <ul className="grid gap-2">
        {scans.map((scan) => (
          <li key={scan.detail.id}>
            <Link href={`/demo/scans/${scan.detail.id}`} className="block">
              <Card
                size="sm"
                className="flex-row items-center justify-between transition-shadow hover:ring-ring/40"
              >
                <CardContent>
                  <span className="mono">{shortSha(scan.detail.commit_sha)}</span>{" "}
                  <span className="text-muted-foreground">{shortRef(scan.detail.ref)}</span>
                </CardContent>
                <CardContent className="flex items-center gap-3">
                  <Badge variant="outline" className={bandClass("critical")}>
                    {scan.detail.summary.by_band?.critical ?? 0} critical
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {scan.detail.summary.total ?? 0} findings
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {formatDate(scan.detail.created_at)}
                  </span>
                </CardContent>
              </Card>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
