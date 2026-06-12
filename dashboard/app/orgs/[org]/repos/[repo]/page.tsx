import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader } from "@/components/blocks";
import { TrendAreaChart } from "@/components/analytics-charts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { bandClass, formatDate, shortRef, shortSha } from "@/lib/format";
import type { Repo, ScanPage, TrendResponse } from "@/lib/types";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ org: string; repo: string }>;
}) {
  const { org, repo } = await params;
  return { title: `${org}/${repo}` };
}

export default async function RepoPage({
  params,
  searchParams,
}: {
  params: Promise<{ org: string; repo: string }>;
  searchParams: Promise<{ ref?: string }>;
}) {
  const { org, repo } = await params;
  const { ref: selectedRef } = await searchParams;

  const detail = await apiGetOrNull<Repo>(`/v1/orgs/${org}/repos/${repo}`);
  if (detail === null) notFound();
  const trend = await apiGetOrNull<TrendResponse>(`/v1/orgs/${org}/repos/${repo}/trend?window=90d`);
  const page = await apiGetOrNull<ScanPage>(`/v1/orgs/${org}/repos/${repo}/scans?limit=50`);
  const allScans = page?.items ?? [];

  const refs = Array.from(
    new Set(allScans.map((s) => s.ref).filter((r): r is string => r !== null))
  );
  const scans = selectedRef ? allScans.filter((s) => s.ref === selectedRef) : allScans;
  const base = `/orgs/${org}/repos/${repo}`;

  return (
    <div>
      <PageHeader
        title={<span className="mono">{detail.name}</span>}
        subtitle={
          <>
            <Link href={`/orgs/${org}`} className="link">
              {org}
            </Link>{" "}
            · default {detail.default_branch} · {detail.scan_count} scans
          </>
        }
      />

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          90-day trend
        </h2>
        <Card size="sm">
          <CardContent>
            {(trend?.points.length ?? 0) > 0 ? (
              <TrendAreaChart
                points={trend?.points ?? []}
                ariaLabel="Actionable versus deprioritized findings over time"
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                No scans in this window yet — run{" "}
                <code className="mono text-foreground">vulnadvisor scan . --upload</code> to chart
                the first one.
              </p>
            )}
          </CardContent>
        </Card>
      </section>

      {refs.length > 1 ? (
        <nav className="mb-3 flex flex-wrap gap-2 text-sm" aria-label="Filter by ref">
          <Button asChild variant="outline" size="sm" className={selectedRef ? "" : "border-ring"}>
            <Link href={base}>all refs</Link>
          </Button>
          {refs.map((r) => (
            <Button
              key={r}
              asChild
              variant="outline"
              size="sm"
              className={selectedRef === r ? "border-ring" : ""}
            >
              <Link href={`${base}?ref=${encodeURIComponent(r)}`}>{shortRef(r)}</Link>
            </Button>
          ))}
        </nav>
      ) : null}

      {scans.length >= 2 ? (
        <p className="mb-3 text-sm text-muted-foreground">
          <Link href={`/scans/${scans[1].id}/diff/${scans[0].id}`} className="link">
            Compare the two latest scans →
          </Link>
        </p>
      ) : null}

      <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
        Scans
      </h2>
      {scans.length === 0 ? (
        <EmptyState>
          {allScans.length > 0 ? (
            <>
              No scans on this ref —{" "}
              <Link className="link" href={base}>
                show all refs
              </Link>
              .
            </>
          ) : (
            <>
              No scans uploaded yet — run{" "}
              <code className="mono text-foreground">vulnadvisor scan . --upload</code> from this
              repository to publish the first report.
            </>
          )}
        </EmptyState>
      ) : (
        <ul className="grid gap-2">
          {scans.map((scan) => (
            <li key={scan.id}>
              <Link href={`/scans/${scan.id}`} className="block">
                <Card
                  size="sm"
                  className="flex-row items-center justify-between transition-shadow hover:ring-ring/40"
                >
                  <CardContent>
                    {shortSha(scan.commit_sha) ? (
                      <span className="mono">{shortSha(scan.commit_sha)}</span>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">
                        local scan
                      </Badge>
                    )}{" "}
                    {shortRef(scan.ref) ? (
                      <span className="text-muted-foreground">{shortRef(scan.ref)}</span>
                    ) : null}
                    {scan.pr_number ? (
                      <span className="text-muted-foreground"> · PR #{scan.pr_number}</span>
                    ) : null}
                  </CardContent>
                  <CardContent className="flex items-center gap-3">
                    <Badge variant="outline" className={bandClass("critical")}>
                      {scan.summary.by_band?.critical ?? 0} critical
                    </Badge>
                    <span className="text-sm text-muted-foreground">
                      {scan.summary.total ?? 0} findings
                    </span>
                    <span className="text-sm text-muted-foreground">
                      {formatDate(scan.created_at)}
                    </span>
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
