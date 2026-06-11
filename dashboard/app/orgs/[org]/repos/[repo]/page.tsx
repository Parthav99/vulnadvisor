import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { Card, EmptyState, PageHeader } from "@/components/ui";
import { TrendChart } from "@/components/trend-chart";
import { Badge } from "@/components/ui";
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
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">
          90-day trend
        </h2>
        <TrendChart points={trend?.points ?? []} />
      </section>

      {refs.length > 1 ? (
        <nav className="mb-3 flex flex-wrap gap-2 text-sm" aria-label="Filter by ref">
          <Link href={base} className={`btn ${selectedRef ? "" : "border-[#58a6ff]"}`}>
            all refs
          </Link>
          {refs.map((r) => (
            <Link
              key={r}
              href={`${base}?ref=${encodeURIComponent(r)}`}
              className={`btn ${selectedRef === r ? "border-[#58a6ff]" : ""}`}
            >
              {shortRef(r)}
            </Link>
          ))}
        </nav>
      ) : null}

      {scans.length >= 2 ? (
        <p className="muted mb-3 text-sm">
          <Link href={`/scans/${scans[1].id}/diff/${scans[0].id}`} className="link">
            Compare the two latest scans →
          </Link>
        </p>
      ) : null}

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide muted">Scans</h2>
      {scans.length === 0 ? (
        <EmptyState>
          {allScans.length > 0 ? (
            "No scans on this ref."
          ) : (
            <>
              No scans uploaded yet. Run{" "}
              <code className="mono text-[#e6edf3]">vulnadvisor scan . --upload</code> from this
              repository to publish the first report.
            </>
          )}
        </EmptyState>
      ) : (
        <ul className="grid gap-2">
          {scans.map((scan) => (
            <li key={scan.id}>
              <Link href={`/scans/${scan.id}`} className="block">
                <Card className="flex items-center justify-between hover:border-[#58a6ff]">
                  <div>
                    {shortSha(scan.commit_sha) ? (
                      <span className="mono">{shortSha(scan.commit_sha)}</span>
                    ) : (
                      <Badge className="border-[#6e7681] text-[#8b949e] bg-[#6e768122]">
                        local scan
                      </Badge>
                    )}{" "}
                    {shortRef(scan.ref) ? (
                      <span className="muted">{shortRef(scan.ref)}</span>
                    ) : null}
                    {scan.pr_number ? <span className="muted"> · PR #{scan.pr_number}</span> : null}
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge className={bandClass("critical")}>
                      {scan.summary.by_band?.critical ?? 0} critical
                    </Badge>
                    <span className="muted text-sm">{scan.summary.total ?? 0} findings</span>
                    <span className="muted text-sm">{formatDate(scan.created_at)}</span>
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
