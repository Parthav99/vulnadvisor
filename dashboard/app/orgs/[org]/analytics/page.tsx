import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader, Stat } from "@/components/blocks";
import {
  PackagesBar,
  SeverityDonut,
  TierDonut,
  TrendAreaChart,
} from "@/components/analytics-charts";
import { Card, CardContent } from "@/components/ui/card";
import type {
  AnalyticsOverview,
  OrgTrendResponse,
  PackagesResponse,
  ResolutionResponse,
} from "@/lib/types";

export async function generateMetadata({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  return { title: `${org} analytics` };
}

function formatMedianDays(days: number | null): string {
  if (days === null) return "—";
  if (days < 1) return "<1 day";
  const rounded = Math.round(days * 10) / 10;
  return `${rounded} day${rounded === 1 ? "" : "s"}`;
}

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <Card size="sm">
      <CardContent>
        <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
          {title}
        </h2>
        {subtitle ? <p className="mt-0.5 mb-2 text-xs text-muted-foreground">{subtitle}</p> : null}
        <div className="mt-2">{children}</div>
      </CardContent>
    </Card>
  );
}

function TeachingState({ children }: { children: React.ReactNode }) {
  return (
    <p className="py-8 text-center text-sm text-muted-foreground">
      {children ?? "Upload a scan to see analytics."}
    </p>
  );
}

export default async function AnalyticsPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const overview = await apiGetOrNull<AnalyticsOverview>(`/v1/orgs/${org}/analytics/overview`);
  if (overview === null) notFound();
  const [trend, packages, resolution] = await Promise.all([
    apiGetOrNull<OrgTrendResponse>(`/v1/orgs/${org}/analytics/trend?window=90d`),
    apiGetOrNull<PackagesResponse>(`/v1/orgs/${org}/analytics/packages?limit=10`),
    apiGetOrNull<ResolutionResponse>(`/v1/orgs/${org}/analytics/resolution`),
  ]);

  const protectedRepos = overview.repo_count - overview.repos_at_risk;
  const points = trend?.points ?? [];
  const topPackages = packages?.packages ?? [];
  const uploadHint = (
    <>
      Upload a scan to see analytics — run{" "}
      <code className="mono text-foreground">vulnadvisor scan . --upload</code> from a repository.
    </>
  );

  return (
    <div>
      <PageHeader
        title="Analytics"
        subtitle={
          <>
            <Link href={`/orgs/${org}`} className="link">
              {org}
            </Link>{" "}
            · computed from each repo&apos;s latest scan
          </>
        }
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Protected repos"
          value={
            <>
              <span className={overview.repo_count > 0 ? "text-safe" : undefined}>
                {protectedRepos}
              </span>
              <span className="text-sm font-normal text-muted-foreground">
                {` of ${overview.repo_count}`}
              </span>
            </>
          }
        />
        <Stat
          label="Actionable findings"
          value={
            <span className={overview.actionable > 0 ? "text-risk" : "text-safe"}>
              {overview.actionable.toLocaleString()}
            </span>
          }
        />
        <Stat
          label="Known-exploited (KEV)"
          value={
            <span className={overview.kev_count > 0 ? "text-risk" : "text-safe"}>
              {overview.kev_count.toLocaleString()}
            </span>
          }
        />
        <Stat
          label="Median fix time"
          value={formatMedianDays(resolution?.overall.median_days ?? null)}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Severity distribution" subtitle="Findings by priority band">
          {overview.total_findings > 0 ? (
            <SeverityDonut byBand={overview.by_band} />
          ) : (
            <TeachingState>{uploadHint}</TeachingState>
          )}
        </ChartCard>

        <ChartCard
          title="Reachability split"
          subtitle="What the engine confidently deprioritized vs what needs you"
        >
          {overview.total_findings > 0 ? (
            <TierDonut byTier={overview.by_tier} />
          ) : (
            <TeachingState>{uploadHint}</TeachingState>
          )}
        </ChartCard>

        <div className="lg:col-span-2">
          <ChartCard title="90-day trend" subtitle="Per-day findings across all repos">
            {points.length > 0 ? (
              <TrendAreaChart
                points={points}
                ariaLabel="Actionable versus deprioritized findings across the organization over the last 90 days"
              />
            ) : (
              <TeachingState>{uploadHint}</TeachingState>
            )}
          </ChartCard>
        </div>

        <div className="lg:col-span-2">
          <ChartCard
            title="Top risky packages"
            subtitle="By top finding priority — click a bar to open that finding's scan"
          >
            {topPackages.length > 0 ? (
              <PackagesBar packages={topPackages} />
            ) : (
              <TeachingState>{uploadHint}</TeachingState>
            )}
          </ChartCard>
        </div>
      </div>

      {overview.total_findings === 0 ? (
        <div className="mt-6">
          <EmptyState>
            Nothing to chart yet —{" "}
            <Link className="link" href="/demo/analytics">
              see this page with data in the demo org
            </Link>
            .
          </EmptyState>
        </div>
      ) : null}
    </div>
  );
}
