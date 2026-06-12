// File: dashboard/app/demo/analytics/page.tsx
// Demo analytics — the full chart page over the seeded dataset. The KPI strip and every
// chart read the aggregates lib/demo-data derives from the findings, so the numbers here
// always match what the demo finding cards show.
import Link from "next/link";
import { PageHeader, Stat } from "@/components/blocks";
import {
  PackagesBar,
  SeverityDonut,
  TierDonut,
  TrendAreaChart,
} from "@/components/analytics-charts";
import { Card, CardContent } from "@/components/ui/card";
import {
  DEMO_ORG_TREND,
  DEMO_OVERVIEW,
  DEMO_PACKAGES,
  DEMO_RESOLUTION,
} from "@/lib/demo-data";

export const metadata = { title: "Demo analytics" };

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

export default function DemoAnalyticsPage() {
  const protectedRepos = DEMO_OVERVIEW.repo_count - DEMO_OVERVIEW.repos_at_risk;

  return (
    <div>
      <PageHeader
        title="Analytics"
        subtitle={
          <>
            <Link href="/demo" className="link">
              demo
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
              <span className="text-safe">{protectedRepos}</span>
              <span className="text-sm font-normal text-muted-foreground">
                {` of ${DEMO_OVERVIEW.repo_count}`}
              </span>
            </>
          }
        />
        <Stat
          label="Actionable findings"
          value={
            <span className={DEMO_OVERVIEW.actionable > 0 ? "text-risk" : "text-safe"}>
              {DEMO_OVERVIEW.actionable.toLocaleString()}
            </span>
          }
        />
        <Stat
          label="Known-exploited (KEV)"
          value={
            <span className={DEMO_OVERVIEW.kev_count > 0 ? "text-risk" : "text-safe"}>
              {DEMO_OVERVIEW.kev_count.toLocaleString()}
            </span>
          }
        />
        <Stat
          label="Median fix time"
          value={formatMedianDays(DEMO_RESOLUTION.overall.median_days)}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Severity distribution" subtitle="Findings by priority band">
          <SeverityDonut byBand={DEMO_OVERVIEW.by_band} />
        </ChartCard>

        <ChartCard
          title="Reachability split"
          subtitle="What the engine confidently deprioritized vs what needs you"
        >
          <TierDonut byTier={DEMO_OVERVIEW.by_tier} />
        </ChartCard>

        <div className="lg:col-span-2">
          <ChartCard title="90-day trend" subtitle="Per-day findings across all repos">
            <TrendAreaChart
              points={DEMO_ORG_TREND}
              ariaLabel="Actionable versus deprioritized findings across the demo organization over the last 90 days"
            />
          </ChartCard>
        </div>

        <div className="lg:col-span-2">
          <ChartCard
            title="Top risky packages"
            subtitle="By top finding priority — click a bar to open that finding's scan"
          >
            <PackagesBar packages={DEMO_PACKAGES} scanPathPrefix="/demo/scans/" />
          </ChartCard>
        </div>
      </div>
    </div>
  );
}
