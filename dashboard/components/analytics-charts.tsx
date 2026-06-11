"use client";

// Aegis-themed charts for the analytics page (Task 13.4), built on the shadcn chart kit
// (Recharts). Color semantics come from the design tokens and match lib/format.ts exactly:
// red = confirmed risk, amber = uncertainty, blue = low, teal (--safe) only for safe states.
// Every chart carries role="img" + aria-label; pages own the empty/teaching states.

import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Label,
  Line,
  Pie,
  PieChart,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import type { PackageRisk, TrendPoint } from "@/lib/types";

// Band colors mirror lib/format.ts text colors; tier colors mirror the badge semantics.
const BAND_COLORS: Record<string, string> = {
  critical: "var(--risk)",
  high: "var(--elevated)",
  medium: "var(--warn)",
  low: "var(--info)",
  info: "var(--muted-foreground)",
};

const TIER_COLORS: Record<string, string> = {
  "imported-and-called": "var(--risk)",
  imported: "var(--warn)",
  // Uncertainty stays in the amber family but visibly lighter — unresolved, never safe-looking.
  "dynamic-unknown": "color-mix(in srgb, var(--warn) 55%, transparent)",
  "not-imported": "var(--safe)",
};

const BAND_ORDER = ["critical", "high", "medium", "low", "info"];
const TIER_ORDER = ["imported-and-called", "imported", "dynamic-unknown", "not-imported"];

const TIER_SHORT_LABELS: Record<string, string> = {
  "imported-and-called": "Imported & called",
  imported: "Imported",
  "dynamic-unknown": "Dynamic unknown",
  "not-imported": "Not imported (deprioritized)",
};

function donutData(
  counts: Record<string, number>,
  order: string[],
  colors: Record<string, string>,
) {
  return order
    .map((key) => ({ key, count: counts[key] ?? 0, fill: colors[key] }))
    .filter((d) => d.count > 0);
}

/** Donut of findings per priority band, with the total in the center. */
export function SeverityDonut({ byBand }: { byBand: Record<string, number> }) {
  const data = donutData(byBand, BAND_ORDER, BAND_COLORS);
  const total = data.reduce((sum, d) => sum + d.count, 0);
  const config: ChartConfig = Object.fromEntries(
    BAND_ORDER.map((band) => [band, { label: band, color: BAND_COLORS[band] }]),
  );

  return (
    <ChartContainer
      config={config}
      role="img"
      aria-label={`Severity distribution: ${data.map((d) => `${d.count} ${d.key}`).join(", ")}`}
      className="mx-auto aspect-square max-h-56 w-full"
    >
      <PieChart>
        <ChartTooltip content={<ChartTooltipContent nameKey="key" hideLabel />} />
        <Pie
          data={data}
          dataKey="count"
          nameKey="key"
          innerRadius={55}
          strokeWidth={2}
          isAnimationActive={false}
        >
          <Label
            content={({ viewBox }) => {
              if (!viewBox || !("cx" in viewBox) || viewBox.cx == null || viewBox.cy == null)
                return null;
              return (
                <text x={viewBox.cx} y={viewBox.cy} textAnchor="middle" dominantBaseline="middle">
                  <tspan
                    x={viewBox.cx}
                    y={viewBox.cy}
                    className="fill-foreground text-2xl font-semibold"
                  >
                    {total.toLocaleString()}
                  </tspan>
                  <tspan x={viewBox.cx} y={viewBox.cy + 20} className="fill-muted-foreground">
                    findings
                  </tspan>
                </text>
              );
            }}
          />
        </Pie>
        <ChartLegend content={<ChartLegendContent nameKey="key" />} />
      </PieChart>
    </ChartContainer>
  );
}

/** Donut of findings per reachability tier — the noise-reduction story. Center shows the
 *  percentage the engine confidently deprioritized (not-imported, the only safe tier). */
export function TierDonut({ byTier }: { byTier: Record<string, number> }) {
  const data = donutData(byTier, TIER_ORDER, TIER_COLORS);
  const total = data.reduce((sum, d) => sum + d.count, 0);
  const deprioritized = byTier["not-imported"] ?? 0;
  const pct = total > 0 ? Math.round((deprioritized / total) * 100) : 0;
  const config: ChartConfig = Object.fromEntries(
    TIER_ORDER.map((tier) => [tier, { label: TIER_SHORT_LABELS[tier], color: TIER_COLORS[tier] }]),
  );

  return (
    <ChartContainer
      config={config}
      role="img"
      aria-label={`Reachability tier split: ${data
        .map((d) => `${d.count} ${TIER_SHORT_LABELS[d.key]}`)
        .join(", ")}; ${pct}% deprioritized`}
      className="mx-auto aspect-square max-h-56 w-full"
    >
      <PieChart>
        <ChartTooltip content={<ChartTooltipContent nameKey="key" hideLabel />} />
        <Pie
          data={data}
          dataKey="count"
          nameKey="key"
          innerRadius={55}
          strokeWidth={2}
          isAnimationActive={false}
        >
          <Label
            content={({ viewBox }) => {
              if (!viewBox || !("cx" in viewBox) || viewBox.cx == null || viewBox.cy == null)
                return null;
              return (
                <text x={viewBox.cx} y={viewBox.cy} textAnchor="middle" dominantBaseline="middle">
                  <tspan
                    x={viewBox.cx}
                    y={viewBox.cy}
                    className="fill-safe text-2xl font-semibold"
                  >
                    {pct}%
                  </tspan>
                  <tspan x={viewBox.cx} y={viewBox.cy + 20} className="fill-muted-foreground">
                    deprioritized
                  </tspan>
                </text>
              );
            }}
          />
        </Pie>
        <ChartLegend content={<ChartLegendContent nameKey="key" />} />
      </PieChart>
    </ChartContainer>
  );
}

const TREND_CONFIG: ChartConfig = {
  actionable: { label: "Actionable", color: "var(--risk)" },
  deprioritized: { label: "Deprioritized", color: "var(--safe)" },
  reachable_called: { label: "Reachable-called", color: "var(--risk-strong)" },
};

/** Stacked area trend (actionable over deprioritized) with the reachable-called line on top.
 *  Reachable-called is a subset of actionable, so it is drawn as a line, never stacked. */
export function TrendAreaChart({ points, ariaLabel }: { points: TrendPoint[]; ariaLabel: string }) {
  if (points.length === 0) return null;
  return (
    <ChartContainer
      config={TREND_CONFIG}
      role="img"
      aria-label={ariaLabel}
      className="aspect-auto h-56 w-full"
    >
      <ComposedChart data={points} margin={{ left: -16, right: 8, top: 8 }}>
        <CartesianGrid vertical={false} />
        <XAxis
          dataKey="date"
          tickLine={false}
          axisLine={false}
          minTickGap={32}
          tickFormatter={(value: string) => value.slice(5)}
        />
        <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
        <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
        <Area
          dataKey="deprioritized"
          stackId="findings"
          type="monotone"
          fill="var(--safe)"
          fillOpacity={0.25}
          stroke="var(--safe)"
          isAnimationActive={false}
        />
        <Area
          dataKey="actionable"
          stackId="findings"
          type="monotone"
          fill="var(--risk)"
          fillOpacity={0.3}
          stroke="var(--risk)"
          isAnimationActive={false}
        />
        <Line
          dataKey="reachable_called"
          type="monotone"
          stroke="var(--risk-strong)"
          strokeWidth={2}
          dot={false}
          isAnimationActive={false}
        />
        <ChartLegend content={<ChartLegendContent />} />
      </ComposedChart>
    </ChartContainer>
  );
}

const PACKAGES_CONFIG: ChartConfig = {
  max_priority: { label: "Top priority" },
};

/** Horizontal bars of the riskiest packages by top priority (0–100), colored by band.
 *  Clicking a bar opens the scan holding that package's top-priority finding; an sr-only
 *  link list provides the same click-through for keyboard and screen-reader users. */
export function PackagesBar({ packages }: { packages: PackageRisk[] }) {
  const router = useRouter();
  if (packages.length === 0) return null;
  const height = Math.max(160, packages.length * 36 + 48);

  return (
    <div>
      <ChartContainer
        config={PACKAGES_CONFIG}
        role="img"
        aria-label={`Top risky packages: ${packages
          .map((p) => `${p.package} priority ${Math.round(p.max_priority)}`)
          .join(", ")}`}
        className="aspect-auto w-full"
        style={{ height }}
      >
        <BarChart
          data={packages}
          layout="vertical"
          margin={{ left: 8, right: 8, top: 4, bottom: 20 }}
        >
          <CartesianGrid horizontal={false} />
          <XAxis
            type="number"
            domain={[0, 100]}
            tickLine={false}
            axisLine={false}
            label={{
              value: "priority (0–100)",
              position: "bottom",
              offset: 0,
              className: "fill-muted-foreground",
            }}
          />
          <YAxis
            dataKey="package"
            type="category"
            width={110}
            tickLine={false}
            axisLine={false}
            className="mono"
          />
          <ChartTooltip
            content={
              <ChartTooltipContent
                hideLabel
                formatter={(value, _name, item) => {
                  const pkg = item?.payload as PackageRisk | undefined;
                  return (
                    <span className="flex w-full justify-between gap-4">
                      <span className="text-muted-foreground">
                        {pkg
                          ? `${pkg.package} · ${pkg.finding_count} finding${
                              pkg.finding_count === 1 ? "" : "s"
                            } · ${pkg.repo_count} repo${pkg.repo_count === 1 ? "" : "s"}`
                          : "priority"}
                      </span>
                      <span className="font-mono font-medium tabular-nums">
                        {typeof value === "number" ? value.toFixed(1) : String(value)}
                      </span>
                    </span>
                  );
                }}
              />
            }
          />
          <Bar dataKey="max_priority" radius={4} isAnimationActive={false}>
            {packages.map((pkg) => (
              <Cell
                key={pkg.package}
                fill={BAND_COLORS[pkg.band] ?? BAND_COLORS.info}
                cursor={pkg.top_scan_id ? "pointer" : undefined}
                onClick={() => {
                  if (pkg.top_scan_id) router.push(`/scans/${pkg.top_scan_id}`);
                }}
              />
            ))}
          </Bar>
        </BarChart>
      </ChartContainer>
      <ul className="sr-only">
        {packages.map((pkg) =>
          pkg.top_scan_id ? (
            <li key={pkg.package}>
              <Link href={`/scans/${pkg.top_scan_id}`}>
                Open the scan with {pkg.package}&apos;s top finding
              </Link>
            </li>
          ) : null,
        )}
      </ul>
    </div>
  );
}
