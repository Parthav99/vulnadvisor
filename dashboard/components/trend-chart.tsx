import { Card, CardContent } from "@/components/ui/card";
import type { TrendPoint } from "@/lib/types";

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden style={{ background: color }} className="inline-block h-2 w-3 rounded-sm" />
      {label}
    </span>
  );
}

// Aegis state colors (see lib/format.ts): actionable = confirmed risk (red),
// deprioritized = the only safe state (teal accent), reachable-called = strong risk marker.
const ACTIONABLE = "var(--risk)";
const DEPRIORITIZED = "var(--safe)";
const REACHABLE_CALLED = "var(--risk-strong)";
const AXIS = "var(--border)";

/** A dependency-free SVG trend of actionable vs deprioritized findings (reachable-called marked). */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return (
      <Card size="sm">
        <CardContent className="text-sm text-muted-foreground">
          No scans in this window yet.
        </CardContent>
      </Card>
    );
  }

  const width = 720;
  const height = 200;
  const pad = 28;
  const max = Math.max(1, ...points.map((p) => Math.max(p.actionable, p.deprioritized)));
  const n = points.length;
  const x = (i: number) => (n === 1 ? width / 2 : pad + (i * (width - 2 * pad)) / (n - 1));
  const y = (v: number) => height - pad - (v * (height - 2 * pad)) / max;
  const path = (select: (p: TrendPoint) => number) =>
    points.map((p, i) => `${x(i)},${y(select(p))}`).join(" ");

  return (
    <Card size="sm">
      <CardContent>
        <div className="mb-3 flex flex-wrap gap-4 text-xs">
          <Legend color={ACTIONABLE} label="Actionable" />
          <Legend color={DEPRIORITIZED} label="Deprioritized" />
          <Legend color={REACHABLE_CALLED} label="Reachable-called" />
        </div>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label="Actionable versus deprioritized findings over time"
          className="w-full"
        >
          <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} stroke={AXIS} />
          <line x1={pad} y1={pad} x2={pad} y2={height - pad} stroke={AXIS} />
          <polyline
            fill="none"
            stroke={ACTIONABLE}
            strokeWidth="2"
            points={path((p) => p.actionable)}
          />
          <polyline
            fill="none"
            stroke={DEPRIORITIZED}
            strokeWidth="2"
            points={path((p) => p.deprioritized)}
          />
          {points.map((p, i) =>
            p.reachable_called > 0 ? (
              <circle key={p.date} cx={x(i)} cy={y(p.actionable)} r="3.5" fill={REACHABLE_CALLED} />
            ) : null,
          )}
        </svg>
        <div className="mt-2 flex justify-between text-[11px] text-muted-foreground">
          <span>{points[0].date}</span>
          <span>peak {max}</span>
          <span>{points[points.length - 1].date}</span>
        </div>
      </CardContent>
    </Card>
  );
}
