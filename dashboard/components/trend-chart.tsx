import type { TrendPoint } from "@/lib/types";

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden style={{ background: color }} className="inline-block h-2 w-3 rounded-sm" />
      {label}
    </span>
  );
}

/** A dependency-free SVG trend of actionable vs deprioritized findings (reachable-called marked). */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return <div className="card muted text-sm">No scans in this window yet.</div>;
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
    <div className="card">
      <div className="mb-3 flex flex-wrap gap-4 text-xs">
        <Legend color="#ff7b72" label="Actionable" />
        <Legend color="#56d364" label="Deprioritized" />
        <Legend color="#d2a8ff" label="Reachable-called" />
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Actionable versus deprioritized findings over time"
        className="w-full"
      >
        <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} stroke="#30363d" />
        <line x1={pad} y1={pad} x2={pad} y2={height - pad} stroke="#30363d" />
        <polyline fill="none" stroke="#ff7b72" strokeWidth="2" points={path((p) => p.actionable)} />
        <polyline
          fill="none"
          stroke="#56d364"
          strokeWidth="2"
          points={path((p) => p.deprioritized)}
        />
        {points.map((p, i) =>
          p.reachable_called > 0 ? (
            <circle key={p.date} cx={x(i)} cy={y(p.actionable)} r="3.5" fill="#d2a8ff" />
          ) : null,
        )}
      </svg>
      <div className="muted mt-2 flex justify-between text-[11px]">
        <span>{points[0].date}</span>
        <span>peak {max}</span>
        <span>{points[points.length - 1].date}</span>
      </div>
    </div>
  );
}
