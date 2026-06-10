import { Badge } from "@/components/ui";
import { bandClass, displayId, tierClass, tierLabel } from "@/lib/format";
import type { Finding } from "@/lib/types";

function Card3({ letter, title, children }: { letter: string; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-[#30363d] bg-[#0d1117] p-3">
      <div className="muted mb-1 text-xs font-semibold uppercase tracking-wide">
        {letter} · {title}
      </div>
      <div className="text-sm">{children}</div>
    </div>
  );
}

/** One finding rendered as the signature three cards: Attack story / Risk / Action. */
export function FindingCard({ finding }: { finding: Finding }) {
  const { dependency, advisory, score, reachability, fix, epss, in_kev } = finding;
  const tier = reachability?.tier ?? "unknown";
  const version = dependency.version || "(unpinned)";

  return (
    <article className="card space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mono font-semibold">{displayId(advisory)}</span>
        <span className="muted">·</span>
        <span className="mono">
          {dependency.name} {version}
        </span>
        <span className="ml-auto flex items-center gap-2">
          <Badge className={bandClass(score.band)}>
            {score.band} · {Math.round(score.value)}
          </Badge>
          <Badge className={tierClass(tier)}>{tierLabel(tier)}</Badge>
          {in_kev ? <Badge className={bandClass("critical")}>KEV</Badge> : null}
        </span>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Card3 letter="A" title="Attack story">
          <p>{score.verdict || advisory.summary || "No summary available."}</p>
          {score.rationale ? <p className="muted mt-1">{score.rationale}</p> : null}
        </Card3>

        <Card3 letter="B" title="Risk">
          <ul className="space-y-0.5">
            <li>
              Priority <span className="font-semibold">{Math.round(score.value)}</span> ({score.band})
            </li>
            {epss ? (
              <li>EPSS {(epss.probability * 100).toFixed(1)}% (p{Math.round(epss.percentile * 100)})</li>
            ) : (
              <li className="muted">EPSS unavailable</li>
            )}
            <li>{in_kev ? "Listed in CISA KEV" : "Not in CISA KEV"}</li>
          </ul>
        </Card3>

        <Card3 letter="C" title="Action">
          {fix.command ? (
            <code className="mono block break-all rounded bg-[#161b22] px-2 py-1">{fix.command}</code>
          ) : (
            <p className="muted">No fixed version available yet.</p>
          )}
          {reachability?.reason ? <p className="muted mt-2">{reachability.reason}</p> : null}
        </Card3>
      </div>

      {reachability?.call_paths && reachability.call_paths.length > 0 ? (
        <div>
          <div className="muted text-xs font-semibold uppercase tracking-wide">Call path</div>
          <ul className="mono mt-1 space-y-0.5 text-xs">
            {reachability.call_paths.map((p) => (
              <li key={p} className="break-all text-[#ff7b72]">
                {p}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {reachability?.evidence && reachability.evidence.length > 0 ? (
        <div className="muted mono text-xs">
          Imported at{" "}
          {reachability.evidence.slice(0, 3).map((e, i) => (
            <span key={`${e.file}:${e.line}`}>
              {i > 0 ? ", " : ""}
              {e.file}:{e.line}
            </span>
          ))}
        </div>
      ) : null}
    </article>
  );
}
