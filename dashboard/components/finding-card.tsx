import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { bandClass, displayId, tierClass, tierLabel } from "@/lib/format";
import type { Finding } from "@/lib/types";

function Card3({ letter, title, children }: { letter: string; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg bg-background/60 p-3 ring-1 ring-border">
      <div className="mb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
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
    <Card className="gap-3">
      <CardContent>
        <article className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono font-semibold">{displayId(advisory)}</span>
            <span className="text-muted-foreground">·</span>
            <span className="mono">
              {dependency.name} {version}
            </span>
            <span className="ml-auto flex items-center gap-2">
              <Badge variant="outline" className={bandClass(score.band)}>
                {score.band} · {Math.round(score.value)}
              </Badge>
              <Badge variant="outline" className={tierClass(tier)}>
                {tierLabel(tier)}
              </Badge>
              {in_kev ? (
                <Badge variant="outline" className={bandClass("critical")}>
                  KEV
                </Badge>
              ) : null}
            </span>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <Card3 letter="A" title="Attack story">
              <p>{score.verdict || advisory.summary || "No summary available."}</p>
              {score.rationale ? (
                <p className="mt-1 text-muted-foreground">{score.rationale}</p>
              ) : null}
            </Card3>

            <Card3 letter="B" title="Risk">
              <ul className="space-y-0.5">
                <li>
                  Priority <span className="font-semibold">{Math.round(score.value)}</span> (
                  {score.band})
                </li>
                {epss ? (
                  <li>
                    EPSS {(epss.probability * 100).toFixed(1)}% (p
                    {Math.round(epss.percentile * 100)})
                  </li>
                ) : (
                  <li className="text-muted-foreground">EPSS unavailable</li>
                )}
                <li>{in_kev ? "Listed in CISA KEV" : "Not in CISA KEV"}</li>
              </ul>
            </Card3>

            <Card3 letter="C" title="Action">
              {fix.command ? (
                <code className="mono block rounded bg-secondary px-2 py-1 break-all">
                  {fix.command}
                </code>
              ) : (
                <p className="text-muted-foreground">No fixed version available yet.</p>
              )}
              {reachability?.reason ? (
                <p className="mt-2 text-muted-foreground">{reachability.reason}</p>
              ) : null}
            </Card3>
          </div>

          {reachability?.call_paths && reachability.call_paths.length > 0 ? (
            <div>
              <div className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                Call path
              </div>
              <ul className="mono mt-1 space-y-0.5 text-xs">
                {reachability.call_paths.map((p) => (
                  <li key={p} className="break-all text-risk">
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {reachability?.evidence && reachability.evidence.length > 0 ? (
            <div className="mono text-xs text-muted-foreground">
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
      </CardContent>
    </Card>
  );
}
