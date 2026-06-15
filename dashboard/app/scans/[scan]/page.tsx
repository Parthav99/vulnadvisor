import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader } from "@/components/blocks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { FindingCard } from "@/components/finding-card";
import { matchesFocus } from "@/lib/copilot-ui";
import { codeFindingId, dependencyFindingId } from "@/lib/fix";
import { bandClass, findingKey, formatDate, isCodeFinding, shortRef, shortSha } from "@/lib/format";
import type { FindingsResponse, ProposedFix, ScanDetail } from "@/lib/types";

const TIERS = ["imported-and-called", "imported", "dynamic-unknown", "not-imported"];
const BANDS = ["critical", "high", "medium", "low", "info"];

export async function generateMetadata({ params }: { params: Promise<{ scan: string }> }) {
  const { scan } = await params;
  return { title: `Scan ${scan.slice(0, 8)}` };
}

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ scan: string }>;
  searchParams: Promise<{ tier?: string; band?: string; finding?: string }>;
}) {
  const { scan: scanId } = await params;
  const { tier, band, finding: focus } = await searchParams;

  const scan = await apiGetOrNull<ScanDetail>(`/v1/scans/${scanId}`);
  if (scan === null) notFound();

  const query = new URLSearchParams();
  if (tier) query.set("tier", tier);
  if (band) query.set("band", band);
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const findings = await apiGetOrNull<FindingsResponse>(`/v1/scans/${scanId}/findings${suffix}`);
  const items = findings?.findings ?? [];
  // Validated patches (Task 17.5) are joined to their code finding by finding_id client-side; a
  // finding without a stored fix simply gets none (no panel rendered).
  const fixesById = new Map<string, ProposedFix>(
    (findings?.suggestions ?? []).map((s) => [s.finding_id, s]),
  );

  const filterLink = (next: { tier?: string; band?: string }) => {
    const q = new URLSearchParams();
    if (next.tier) q.set("tier", next.tier);
    if (next.band) q.set("band", next.band);
    return q.toString() ? `?${q.toString()}` : "";
  };

  return (
    <div>
      <PageHeader
        title={
          shortSha(scan.commit_sha) ? (
            <>
              Scan <span className="mono">{shortSha(scan.commit_sha)}</span>
            </>
          ) : (
            <>
              Scan{" "}
              <Badge variant="outline" className="align-middle text-muted-foreground">
                local scan
              </Badge>
            </>
          )
        }
        subtitle={
          <>
            {shortRef(scan.ref) ? `${shortRef(scan.ref)} · ` : ""}
            {scan.pr_number ? `PR #${scan.pr_number} · ` : ""}
            {scan.source} · {scan.status} · {formatDate(scan.created_at)}
          </>
        }
      />

      {(scan.degraded_sources ?? []).length > 0 ? (
        <Card size="sm" className="mb-4 ring-warn/50">
          <CardContent className="text-warn">
            Degraded sources: {scan.degraded_sources.join(", ")} — results may be incomplete.
          </CardContent>
        </Card>
      ) : null}

      <div className="mb-4 flex flex-wrap items-center gap-2 text-sm">
        <Button asChild variant="outline" size="sm" className={tier || band ? "" : "border-ring"}>
          <Link href={`/scans/${scanId}`}>all</Link>
        </Button>
        {TIERS.map((t) => (
          <Button
            key={t}
            asChild
            variant="outline"
            size="sm"
            className={tier === t ? "border-ring" : ""}
          >
            <Link href={`/scans/${scanId}${filterLink({ tier: t, band })}`}>{t}</Link>
          </Button>
        ))}
        {BANDS.map((b) => (
          <Button
            key={b}
            asChild
            variant="outline"
            size="sm"
            className={band === b ? "border-ring" : ""}
          >
            <Link href={`/scans/${scanId}${filterLink({ tier, band: b })}`}>
              <Badge variant="outline" className={bandClass(b)}>
                {b}
              </Badge>
            </Link>
          </Button>
        ))}
      </div>

      {items.length === 0 ? (
        <EmptyState>
          {tier || band ? (
            <>
              No findings match this filter —{" "}
              <Link className="link" href={`/scans/${scanId}`}>
                clear the filter
              </Link>
              .
            </>
          ) : (
            <>
              This scan reported no findings — keep it that way with{" "}
              <code className="mono text-foreground">vulnadvisor scan . --fail-on high</code> in
              CI.
            </>
          )}
        </EmptyState>
      ) : (
        <div className="space-y-4">
          {items.map((finding) => {
            const focused = focus !== undefined && matchesFocus(finding, focus);
            const proposedFix = isCodeFinding(finding)
              ? fixesById.get(codeFindingId(finding))
              : fixesById.get(dependencyFindingId(finding));
            return (
              <FindingCard
                key={findingKey(finding)}
                finding={finding}
                defaultOpen={focused}
                focus={focused}
                proposedFix={proposedFix}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
