// File: dashboard/app/demo/scans/[scan]/page.tsx
// Demo scan page — the three-card finding list with working tier/band filters (pure URL
// params, filtered locally over the seeded findings). Same FindingCard as the product.
import Link from "next/link";
import { notFound } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/blocks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FindingCard } from "@/components/finding-card";
import { demoScanById } from "@/lib/demo-data";
import { codeFindingId, dependencyFindingId } from "@/lib/fix";
import { bandClass, findingKey, formatDate, isCodeFinding, shortRef, shortSha } from "@/lib/format";
import type { ProposedFix } from "@/lib/types";

const TIERS = ["imported-and-called", "imported", "dynamic-unknown", "not-imported"];
const BANDS = ["critical", "high", "medium", "low", "info"];

export async function generateMetadata({ params }: { params: Promise<{ scan: string }> }) {
  const { scan } = await params;
  return { title: `Demo scan ${scan.slice(0, 8)}` };
}

export default async function DemoScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ scan: string }>;
  searchParams: Promise<{ tier?: string; band?: string }>;
}) {
  const { scan: scanId } = await params;
  const { tier, band } = await searchParams;

  const scan = demoScanById(scanId);
  if (scan === null) notFound();

  const items = scan.findings.filter(
    (f) =>
      (!tier || (f.reachability?.tier ?? "unknown") === tier) && (!band || f.score.band === band),
  );
  // Join seeded validated patches to their finding by finding_id, exactly as the product page does.
  const fixesById = new Map<string, ProposedFix>(scan.suggestions.map((s) => [s.finding_id, s]));

  const base = `/demo/scans/${scanId}`;
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
          <>
            Scan <span className="mono">{shortSha(scan.detail.commit_sha)}</span>
          </>
        }
        subtitle={
          <>
            <Link href={`/demo/repos/${scan.repo}`} className="link">
              {scan.repo}
            </Link>{" "}
            · {shortRef(scan.detail.ref)} · {scan.detail.source} · {scan.detail.status} ·{" "}
            {formatDate(scan.detail.created_at)}
          </>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2 text-sm">
        <Button asChild variant="outline" size="sm" className={tier || band ? "" : "border-ring"}>
          <Link href={base}>all</Link>
        </Button>
        {TIERS.map((t) => (
          <Button
            key={t}
            asChild
            variant="outline"
            size="sm"
            className={tier === t ? "border-ring" : ""}
          >
            <Link href={`${base}${filterLink({ tier: t, band })}`}>{t}</Link>
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
            <Link href={`${base}${filterLink({ tier, band: b })}`}>
              <Badge variant="outline" className={bandClass(b)}>
                {b}
              </Badge>
            </Link>
          </Button>
        ))}
      </div>

      {items.length === 0 ? (
        <EmptyState>
          <p>No findings match this filter.</p>
          <p className="mt-4">
            <Link className="link" href={base}>
              Clear the filter
            </Link>
          </p>
        </EmptyState>
      ) : (
        <div className="space-y-4">
          {items.map((finding) => {
            const proposedFix = isCodeFinding(finding)
              ? fixesById.get(codeFindingId(finding))
              : fixesById.get(dependencyFindingId(finding));
            return (
              <FindingCard
                key={findingKey(finding)}
                finding={finding}
                proposedFix={proposedFix}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
