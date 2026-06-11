import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { Badge, EmptyState, PageHeader } from "@/components/ui";
import { FindingCard } from "@/components/finding-card";
import { bandClass, formatDate, shortRef, shortSha } from "@/lib/format";
import type { FindingsResponse, ScanDetail } from "@/lib/types";

const TIERS = ["imported-and-called", "imported", "dynamic-unknown", "not-imported"];
const BANDS = ["critical", "high", "medium", "low", "info"];

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ scan: string }>;
  searchParams: Promise<{ tier?: string; band?: string }>;
}) {
  const { scan: scanId } = await params;
  const { tier, band } = await searchParams;

  const scan = await apiGetOrNull<ScanDetail>(`/v1/scans/${scanId}`);
  if (scan === null) notFound();

  const query = new URLSearchParams();
  if (tier) query.set("tier", tier);
  if (band) query.set("band", band);
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const findings = await apiGetOrNull<FindingsResponse>(`/v1/scans/${scanId}/findings${suffix}`);
  const items = findings?.findings ?? [];

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
              <Badge className="border-[#6e7681] text-[#8b949e] bg-[#6e768122] align-middle">
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

      {scan.degraded_sources.length > 0 ? (
        <div className="card mb-4 border-[#d29922] text-[#e3b341]">
          Degraded sources: {scan.degraded_sources.join(", ")} — results may be incomplete.
        </div>
      ) : null}

      <div className="mb-4 flex flex-wrap items-center gap-2 text-sm">
        <Link href={`/scans/${scanId}`} className={`btn ${tier || band ? "" : "border-[#58a6ff]"}`}>
          all
        </Link>
        {TIERS.map((t) => (
          <Link
            key={t}
            href={`/scans/${scanId}${filterLink({ tier: t, band })}`}
            className={`btn ${tier === t ? "border-[#58a6ff]" : ""}`}
          >
            {t}
          </Link>
        ))}
        {BANDS.map((b) => (
          <Link
            key={b}
            href={`/scans/${scanId}${filterLink({ tier, band: b })}`}
            className={`btn ${band === b ? "border-[#58a6ff]" : ""}`}
          >
            <Badge className={bandClass(b)}>{b}</Badge>
          </Link>
        ))}
      </div>

      {items.length === 0 ? (
        <EmptyState>No findings match this filter.</EmptyState>
      ) : (
        <div className="space-y-4">
          {items.map((finding) => (
            <FindingCard key={`${finding.dependency.name}:${finding.advisory.id}`} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}
