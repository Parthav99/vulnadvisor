import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { EmptyState, PageHeader, Stat } from "@/components/blocks";
import { Card, CardContent } from "@/components/ui/card";
import { FindingCard } from "@/components/finding-card";
import { displayId, findingKey, isCodeFinding } from "@/lib/format";
import type { DiffResponse } from "@/lib/types";

export const metadata = { title: "Scan diff" };

// Route: /scans/{from}/diff/{to} — the `scan` slug is the "from" scan (kept consistent with the
// sibling /scans/[scan] route, which Next requires to share the same slug name).
export default async function DiffPage({
  params,
}: {
  params: Promise<{ scan: string; to: string }>;
}) {
  const { scan: from, to } = await params;
  const diff = await apiGetOrNull<DiffResponse>(`/v1/scans/${from}/diff/${to}`);
  if (diff === null) notFound();

  return (
    <div>
      <PageHeader title="Scan diff" subtitle="Findings introduced and fixed between two scans." />

      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat label="Introduced" value={diff.introduced.length} />
        <Stat label="Fixed" value={diff.fixed.length} />
        <Stat label="Unchanged" value={diff.unchanged} />
      </div>

      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-risk uppercase">
          Introduced
        </h2>
        {diff.introduced.length === 0 ? (
          <EmptyState>No new findings — nice.</EmptyState>
        ) : (
          <div className="space-y-4">
            {diff.introduced.map((finding) => (
              <FindingCard key={findingKey(finding)} finding={finding} />
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold tracking-wide text-safe uppercase">Fixed</h2>
        {diff.fixed.length === 0 ? (
          <EmptyState>No findings were fixed.</EmptyState>
        ) : (
          <ul className="grid gap-2">
            {diff.fixed.map((finding) => (
              <li key={findingKey(finding)}>
                <Card size="sm" className="flex-row items-center justify-between">
                  <CardContent>
                    <span className="mono">
                      {isCodeFinding(finding)
                        ? `${finding.rule.title} (${finding.location.file}:${finding.location.line})`
                        : `${finding.dependency.name} ${finding.dependency.version || "(unpinned)"}`}
                    </span>
                  </CardContent>
                  <CardContent>
                    <span className="mono text-xs text-muted-foreground">
                      {isCodeFinding(finding) ? finding.rule.cwe : displayId(finding.advisory)}
                    </span>
                  </CardContent>
                </Card>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
