import { Skeleton } from "@/components/ui";

// Diff: header + stat strip + introduced/fixed sections.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading scan diff">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-40" />
      <Skeleton className="mb-6 h-4 w-80" />
      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
      </div>
      <Skeleton className="mb-2 h-4 w-24" />
      <Skeleton className="mb-6 h-44" />
      <Skeleton className="mb-2 h-4 w-16" />
      <Skeleton className="h-14" />
    </div>
  );
}
