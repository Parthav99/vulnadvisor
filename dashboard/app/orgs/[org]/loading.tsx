import { Skeleton } from "@/components/ui";

// Org: header + stat strip + repo rows.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading organization">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-64" />
      <Skeleton className="mb-6 h-4 w-96" />
      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
      </div>
      <Skeleton className="mb-2 h-4 w-32" />
      <div className="grid gap-3">
        <Skeleton className="h-16" />
        <Skeleton className="h-16" />
        <Skeleton className="h-16" />
      </div>
    </div>
  );
}
