import { Skeleton } from "@/components/ui/skeleton";

// Setup: header + per-org repo rows.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading repository setup">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-64" />
      <Skeleton className="mb-6 h-4 w-96" />
      <Skeleton className="mb-2 h-4 w-32" />
      <div className="grid gap-2">
        <Skeleton className="h-16" />
        <Skeleton className="h-16" />
        <Skeleton className="h-16" />
      </div>
    </div>
  );
}
