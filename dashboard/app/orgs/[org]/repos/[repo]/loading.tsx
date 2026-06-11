import { Skeleton } from "@/components/ui/skeleton";

// Repo: header + trend chart area + scan rows.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading repository">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-64" />
      <Skeleton className="mb-6 h-4 w-96" />
      <Skeleton className="mb-2 h-4 w-28" />
      <Skeleton className="mb-6 h-56" />
      <Skeleton className="mb-2 h-4 w-20" />
      <div className="grid gap-2">
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
      </div>
    </div>
  );
}
