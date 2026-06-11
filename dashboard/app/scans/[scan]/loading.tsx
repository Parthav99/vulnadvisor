import { Skeleton } from "@/components/ui/skeleton";

// Scan: header + filter bar + three-card finding skeletons.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading scan">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-56" />
      <Skeleton className="mb-6 h-4 w-80" />
      <div className="mb-4 flex flex-wrap gap-2">
        <Skeleton className="h-8 w-14" />
        <Skeleton className="h-8 w-36" />
        <Skeleton className="h-8 w-24" />
        <Skeleton className="h-8 w-32" />
        <Skeleton className="h-8 w-28" />
      </div>
      <div className="space-y-4">
        <Skeleton className="h-44" />
        <Skeleton className="h-44" />
        <Skeleton className="h-44" />
      </div>
    </div>
  );
}
