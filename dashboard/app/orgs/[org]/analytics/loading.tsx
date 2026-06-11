import { Skeleton } from "@/components/ui/skeleton";

// Analytics: header + KPI strip + two donuts + two full-width charts.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading analytics">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-40" />
      <Skeleton className="mb-6 h-4 w-72" />
      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
        <Skeleton className="h-20" />
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Skeleton className="h-72" />
        <Skeleton className="h-72" />
        <Skeleton className="h-72 lg:col-span-2" />
        <Skeleton className="h-72 lg:col-span-2" />
      </div>
    </div>
  );
}
