import { Skeleton } from "@/components/ui/skeleton";

// API keys: header + create card + key rows.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading API keys">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-64" />
      <Skeleton className="mb-6 h-4 w-80" />
      <Skeleton className="mb-4 h-24" />
      <div className="grid gap-2">
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
      </div>
    </div>
  );
}
