import { Skeleton } from "@/components/ui";

// Settings: header + three section cards.
export default function Loading() {
  return (
    <div role="status" aria-label="Loading settings">
      <span className="sr-only">Loading…</span>
      <Skeleton className="mb-2 h-7 w-64" />
      <Skeleton className="mb-6 h-4 w-72" />
      <Skeleton className="mb-2 h-4 w-24" />
      <Skeleton className="mb-6 h-16" />
      <Skeleton className="mb-2 h-4 w-20" />
      <Skeleton className="mb-6 h-16" />
      <Skeleton className="mb-2 h-4 w-28" />
      <Skeleton className="h-16" />
    </div>
  );
}
