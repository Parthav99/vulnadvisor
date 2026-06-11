"use client"; // Error boundaries must be Client Components

import { useEffect } from "react";
import { FullPageNotice } from "@/components/blocks";
import { Button } from "@/components/ui/button";

// Branded fallback for unexpected runtime errors (e.g. the platform API being unreachable).
// Never renders the raw error message — only the opaque digest for support correlation.
export default function Error({
  error,
  unstable_retry,
}: {
  error: Error & { digest?: string };
  unstable_retry: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <FullPageNotice
      title="Something went wrong"
      action={
        <Button type="button" variant="outline" onClick={() => unstable_retry()}>
          Try again
        </Button>
      }
    >
      <p>We couldn&apos;t load this page. The API may be waking up — retry in a moment.</p>
      {error.digest ? <p className="mono mt-3 text-xs">ref {error.digest}</p> : null}
    </FullPageNotice>
  );
}
