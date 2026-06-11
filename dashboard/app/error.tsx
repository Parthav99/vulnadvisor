"use client"; // Error boundaries must be Client Components

import { useEffect } from "react";
import { FullPageNotice } from "@/components/ui";

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
        <button type="button" className="btn" onClick={() => unstable_retry()}>
          Try again
        </button>
      }
    >
      <p>We couldn&apos;t load this page. The API may be waking up — retry in a moment.</p>
      {error.digest ? <p className="mono mt-3 text-xs">ref {error.digest}</p> : null}
    </FullPageNotice>
  );
}
