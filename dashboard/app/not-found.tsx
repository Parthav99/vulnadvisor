import Link from "next/link";
import { FullPageNotice } from "@/components/blocks";
import { Button } from "@/components/ui/button";

// Catches notFound() from any segment without its own not-found.tsx, plus all unmatched URLs.
export default function NotFound() {
  return (
    <FullPageNotice
      title="Page not found"
      action={
        <Button asChild variant="outline">
          <Link href="/">Back to home</Link>
        </Button>
      }
    >
      This page doesn&apos;t exist, or you don&apos;t have access to it.
    </FullPageNotice>
  );
}
