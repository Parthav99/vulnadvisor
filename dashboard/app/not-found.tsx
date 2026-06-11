import Link from "next/link";
import { FullPageNotice } from "@/components/ui";

// Catches notFound() from any segment without its own not-found.tsx, plus all unmatched URLs.
export default function NotFound() {
  return (
    <FullPageNotice
      title="Page not found"
      action={
        <Link href="/" className="btn">
          Back to home
        </Link>
      }
    >
      This page doesn&apos;t exist, or you don&apos;t have access to it.
    </FullPageNotice>
  );
}
