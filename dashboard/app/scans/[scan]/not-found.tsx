import Link from "next/link";
import { FullPageNotice } from "@/components/blocks";
import { Button } from "@/components/ui/button";

export default function ScanNotFound() {
  return (
    <FullPageNotice
      title="Scan not found"
      action={
        <Button asChild variant="outline">
          <Link href="/">Back to home</Link>
        </Button>
      }
    >
      This scan doesn&apos;t exist, or it belongs to an organization you&apos;re not a member of.
    </FullPageNotice>
  );
}
