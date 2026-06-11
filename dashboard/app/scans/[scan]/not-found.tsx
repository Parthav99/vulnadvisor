import Link from "next/link";
import { FullPageNotice } from "@/components/ui";

export default function ScanNotFound() {
  return (
    <FullPageNotice
      title="Scan not found"
      action={
        <Link href="/" className="btn">
          Back to home
        </Link>
      }
    >
      This scan doesn&apos;t exist, or it belongs to an organization you&apos;re not a member of.
    </FullPageNotice>
  );
}
