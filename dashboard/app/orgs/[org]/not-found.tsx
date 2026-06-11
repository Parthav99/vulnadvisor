import Link from "next/link";
import { FullPageNotice } from "@/components/blocks";
import { Button } from "@/components/ui/button";

export default function OrgNotFound() {
  return (
    <FullPageNotice
      title="Organization not found"
      action={
        <Button asChild variant="outline">
          <Link href="/">Your organizations</Link>
        </Button>
      }
    >
      This organization doesn&apos;t exist, or your account isn&apos;t a member of it.
    </FullPageNotice>
  );
}
