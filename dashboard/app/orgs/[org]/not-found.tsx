import Link from "next/link";
import { FullPageNotice } from "@/components/ui";

export default function OrgNotFound() {
  return (
    <FullPageNotice
      title="Organization not found"
      action={
        <Link href="/" className="btn">
          Your organizations
        </Link>
      }
    >
      This organization doesn&apos;t exist, or your account isn&apos;t a member of it.
    </FullPageNotice>
  );
}
