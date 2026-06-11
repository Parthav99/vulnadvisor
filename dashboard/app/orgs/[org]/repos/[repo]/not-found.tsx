import Link from "next/link";
import { FullPageNotice } from "@/components/ui";

export default function RepoNotFound() {
  return (
    <FullPageNotice
      title="Repository not found"
      action={
        <Link href="/" className="btn">
          Back to home
        </Link>
      }
    >
      This repository doesn&apos;t exist in this organization, or you don&apos;t have access to it.
    </FullPageNotice>
  );
}
