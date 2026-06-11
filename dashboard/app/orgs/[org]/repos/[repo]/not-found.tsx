import Link from "next/link";
import { FullPageNotice } from "@/components/blocks";
import { Button } from "@/components/ui/button";

export default function RepoNotFound() {
  return (
    <FullPageNotice
      title="Repository not found"
      action={
        <Button asChild variant="outline">
          <Link href="/">Back to home</Link>
        </Button>
      }
    >
      This repository doesn&apos;t exist in this organization, or you don&apos;t have access to it.
    </FullPageNotice>
  );
}
