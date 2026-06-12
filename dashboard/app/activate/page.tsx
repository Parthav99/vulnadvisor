import { apiGetOrNull, loginUrl } from "@/lib/api";
import { PageHeader } from "@/components/blocks";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Org } from "@/lib/types";
import { ActivateForm } from "./activate-form";

export const metadata = { title: "Activate device" };

export default async function ActivatePage({
  searchParams,
}: {
  searchParams: Promise<{ code?: string }>;
}) {
  const { code } = await searchParams;
  const orgs = await apiGetOrNull<Org[]>("/v1/orgs");

  if (orgs === null) {
    return (
      <div className="mx-auto max-w-md">
        <PageHeader
          title="Activate device"
          subtitle="Sign in first, then return to this page to approve your CLI login."
        />
        <Card>
          <CardContent>
            <Button asChild variant="outline">
              <a href={loginUrl()}>Sign in with GitHub</a>
            </Button>
            <p className="mt-3 text-xs text-muted-foreground">
              After signing in, open the activation link from your terminal again (or navigate
              back to /activate).
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Activate device"
        subtitle="Approve the code shown by `vulnadvisor login` to connect that machine to an org."
      />
      <ActivateForm orgs={orgs} initialCode={code ?? ""} />
      <p className="mt-4 text-xs text-muted-foreground">
        Approving mints an org-scoped API key for that device. You can revoke it any time under
        Settings → API keys.
      </p>
    </div>
  );
}
