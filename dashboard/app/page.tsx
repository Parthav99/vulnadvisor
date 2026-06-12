import Link from "next/link";
import { apiGetOrNull, installUrl, loginUrl } from "@/lib/api";
import { EmptyState, PageHeader } from "@/components/blocks";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Org } from "@/lib/types";

export default async function Home() {
  const orgs = await apiGetOrNull<Org[]>("/v1/orgs");

  if (orgs === null) {
    return (
      <div className="mx-auto max-w-md">
        <PageHeader
          title="Sign in"
          subtitle="Reachability-first triage for your team's Python dependencies."
        />
        <Card>
          <CardContent>
            <Button asChild variant="outline">
              <a href={loginUrl()}>Sign in with GitHub</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader title="Your organizations" />
      {orgs.length === 0 ? (
        <EmptyState>
          <p>No organizations yet — connect GitHub and your repos sync in one click.</p>
          <div className="mt-4">
            <Button asChild variant="outline">
              <a href={installUrl()}>Install the GitHub App</a>
            </Button>
          </div>
        </EmptyState>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2">
          {orgs.map((org) => (
            <li key={org.id}>
              <Link href={`/orgs/${org.slug}`} className="block">
                <Card size="sm" className="transition-shadow hover:ring-ring/40">
                  <CardContent>
                    <div className="font-semibold">{org.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {org.slug} · {org.role} · {org.plan}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
