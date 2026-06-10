import Link from "next/link";
import { apiGetOrNull, loginUrl } from "@/lib/api";
import { Card, EmptyState, PageHeader } from "@/components/ui";
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
          <a className="btn" href={loginUrl()}>
            Sign in with GitHub
          </a>
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader title="Your organizations" />
      {orgs.length === 0 ? (
        <EmptyState>No organizations yet. Install the GitHub App to get started.</EmptyState>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2">
          {orgs.map((org) => (
            <li key={org.id}>
              <Link href={`/orgs/${org.slug}`} className="block">
                <Card className="hover:border-[#58a6ff]">
                  <div className="font-semibold">{org.name}</div>
                  <div className="muted text-sm">
                    {org.slug} · {org.role} · {org.plan}
                  </div>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
