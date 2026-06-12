import Link from "next/link";
import { apiGetOrNull, installUrl, loginUrl } from "@/lib/api";
import { EmptyState, PageHeader } from "@/components/blocks";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Org, Repo } from "@/lib/types";
import { RepoSetupRow } from "./repo-setup-row";

export const metadata = { title: "Set up repositories" };

// GitHub redirects here after the App is installed (the App's post-install Setup URL),
// with ?installation_id=…&setup_action=… — the webhook has already synced the repos by the
// time the user lands, so the page just reads the current state.
export default async function SetupPage() {
  const orgs = await apiGetOrNull<Org[]>("/v1/orgs");

  if (orgs === null) {
    return (
      <div className="mx-auto max-w-md">
        <PageHeader
          title="Set up repositories"
          subtitle="Sign in first — then this page turns each synced repo into a scanning repo."
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

  const reposByOrg = await Promise.all(
    orgs.map((org) => apiGetOrNull<Repo[]>(`/v1/orgs/${org.slug}/repos`).then((r) => r ?? [])),
  );

  return (
    <div>
      <PageHeader
        title="Set up repositories"
        subtitle={
          <>
            One click per repo: the GitHub App opens a PR adding the VulnAdvisor workflow — merge
            it and scans start arriving. Missing a repo?{" "}
            <a className="link" href={installUrl()}>
              Configure the GitHub App
            </a>
            .
          </>
        }
      />

      {orgs.length === 0 ? (
        <EmptyState>
          No organizations yet.{" "}
          <a className="link" href={installUrl()}>
            Install the GitHub App
          </a>{" "}
          — it syncs your repos and brings you back here.
        </EmptyState>
      ) : (
        orgs.map((org, index) => {
          const repos = reposByOrg[index];
          return (
            <section key={org.id} className="mb-6">
              <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted-foreground uppercase">
                <Link href={`/orgs/${org.slug}`} className="link">
                  {org.name}
                </Link>
              </h2>
              {repos.length === 0 ? (
                <EmptyState>
                  No repositories synced for this org yet — grant the App access to repos when{" "}
                  <a className="link" href={installUrl()}>
                    configuring the installation
                  </a>
                  .
                </EmptyState>
              ) : (
                <ul className="grid gap-2">
                  {repos.map((repo) => (
                    <li key={repo.id}>
                      <RepoSetupRow orgSlug={org.slug} repo={repo} />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          );
        })
      )}
    </div>
  );
}
