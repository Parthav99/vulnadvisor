import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGetOrNull } from "@/lib/api";
import { PageHeader } from "@/components/ui";
import type { ApiKey, OrgDetail } from "@/lib/types";
import { KeysManager } from "./keys-manager";

export async function generateMetadata({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  return { title: `API keys · ${org}` };
}

export default async function ApiKeysPage({ params }: { params: Promise<{ org: string }> }) {
  const { org: slug } = await params;
  const org = await apiGetOrNull<OrgDetail>(`/v1/orgs/${slug}`);
  if (org === null) notFound();
  const keys = (await apiGetOrNull<ApiKey[]>(`/v1/orgs/${slug}/api-keys`)) ?? [];

  return (
    <div>
      <PageHeader
        title={`${org.name} · API keys`}
        subtitle={
          <>
            Upload scan reports from CI/CLI ·{" "}
            <Link className="link" href={`/orgs/${slug}/settings`}>
              back to settings
            </Link>
          </>
        }
      />
      <KeysManager slug={slug} initialKeys={keys} />
      <p className="muted mt-4 text-xs">
        Keys are org-scoped and shown only once at creation. Source code never leaves your machine —
        only the JSON report is uploaded.
      </p>
    </div>
  );
}
