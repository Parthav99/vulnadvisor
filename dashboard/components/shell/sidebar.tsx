"use client";

import { useMemo } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  Check,
  ChevronsUpDown,
  FolderGit2,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Brand } from "@/components/shell/brand";
import type { Org } from "@/lib/types";
import { cn } from "@/lib/utils";

function OrgSwitcher({ orgs, currentSlug }: { orgs: Org[]; currentSlug: string | null }) {
  const current = orgs.find((org) => org.slug === currentSlug) ?? null;
  if (orgs.length === 0) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" className="w-full justify-between font-normal">
          <span className="truncate">{current ? current.name : "Choose organization"}</span>
          <ChevronsUpDown aria-hidden className="text-muted-foreground" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-(--radix-dropdown-menu-trigger-width)">
        <DropdownMenuLabel>Organizations</DropdownMenuLabel>
        {orgs.map((org) => (
          <DropdownMenuItem key={org.id} asChild>
            <Link href={`/orgs/${org.slug}`}>
              <span className="truncate">{org.name}</span>
              {org.slug === currentSlug ? <Check aria-hidden className="ml-auto" /> : null}
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function NavItem({
  href,
  icon: Icon,
  label,
  active,
  disabled,
  badge,
}: {
  href?: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  label: string;
  active?: boolean;
  disabled?: boolean;
  badge?: string;
}) {
  const className = cn(
    "flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors",
    active
      ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
      : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
    disabled && "cursor-default opacity-50 hover:bg-transparent hover:text-muted-foreground",
  );
  const body = (
    <>
      <Icon aria-hidden className="size-4 shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      {badge ? (
        <Badge variant="outline" className="text-muted-foreground">
          {badge}
        </Badge>
      ) : null}
    </>
  );
  if (disabled || !href) {
    return <span className={className}>{body}</span>;
  }
  return (
    <Link href={href} className={className} aria-current={active ? "page" : undefined}>
      {body}
    </Link>
  );
}

/** Left sidebar: brand, org switcher, main nav, trust footer. Hidden below md. */
export function Sidebar({ orgs }: { orgs: Org[] }) {
  const pathname = usePathname();

  // Current org from the URL when on an org-scoped route; otherwise the first org,
  // so the sidebar always has a sane navigation target.
  const orgSlug = useMemo(() => {
    const match = /^\/orgs\/([^/]+)/.exec(pathname);
    return match ? decodeURIComponent(match[1]) : (orgs[0]?.slug ?? null);
  }, [pathname, orgs]);

  return (
    <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col gap-4 border-r border-sidebar-border bg-sidebar/80 px-3 py-4 backdrop-blur md:flex">
      <Brand className="px-2" />
      <OrgSwitcher orgs={orgs} currentSlug={orgSlug} />
      {orgSlug ? (
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          <NavItem
            href={`/orgs/${orgSlug}`}
            icon={FolderGit2}
            label="Repos"
            active={
              pathname === `/orgs/${orgSlug}` || pathname.startsWith(`/orgs/${orgSlug}/repos`)
            }
          />
          <NavItem icon={BarChart3} label="Analytics" disabled badge="Soon" />
          <NavItem
            href={`/orgs/${orgSlug}/settings`}
            icon={Settings}
            label="Settings"
            active={pathname.startsWith(`/orgs/${orgSlug}/settings`)}
          />
        </nav>
      ) : null}
      <div className="mt-auto flex items-center gap-2 px-2 text-xs text-muted-foreground">
        <ShieldCheck aria-hidden className="size-3.5 shrink-0 text-safe" />
        Local-first · no telemetry
      </div>
    </aside>
  );
}
