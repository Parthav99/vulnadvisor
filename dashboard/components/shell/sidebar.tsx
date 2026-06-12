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
  dataTour,
}: {
  href?: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  label: string;
  active?: boolean;
  disabled?: boolean;
  badge?: string;
  dataTour?: string;
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
    <Link
      href={href}
      className={className}
      aria-current={active ? "page" : undefined}
      data-tour={dataTour}
    >
      {body}
    </Link>
  );
}

/** Left sidebar: brand, org switcher, main nav, trust footer. Hidden below md.
 *  On /demo routes the nav points at the demo org instead — same frame, sample data. */
export function Sidebar({ orgs }: { orgs: Org[] }) {
  const pathname = usePathname();
  const isDemo = pathname === "/demo" || pathname.startsWith("/demo/");

  // Current org from the URL when on an org-scoped route; otherwise the first org,
  // so the sidebar always has a sane navigation target.
  const orgSlug = useMemo(() => {
    const match = /^\/orgs\/([^/]+)/.exec(pathname);
    return match ? decodeURIComponent(match[1]) : (orgs[0]?.slug ?? null);
  }, [pathname, orgs]);

  return (
    <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col gap-4 border-r border-sidebar-border bg-sidebar/80 px-3 py-4 backdrop-blur md:flex">
      <Brand className="px-2" />
      {isDemo ? (
        <div className="flex items-center justify-between rounded-md border px-3 py-1.5 text-sm">
          <span className="truncate">Acme Robotics</span>
          <Badge variant="outline" className="text-warn">
            demo
          </Badge>
        </div>
      ) : (
        <OrgSwitcher orgs={orgs} currentSlug={orgSlug} />
      )}
      {isDemo ? (
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          <NavItem
            href="/demo"
            icon={FolderGit2}
            label="Repos"
            active={pathname === "/demo" || pathname.startsWith("/demo/repos")}
          />
          <NavItem
            href="/demo/analytics"
            icon={BarChart3}
            label="Analytics"
            active={pathname.startsWith("/demo/analytics")}
            dataTour="nav-analytics"
          />
          <NavItem icon={Settings} label="Settings" disabled badge="demo" />
        </nav>
      ) : orgSlug ? (
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          <NavItem
            href={`/orgs/${orgSlug}`}
            icon={FolderGit2}
            label="Repos"
            active={
              pathname === `/orgs/${orgSlug}` || pathname.startsWith(`/orgs/${orgSlug}/repos`)
            }
          />
          <NavItem
            href={`/orgs/${orgSlug}/analytics`}
            icon={BarChart3}
            label="Analytics"
            active={pathname.startsWith(`/orgs/${orgSlug}/analytics`)}
            dataTour="nav-analytics"
          />
          <NavItem
            href={`/orgs/${orgSlug}/settings`}
            icon={Settings}
            label="Settings"
            active={pathname.startsWith(`/orgs/${orgSlug}/settings`)}
            dataTour="nav-settings"
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
