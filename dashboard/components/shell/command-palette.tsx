"use client";

import { useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Building2, FolderGit2, House, Radar, Settings } from "lucide-react";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { usePalette } from "@/components/shell/palette-context";
import type { ShellData } from "@/lib/shell-data";

/**
 * ⌘K command palette: jump to any org, repo, or recent scan. The index is
 * server-fetched shell data (lib/shell-data.ts), so it works with both auth modes.
 */
export function CommandPalette({ data }: { data: ShellData }) {
  const { open, setOpen } = usePalette();
  const router = useRouter();

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen(!open);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, setOpen]);

  const go = useCallback(
    (href: string) => {
      setOpen(false);
      router.push(href);
    },
    [setOpen, router],
  );

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title="Jump to"
      description="Jump to a repository, scan, or page"
    >
      <Command>
        <CommandInput placeholder="Jump to a repo, scan, or page…" />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>

          {data.repos.length > 0 ? (
            <CommandGroup heading="Repositories">
              {data.repos.map((repo) => (
                <CommandItem
                  key={`${repo.org}/${repo.name}`}
                  value={`repo ${repo.org}/${repo.name}`}
                  onSelect={() => go(`/orgs/${repo.org}/repos/${repo.name}`)}
                >
                  <FolderGit2 aria-hidden />
                  <span className="mono">
                    {repo.org}/{repo.name}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {data.scans.length > 0 ? (
            <CommandGroup heading="Recent scans">
              {data.scans.map((scan) => (
                <CommandItem
                  key={scan.id}
                  value={`scan ${scan.org}/${scan.repo} ${scan.label} ${scan.id}`}
                  onSelect={() => go(`/scans/${scan.id}`)}
                >
                  <Radar aria-hidden />
                  <span className="mono truncate">
                    {scan.repo} · {scan.label}
                  </span>
                  <span className="ml-auto text-xs text-muted-foreground">
                    {scan.createdAt.slice(0, 10)}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          <CommandGroup heading="Pages">
            <CommandItem
              value="page home organizations"
              onSelect={() => go("/")}
            >
              <House aria-hidden />
              Home
            </CommandItem>
            {data.orgs.map((org) => (
              <CommandItem
                key={org.id}
                value={`org ${org.slug} ${org.name}`}
                onSelect={() => go(`/orgs/${org.slug}`)}
              >
                <Building2 aria-hidden />
                {org.name}
              </CommandItem>
            ))}
            {data.orgs.map((org) => (
              <CommandItem
                key={`${org.id}-settings`}
                value={`settings ${org.slug} ${org.name}`}
                onSelect={() => go(`/orgs/${org.slug}/settings`)}
              >
                <Settings aria-hidden />
                {org.name} settings
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
