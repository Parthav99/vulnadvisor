import { Skeleton } from "@/components/ui/skeleton";
import { Brand } from "@/components/shell/brand";
import { CommandPalette } from "@/components/shell/command-palette";
import { Sidebar } from "@/components/shell/sidebar";
import { getShellData } from "@/lib/shell-data";

// Async server slots for the shell. They stream into the layout behind their own
// Suspense boundaries so page rendering (and its status code) is never blocked
// on the shell-data fetch.

export async function ShellSidebar() {
  const data = await getShellData();
  return <Sidebar orgs={data.orgs} />;
}

export function ShellSidebarFallback() {
  return (
    <aside
      aria-hidden
      className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col gap-4 border-r border-sidebar-border bg-sidebar/80 px-3 py-4 md:flex"
    >
      <Brand className="px-2" />
      <Skeleton className="h-8" />
      <div className="flex flex-col gap-1.5">
        <Skeleton className="h-7" />
        <Skeleton className="h-7" />
        <Skeleton className="h-7" />
      </div>
    </aside>
  );
}

export async function ShellPalette() {
  const data = await getShellData();
  return <CommandPalette data={data} />;
}
