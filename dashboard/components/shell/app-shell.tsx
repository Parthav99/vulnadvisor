"use client";

import { usePathname } from "next/navigation";
import { MotionConfig, motion } from "motion/react";
import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Brand } from "@/components/shell/brand";
import { PaletteProvider, usePalette } from "@/components/shell/palette-context";
import { EASE_AEGIS, FADE_DURATION } from "@/lib/motion";

function SearchButton() {
  const { setOpen } = usePalette();
  return (
    <Button
      variant="outline"
      className="ml-auto w-44 justify-between text-muted-foreground sm:w-56"
      onClick={() => setOpen(true)}
    >
      <span className="flex items-center gap-2">
        <Search aria-hidden />
        Search…
      </span>
      <kbd className="mono rounded border bg-muted px-1.5 py-0.5 text-[10px]">⌘K</kbd>
    </Button>
  );
}

/**
 * The Aegis app-shell frame: radar-grid texture, sidebar + palette arriving as
 * separately-streamed server slots (so pages keep their own first-flush status
 * semantics, e.g. real 404s), top bar with the ⌘K trigger, content fade preset.
 */
export function AppShell({
  sidebar,
  palette,
  children,
}: {
  sidebar: React.ReactNode;
  palette: React.ReactNode;
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <MotionConfig reducedMotion="user">
      <PaletteProvider>
        <div aria-hidden className="radar-grid" />
        <div className="relative z-10 flex min-h-dvh">
          {sidebar}
          <div className="flex min-w-0 flex-1 flex-col">
            <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur">
              <Brand className="md:hidden" />
              <SearchButton />
            </header>
            <motion.main
              key={pathname}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: FADE_DURATION, ease: EASE_AEGIS }}
              className="mx-auto w-full max-w-5xl flex-1 px-4 py-6 md:px-8"
            >
              {children}
            </motion.main>
          </div>
        </div>
        {palette}
      </PaletteProvider>
    </MotionConfig>
  );
}
