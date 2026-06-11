"use client";

import { usePathname } from "next/navigation";
import { MotionConfig, motion, useReducedMotion } from "motion/react";
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
  // MotionConfig reducedMotion="user" only suppresses transforms; the content fade is
  // opacity, so it must opt out explicitly for "all animation disabled" to hold.
  const reduceMotion = useReducedMotion() ?? false;

  return (
    <MotionConfig reducedMotion="user">
      <PaletteProvider>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:ring-2 focus:ring-ring"
        >
          Skip to content
        </a>
        <div aria-hidden className="radar-grid" />
        <div className="relative z-10 flex min-h-dvh">
          {sidebar}
          <div className="flex min-w-0 flex-1 flex-col">
            <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur">
              <Brand className="md:hidden" />
              <SearchButton />
            </header>
            <motion.main
              id="main"
              key={pathname}
              initial={reduceMotion ? false : { opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: reduceMotion ? 0 : FADE_DURATION, ease: EASE_AEGIS }}
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
