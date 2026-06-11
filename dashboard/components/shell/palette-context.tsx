"use client";

import { createContext, useContext, useMemo, useState } from "react";

// Shared open/close state for the ⌘K palette. The trigger lives in the top bar
// and the dialog arrives via a separately-streamed server slot, so the state is
// a context rather than a prop chain.
const PaletteContext = createContext<{
  open: boolean;
  setOpen: (open: boolean) => void;
} | null>(null);

export function PaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const value = useMemo(() => ({ open, setOpen }), [open]);
  return <PaletteContext.Provider value={value}>{children}</PaletteContext.Provider>;
}

export function usePalette() {
  const ctx = useContext(PaletteContext);
  if (!ctx) throw new Error("usePalette must be used inside PaletteProvider");
  return ctx;
}
