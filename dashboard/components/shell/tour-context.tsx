"use client";

import { createContext, useContext, useMemo, useState } from "react";

// Shared trigger for the product tour. The "Product tour" item lives in the top-bar help
// menu while the driver.js runner arrives via a separately-streamed server slot (it needs
// shell data for the scan handoff), so — like the ⌘K palette — the link between them is a
// context. `requestId` is a monotonically increasing counter: each help-menu click bumps
// it, and the runner's effect treats every bump as "start the tour now".
const TourContext = createContext<{
  requestId: number;
  requestTour: () => void;
} | null>(null);

export function TourProvider({ children }: { children: React.ReactNode }) {
  const [requestId, setRequestId] = useState(0);
  const value = useMemo(
    () => ({ requestId, requestTour: () => setRequestId((n) => n + 1) }),
    [requestId],
  );
  return <TourContext.Provider value={value}>{children}</TourContext.Provider>;
}

export function useTour() {
  const ctx = useContext(TourContext);
  if (!ctx) throw new Error("useTour must be used inside TourProvider");
  return ctx;
}
