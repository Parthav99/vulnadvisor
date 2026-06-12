"use client";

import { Button } from "@/components/ui/button";
import { useTour } from "@/components/shell/tour-context";

/** The demo banner's tour launcher — the demo never auto-starts the tour, it offers it. */
export function DemoTourButton() {
  const { requestTour } = useTour();
  return (
    <Button variant="outline" size="sm" onClick={() => requestTour()}>
      Take the 60-second tour
    </Button>
  );
}
