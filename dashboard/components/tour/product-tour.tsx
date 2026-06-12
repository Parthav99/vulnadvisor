"use client";

import { useEffect, useRef } from "react";
import { usePathname, useRouter } from "next/navigation";
import { driver, type Driver } from "driver.js";
import "driver.js/dist/driver.css";
import { useTour } from "@/components/shell/tour-context";
import {
  TOUR_DONE_KEY,
  TOUR_HANDOFF_KEY,
  isScanPage,
  isTourStartPage,
  orgLegSteps,
  scanLegSteps,
  shouldAutoStart,
  type TourStep,
} from "@/lib/tour";

// The driver.js runner (Task 14.3). Two legs joined by a sessionStorage handoff:
//   leg A on an org home (or /demo): posture hero → repo list, then navigates to the
//   latest scan; leg B there: finding card (expanded for the user) → tier badge →
//   sidebar analytics/settings. Completing OR dismissing writes TOUR_DONE_KEY, so the
//   tour never auto-starts again — only the help menu (or the demo banner) relaunches it.

/** Resolves true once the selector matches a laid-out element; false on timeout. */
function waitFor(selector: string, timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      const el = document.querySelector(selector);
      if (el && el.getClientRects().length > 0) return resolve(true);
      if (Date.now() - started > timeoutMs) return resolve(false);
      setTimeout(tick, 120);
    };
    tick();
  });
}

function visibleOnly(steps: TourStep[]): TourStep[] {
  return steps.filter((s) => {
    const el = document.querySelector(s.selector);
    return el !== null && el.getClientRects().length > 0;
  });
}

export function ProductTour({
  orgSlugs,
  latestScanByOrg,
  demoScanId,
}: {
  orgSlugs: string[];
  latestScanByOrg: Record<string, string>;
  demoScanId: string;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const { requestId } = useTour();
  const driverRef = useRef<Driver | null>(null);
  const handingOffRef = useRef(false);
  const handledRequestRef = useRef(0);

  useEffect(() => {
    let cancelled = false;

    const markDone = () => localStorage.setItem(TOUR_DONE_KEY, "1");

    const makeDriver = (steps: TourStep[], onLastNext?: () => void): Driver => {
      const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const d = driver({
        animate: !reduceMotion,
        showProgress: true,
        overlayColor: "#0a0e14",
        overlayOpacity: 0.72,
        popoverClass: "aegis-tour",
        nextBtnText: "Next",
        prevBtnText: "Back",
        doneBtnText: "Done",
        // driver.js 1.4.0 never registers its internal nextClick/prevClick/closeClick
        // hooks, so without explicit handlers the popover buttons are no-ops (only the
        // arrow keys work). Step-level handlers (the handoff) still take precedence.
        onNextClick: () => d.moveNext(),
        onPrevClick: () => d.movePrevious(),
        onCloseClick: () => d.destroy(),
        steps: steps.map((s, i) => ({
          element: s.selector,
          popover: {
            title: s.title,
            description: s.description,
            side: s.side,
            // Only the handoff step overrides Next — a present-but-undefined onNextClick
            // key would suppress driver.js's default advance on every step.
            ...(onLastNext && i === steps.length - 1
              ? {
                  onNextClick: () => {
                    handingOffRef.current = true;
                    d.destroy();
                    onLastNext();
                  },
                }
              : {}),
          },
        })),
        onDestroyed: () => {
          // Both "Done" and the close button land here: either way the tour was seen,
          // so it must never reappear unasked. A handoff is mid-tour, not an ending.
          if (!handingOffRef.current) markDone();
          handingOffRef.current = false;
        },
      });
      return d;
    };

    const scanUrlFor = (): string | null => {
      if (pathname.startsWith("/demo")) return `/demo/scans/${demoScanId}`;
      const m = /^\/orgs\/([^/]+)/.exec(pathname);
      const slug = m ? decodeURIComponent(m[1]) : null;
      const scanId = slug ? latestScanByOrg[slug] : undefined;
      return scanId ? `/scans/${scanId}` : null;
    };

    const startLegA = async () => {
      if (!(await waitFor('[data-tour="posture-hero"]')) || cancelled) return;
      driverRef.current?.destroy();
      const scanUrl = scanUrlFor();
      const steps = visibleOnly(orgLegSteps(scanUrl !== null));
      if (steps.length === 0) return;
      const d = makeDriver(
        steps,
        scanUrl !== null
          ? () => {
              sessionStorage.setItem(TOUR_HANDOFF_KEY, "scan");
              router.push(scanUrl);
            }
          : undefined,
      );
      driverRef.current = d;
      d.drive();
    };

    const startLegB = async () => {
      if (!(await waitFor('[data-tour="finding-card"]')) || cancelled) return;
      // "Expand it for them": open the first finding's panel before highlighting it.
      const row = document.querySelector<HTMLButtonElement>(
        '[data-tour="finding-card"] button[aria-expanded="false"]',
      );
      row?.click();
      driverRef.current?.destroy();
      const steps = visibleOnly(scanLegSteps());
      if (steps.length === 0) return;
      const d = makeDriver(steps);
      driverRef.current = d;
      d.drive();
    };

    const startPageFor = (): string => {
      if (pathname.startsWith("/demo")) return "/demo";
      const m = /^\/orgs\/([^/]+)/.exec(pathname);
      if (m) return `/orgs/${m[1]}`;
      if (orgSlugs.length > 0) return `/orgs/${encodeURIComponent(orgSlugs[0])}`;
      return "/demo";
    };

    const done = localStorage.getItem(TOUR_DONE_KEY);
    const handoff = sessionStorage.getItem(TOUR_HANDOFF_KEY);
    const manual = requestId > handledRequestRef.current;

    if (handoff === "scan" && isScanPage(pathname)) {
      sessionStorage.removeItem(TOUR_HANDOFF_KEY);
      void startLegB();
    } else if (handoff === "org" && isTourStartPage(pathname)) {
      sessionStorage.removeItem(TOUR_HANDOFF_KEY);
      void startLegA();
    } else if (manual) {
      handledRequestRef.current = requestId;
      if (isTourStartPage(pathname)) {
        void startLegA();
      } else {
        sessionStorage.setItem(TOUR_HANDOFF_KEY, "org");
        router.push(startPageFor());
      }
    } else if (shouldAutoStart(pathname, done, handoff)) {
      void startLegA();
    } else if (handoff !== null) {
      // A handoff that never landed on its target page (navigation interrupted) must not
      // ambush the user on a later visit.
      sessionStorage.removeItem(TOUR_HANDOFF_KEY);
    }

    return () => {
      cancelled = true;
      // Leaving the page mid-tour dismisses it (driver cleans up; onDestroyed marks done).
      driverRef.current?.destroy();
      driverRef.current = null;
    };
  }, [pathname, requestId, router, orgSlugs, latestScanByOrg, demoScanId]);

  return null;
}
