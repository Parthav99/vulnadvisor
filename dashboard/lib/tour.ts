// File: dashboard/lib/tour.ts
// Product-tour definitions (Task 14.3). Pure — no React, no driver.js, no I/O — so the
// steps, selectors, and start/handoff rules are unit-testable (lib/tour.test.ts) and the
// selector list can be drift-checked against the components that carry the data-tour
// anchors.

/** localStorage key: present ⇒ the tour never auto-starts again (completed OR dismissed). */
export const TOUR_DONE_KEY = "va_tour_done";

/** sessionStorage key carrying the cross-page handoff ("scan" while navigating to leg B). */
export const TOUR_HANDOFF_KEY = "va_tour_leg";

export interface TourStep {
  /** Stable anchor: a [data-tour="…"] attribute owned by exactly one component. */
  selector: string;
  title: string;
  description: string;
  /** Side hint for the popover; driver.js falls back automatically when it doesn't fit. */
  side?: "top" | "right" | "bottom" | "left";
}

const HERO_STEP: TourStep = {
  selector: '[data-tour="posture-hero"]',
  title: "Am I protected?",
  description:
    "The shield answers it in one glance, computed from your latest scans. Uncertainty never reads as safety here — “Protected” is only said when the engine can prove it.",
  side: "bottom",
};

const NAV_STEPS: TourStep[] = [
  {
    selector: '[data-tour="nav-analytics"]',
    title: "Analytics",
    description:
      "Severity and reachability splits, the 90-day trend, and your riskiest packages — the numbers behind the shield.",
    side: "right",
  },
  {
    selector: '[data-tour="nav-settings"]',
    title: "Settings",
    description:
      "API keys for CI uploads and the GitHub App live here. Source code never leaves your machines — only JSON reports are uploaded.",
    side: "right",
  },
];

/**
 * Leg A — runs on an org home (or /demo). When a scan exists the last step hands off
 * to that scan's page (leg B); otherwise the navigation steps run here and the tour
 * completes locally.
 */
export function orgLegSteps(hasScan: boolean): TourStep[] {
  if (!hasScan) return [HERO_STEP, ...NAV_STEPS];
  return [
    HERO_STEP,
    {
      selector: '[data-tour="repo-list"]',
      title: "Your repositories",
      description:
        "Each repo reports its scans here. Next, let's open a real finding — the part most scanners hide.",
      side: "top",
    },
  ];
}

/** Leg B — runs on the scan page the handoff navigated to. */
export function scanLegSteps(): TourStep[] {
  return [
    {
      selector: '[data-tour="finding-card"]',
      title: "A finding, with its evidence",
      description:
        "The attack story in plain English, the risk facts, and the exact fix command — plus the call path proving your code reaches the vulnerable symbol.",
      side: "bottom",
    },
    {
      selector: '[data-tour="tier-badge"]',
      title: "Why it's quiet",
      description:
        "Every finding carries a reachability tier — the engine's confidence. Only “not imported” is deprioritized; anything uncertain stays loud on purpose.",
      side: "left",
    },
    ...NAV_STEPS,
  ];
}

/** Every selector the tour can target — the drift test asserts each exists in source. */
export function allTourSelectors(): string[] {
  const all = [...orgLegSteps(true), ...orgLegSteps(false), ...scanLegSteps()];
  return Array.from(new Set(all.map((s) => s.selector)));
}

/** An org home: /orgs/{slug} with no deeper segment. */
export function isOrgHome(pathname: string): boolean {
  return /^\/orgs\/[^/]+\/?$/.test(pathname);
}

/** A tour start page: an org home or the demo org home. */
export function isTourStartPage(pathname: string): boolean {
  return isOrgHome(pathname) || pathname === "/demo" || pathname === "/demo/";
}

/** A page leg B can run on: a scan detail (real or demo), not its diff sub-route. */
export function isScanPage(pathname: string): boolean {
  return /^\/scans\/[^/]+\/?$/.test(pathname) || /^\/demo\/scans\/[^/]+\/?$/.test(pathname);
}

/**
 * Auto-start rule (the "never reappears unasked" contract): only on a signed-in org home
 * (never hijacking a /demo visitor — the demo banner offers the tour instead), only when
 * the done flag has never been written, and never mid-handoff.
 */
export function shouldAutoStart(
  pathname: string,
  doneFlag: string | null,
  handoffFlag: string | null,
): boolean {
  return isOrgHome(pathname) && doneFlag === null && handoffFlag === null;
}
