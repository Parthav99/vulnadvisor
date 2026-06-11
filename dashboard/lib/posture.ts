// Security-posture wording for the org home hero (Task 13.5). Pure — no React, no I/O —
// so the wording table is unit-testable (lib/posture.test.ts, run via `npm test`).
//
// Soundness rules (CLAUDE.md, verbatim):
//  - uncertainty never reads as safety: dynamic-unknown findings can NEVER produce a
//    "Protected" headline;
//  - escalation only: a KEV listing puts the org "At risk" even if every KEV finding is
//    currently deprioritized — KEV means exploitation observed in the wild, and the
//    deterministic engine (not this wording layer) is the authority on tiers;
//  - "Protected" is reserved for: scans exist AND zero actionable findings.
import type { AnalyticsOverview } from "./types";

export type PostureLevel = "at-risk" | "under-watch" | "unverified" | "protected" | "awaiting";

export interface Posture {
  level: PostureLevel;
  headline: string;
  detail: string;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * Compute the shield-status wording from the analytics overview.
 *
 * `scannedRepoCount` (repos with at least one scan) disambiguates "no findings because
 * nothing was scanned" from "no findings in the latest scans" — the overview alone cannot,
 * and claiming protection for an unscanned org would be a false "you're safe".
 */
export function computePosture(overview: AnalyticsOverview, scannedRepoCount: number): Posture {
  const kev = overview.kev_count;
  const called = overview.reachable_called;
  const actionable = overview.actionable;
  const deprioritized = overview.deprioritized;
  const dynamic = overview.by_tier["dynamic-unknown"] ?? 0;
  const imported = overview.by_tier["imported"] ?? 0;

  if (scannedRepoCount === 0) {
    return {
      level: "awaiting",
      headline: "Awaiting first scan",
      detail:
        "Protection is unverified until a repository reports in — run vulnadvisor scan . --upload or install the GitHub App.",
    };
  }

  if (kev > 0) {
    return {
      level: "at-risk",
      headline: `At risk — ${plural(kev, "KEV-listed finding")}`,
      detail:
        "CISA reports active exploitation of these vulnerabilities in the wild. Fix these first.",
    };
  }

  if (called > 0) {
    return {
      level: "at-risk",
      headline: `At risk — ${plural(called, "finding")} with a confirmed call path`,
      detail:
        "Your code provably reaches the vulnerable symbols — these are concrete attack paths, not theoretical pairings.",
    };
  }

  if (actionable > 0) {
    if (imported === 0 && dynamic > 0) {
      return {
        level: "unverified",
        headline: `Unverified — ${plural(dynamic, "finding")} cannot be ruled out`,
        detail:
          "Dynamic code blocks static proof. Treat these as unresolved — review them or add runtime evidence.",
      };
    }
    const dynamicNote =
      dynamic > 0
        ? ` ${dynamic} of them resist${dynamic === 1 ? "s" : ""} verification due to dynamic code.`
        : "";
    return {
      level: "under-watch",
      headline: `Under watch — ${plural(actionable, "actionable finding")}`,
      detail: `Vulnerable packages are imported, with no confirmed call path and no KEV listing yet.${dynamicNote}`,
    };
  }

  if (deprioritized > 0) {
    return {
      level: "protected",
      headline: "Protected — no reachable findings",
      detail: `${plural(deprioritized, "finding")} deprioritized as not imported; nothing reaches your code.`,
    };
  }

  return {
    level: "protected",
    headline: "Protected — no known vulnerabilities",
    detail: "The latest scans report no advisories against your dependencies.",
  };
}
