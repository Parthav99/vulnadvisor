// Table-driven tests for the posture hero wording (Task 13.5 gate).
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively — no test framework dep).
import assert from "node:assert/strict";
import { test } from "node:test";

import { computePosture } from "./posture.ts";
import type { AnalyticsOverview } from "./types.ts";

function overview(partial: Partial<AnalyticsOverview>): AnalyticsOverview {
  return {
    org_id: "o",
    repo_count: 3,
    repos_at_risk: 0,
    total_findings: 0,
    actionable: 0,
    deprioritized: 0,
    reachable_called: 0,
    kev_count: 0,
    by_band: {},
    by_tier: {},
    ...partial,
  };
}

interface Case {
  name: string;
  overview: AnalyticsOverview;
  scanned: number;
  level: string;
  headlineIncludes: string;
}

const CASES: Case[] = [
  {
    name: "KEV present -> at risk, names KEV",
    overview: overview({
      total_findings: 5,
      actionable: 3,
      reachable_called: 1,
      kev_count: 1,
      by_tier: { "imported-and-called": 1, imported: 2, "dynamic-unknown": 0, "not-imported": 2 },
    }),
    scanned: 3,
    level: "at-risk",
    headlineIncludes: "1 KEV-listed finding",
  },
  {
    name: "KEV beats everything even when all findings are deprioritized (escalation only)",
    overview: overview({
      total_findings: 2,
      deprioritized: 2,
      kev_count: 2,
      by_tier: { "not-imported": 2 },
    }),
    scanned: 1,
    level: "at-risk",
    headlineIncludes: "2 KEV-listed findings",
  },
  {
    name: "confirmed call path, no KEV -> at risk",
    overview: overview({
      total_findings: 4,
      actionable: 3,
      reachable_called: 2,
      by_tier: { "imported-and-called": 2, imported: 1, "not-imported": 1 },
    }),
    scanned: 2,
    level: "at-risk",
    headlineIncludes: "2 findings with a confirmed call path",
  },
  {
    name: "imported only -> under watch (never 'Protected', never 'At risk')",
    overview: overview({
      total_findings: 3,
      actionable: 2,
      deprioritized: 1,
      by_tier: { imported: 2, "not-imported": 1 },
    }),
    scanned: 2,
    level: "under-watch",
    headlineIncludes: "2 actionable findings",
  },
  {
    name: "dynamic-unknown only -> unverified, must NOT read as safe",
    overview: overview({
      total_findings: 3,
      actionable: 3,
      by_tier: { "dynamic-unknown": 3 },
    }),
    scanned: 1,
    level: "unverified",
    headlineIncludes: "3 findings cannot be ruled out",
  },
  {
    name: "only deprioritized -> protected, says why",
    overview: overview({
      total_findings: 4,
      deprioritized: 4,
      by_tier: { "not-imported": 4 },
    }),
    scanned: 2,
    level: "protected",
    headlineIncludes: "no reachable findings",
  },
  {
    name: "scanned and empty -> protected (no known vulnerabilities)",
    overview: overview({ total_findings: 0 }),
    scanned: 3,
    level: "protected",
    headlineIncludes: "no known vulnerabilities",
  },
  {
    name: "no scanned repos -> awaiting, never claims protection",
    overview: overview({ repo_count: 2 }),
    scanned: 0,
    level: "awaiting",
    headlineIncludes: "Awaiting first scan",
  },
  {
    name: "defensive: empty by_tier map does not crash",
    overview: overview({ total_findings: 1, actionable: 1, by_tier: {} }),
    scanned: 1,
    level: "under-watch",
    headlineIncludes: "1 actionable finding",
  },
];

for (const c of CASES) {
  test(c.name, () => {
    const p = computePosture(c.overview, c.scanned);
    assert.equal(p.level, c.level);
    assert.ok(
      p.headline.includes(c.headlineIncludes),
      `headline ${JSON.stringify(p.headline)} should include ${JSON.stringify(c.headlineIncludes)}`,
    );
  });
}

test("soundness: no uncertain or unscanned mix ever produces a 'Protected' headline", () => {
  const uncertain = [
    { o: overview({ total_findings: 1, actionable: 1, by_tier: { "dynamic-unknown": 1 } }), s: 1 },
    { o: overview({ total_findings: 9, actionable: 9, by_tier: { "dynamic-unknown": 9 } }), s: 5 },
    { o: overview({}), s: 0 },
    { o: overview({ total_findings: 2, deprioritized: 2, kev_count: 1, by_tier: { "not-imported": 2 } }), s: 1 },
  ];
  for (const { o, s } of uncertain) {
    const p = computePosture(o, s);
    assert.notEqual(p.level, "protected");
    assert.ok(!p.headline.startsWith("Protected"), `unsound headline: ${p.headline}`);
  }
});

test("singular/plural grammar", () => {
  const one = computePosture(
    overview({ total_findings: 1, actionable: 1, by_tier: { imported: 1, "dynamic-unknown": 0 } }),
    1,
  );
  assert.ok(one.headline.includes("1 actionable finding"));
  assert.ok(!one.headline.includes("findings"));
  const mixed = computePosture(
    overview({ total_findings: 3, actionable: 3, by_tier: { imported: 2, "dynamic-unknown": 1 } }),
    1,
  );
  assert.equal(mixed.level, "under-watch");
  assert.ok(mixed.detail.includes("1 of them resists verification"), mixed.detail);
});
