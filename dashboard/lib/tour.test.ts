// Tests for the product tour (Task 14.3 gate): the auto-start contract ("never reappears
// unasked"), the leg shapes, and a drift guard proving every selector the tour targets is
// anchored by a data-tour attribute that actually exists in the component sources.
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import {
  allTourSelectors,
  isScanPage,
  isTourStartPage,
  orgLegSteps,
  scanLegSteps,
  shouldAutoStart,
} from "./tour.ts";

test("auto-start: first visit to an org home only", () => {
  assert.equal(shouldAutoStart("/orgs/acme", null, null), true);
  assert.equal(shouldAutoStart("/orgs/acme/", null, null), true);
});

test("auto-start: never once the done flag exists (completed or dismissed)", () => {
  assert.equal(shouldAutoStart("/orgs/acme", "1", null), false);
});

test("auto-start: never mid-handoff", () => {
  assert.equal(shouldAutoStart("/orgs/acme", null, "scan"), false);
});

test("auto-start: never hijacks the demo org or non-home pages", () => {
  for (const path of ["/demo", "/", "/orgs/acme/analytics", "/orgs/acme/repos/web", "/setup"]) {
    assert.equal(shouldAutoStart(path, null, null), false, path);
  }
});

test("start pages: org homes and the demo home; scan pages: real and demo scans", () => {
  assert.equal(isTourStartPage("/orgs/acme"), true);
  assert.equal(isTourStartPage("/demo"), true);
  assert.equal(isTourStartPage("/orgs/acme/analytics"), false);
  assert.equal(isScanPage("/scans/abc123"), true);
  assert.equal(isScanPage("/demo/scans/demo-scan-payments-2"), true);
  assert.equal(isScanPage("/scans/abc123/diff/def456"), false);
});

test("leg shapes: hero first; scan handoff ends on the repo list; no-scan leg covers nav", () => {
  const withScan = orgLegSteps(true);
  assert.equal(withScan[0].selector, '[data-tour="posture-hero"]');
  assert.equal(withScan[withScan.length - 1].selector, '[data-tour="repo-list"]');

  const withoutScan = orgLegSteps(false);
  assert.equal(withoutScan[0].selector, '[data-tour="posture-hero"]');
  assert.ok(withoutScan.some((s) => s.selector === '[data-tour="nav-analytics"]'));
  assert.ok(withoutScan.some((s) => s.selector === '[data-tour="nav-settings"]'));

  const scanLeg = scanLegSteps();
  assert.equal(scanLeg[0].selector, '[data-tour="finding-card"]');
  assert.ok(scanLeg.some((s) => s.selector === '[data-tour="tier-badge"]'));
});

// --- selector drift guard -----------------------------------------------------------

function collectSources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) collectSources(path, out);
    else if (entry.endsWith(".tsx") || entry.endsWith(".ts")) out.push(readFileSync(path, "utf8"));
  }
  return out;
}

test("every tour selector is anchored by a data-tour attribute in the sources", () => {
  const sources = [...collectSources("components"), ...collectSources("app")].join("\n");
  for (const selector of allTourSelectors()) {
    const m = /^\[data-tour="([a-z-]+)"\]$/.exec(selector);
    assert.ok(m, `tour selector must be a [data-tour="…"] anchor, got: ${selector}`);
    const name = m[1];
    const anchored =
      sources.includes(`data-tour="${name}"`) || sources.includes(`dataTour="${name}"`);
    assert.ok(anchored, `no component carries data-tour="${name}" (selector drift)`);
  }
});
