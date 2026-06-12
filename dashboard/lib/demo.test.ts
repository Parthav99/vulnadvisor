// Tests for demo mode (Task 14.3 gate): /demo must be read-only with no auth and no
// mutation routes reachable, and the seeded dataset must be internally consistent so the
// demo never contradicts itself. Run: npm test.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import {
  DEMO_ORG_TREND,
  DEMO_OVERVIEW,
  DEMO_PACKAGES,
  DEMO_REPOS,
  DEMO_SCANS,
  DEMO_TOUR_SCAN_ID,
  demoScanById,
} from "./demo-data.ts";

// --- static guarantees over the /demo route sources ---------------------------------

function collectSources(dir: string, out: { path: string; content: string }[] = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) collectSources(path, out);
    else if (entry.endsWith(".tsx") || entry.endsWith(".ts"))
      out.push({ path, content: readFileSync(path, "utf8") });
  }
  return out;
}

const demoSources = collectSources(join("app", "demo"));

test("demo routes exist", () => {
  assert.ok(demoSources.length >= 5, "expected the /demo page tree to exist");
});

test("no demo route touches the API client (no auth, no cookies, no backend coupling)", () => {
  for (const { path, content } of demoSources) {
    assert.ok(!content.includes("lib/api"), `${path} imports lib/api`);
    assert.ok(!content.includes("next/headers"), `${path} reads request headers/cookies`);
  }
});

test("no demo route can mutate anything (no fetch, no forms, no mutating components)", () => {
  for (const { path, content } of demoSources) {
    assert.ok(!content.includes("fetch("), `${path} performs a network call`);
    assert.ok(!/method:\s*["'](POST|PUT|PATCH|DELETE)/i.test(content), `${path} sends a mutation`);
    assert.ok(!content.includes("<form"), `${path} renders a form`);
    for (const mutating of ["keys-manager", "repo-setup-row", "activate-form"]) {
      assert.ok(!content.includes(mutating), `${path} imports mutating component ${mutating}`);
    }
  }
});

test("the demo layout watermarks every demo page", () => {
  const layout = demoSources.find(({ path }) => path.endsWith("layout.tsx"));
  assert.ok(layout, "app/demo/layout.tsx must exist");
  assert.ok(layout.content.includes("Demo organization"), "watermark headline missing");
  assert.ok(layout.content.includes("read-only"), "read-only wording missing");
});

// --- seeded-dataset consistency ------------------------------------------------------

const KNOWN_TIERS = new Set(["imported-and-called", "imported", "dynamic-unknown", "not-imported"]);
const KNOWN_BANDS = new Set(["critical", "high", "medium", "low", "info"]);

test("every demo finding carries a known tier, band, and a fix command", () => {
  for (const scan of DEMO_SCANS) {
    for (const f of scan.findings) {
      assert.ok(KNOWN_TIERS.has(f.reachability?.tier ?? ""), `${f.dependency.name}: tier`);
      assert.ok(KNOWN_BANDS.has(f.score.band), `${f.dependency.name}: band`);
      assert.ok(f.fix.command, `${f.dependency.name}: fix command`);
    }
  }
});

test("scan summaries match their findings", () => {
  for (const scan of DEMO_SCANS) {
    assert.equal(scan.detail.summary.total, scan.findings.length, scan.detail.id);
  }
});

test("the derived overview is internally consistent", () => {
  assert.equal(
    DEMO_OVERVIEW.actionable + DEMO_OVERVIEW.deprioritized,
    DEMO_OVERVIEW.total_findings,
  );
  const tierSum = Object.values(DEMO_OVERVIEW.by_tier).reduce((a, b) => a + b, 0);
  const bandSum = Object.values(DEMO_OVERVIEW.by_band).reduce((a, b) => a + b, 0);
  assert.equal(tierSum, DEMO_OVERVIEW.total_findings);
  assert.equal(bandSum, DEMO_OVERVIEW.total_findings);
  assert.equal(DEMO_OVERVIEW.repo_count, DEMO_REPOS.length);
  assert.ok(DEMO_OVERVIEW.kev_count >= 1, "the demo must show the KEV story");
  assert.ok(DEMO_OVERVIEW.deprioritized > 0, "the demo must show the noise-reduction story");
});

test("the trend's latest point matches the overview (charts never contradict the KPIs)", () => {
  const last = DEMO_ORG_TREND[DEMO_ORG_TREND.length - 1];
  assert.equal(last.actionable, DEMO_OVERVIEW.actionable);
  assert.equal(last.deprioritized, DEMO_OVERVIEW.deprioritized);
  assert.equal(last.reachable_called, DEMO_OVERVIEW.reachable_called);
});

test("packages are ranked by max priority and click through to demo scans", () => {
  for (let i = 1; i < DEMO_PACKAGES.length; i++) {
    assert.ok(DEMO_PACKAGES[i - 1].max_priority >= DEMO_PACKAGES[i].max_priority);
  }
  for (const pkg of DEMO_PACKAGES) {
    assert.ok(pkg.top_scan_id && demoScanById(pkg.top_scan_id), `${pkg.package}: top_scan_id`);
  }
});

test("the tour's scan leg lands on a finding with a concrete call path (the demo's demo)", () => {
  const scan = demoScanById(DEMO_TOUR_SCAN_ID);
  assert.ok(scan, "tour scan must exist");
  const first = scan.findings[0];
  assert.ok((first.reachability?.call_paths ?? []).length > 0, "first finding needs a call path");
  assert.ok(first.in_kev, "the marquee finding should carry the KEV badge");
});
