// Tests for the copilot UI helpers (Task 15.2 gate): org/context derivation, the deep-link
// contract (build + match must agree), and internal-link detection.
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  findingHref,
  isInternalHref,
  matchesFocus,
  orgSlugFromPathname,
  pageContextLabel,
  SUGGESTED_PROMPTS,
} from "./copilot-ui.ts";

test("org slug is derived only under /orgs/{slug}", () => {
  assert.equal(orgSlugFromPathname("/orgs/acme"), "acme");
  assert.equal(orgSlugFromPathname("/orgs/acme/analytics"), "acme");
  assert.equal(orgSlugFromPathname("/orgs/acme/repos/payments-api"), "acme");
  for (const off of ["/", "/scans/abc", "/demo", "/setup", "/orgs", "/orgss/x"]) {
    assert.equal(orgSlugFromPathname(off), null, off);
  }
});

test("page context label summarizes the current section", () => {
  assert.equal(pageContextLabel("/orgs/acme"), "acme overview");
  assert.equal(pageContextLabel("/orgs/acme/analytics"), "acme analytics");
  assert.equal(pageContextLabel("/orgs/acme/settings"), "acme settings");
  assert.equal(pageContextLabel("/orgs/acme/repos"), "acme repositories");
  assert.equal(pageContextLabel("/orgs/acme/repos/payments-api"), "repository payments-api");
  assert.equal(pageContextLabel("/scans/abc"), null);
});

test("deep link builds the ?finding= contract the scan page reads", () => {
  assert.equal(
    findingHref("8d9e3f10-1111-4222-8333-444455556666", "GHSA-462w-v97r-4m45"),
    "/scans/8d9e3f10-1111-4222-8333-444455556666?finding=GHSA-462w-v97r-4m45",
  );
  // Special characters in either segment are encoded.
  assert.equal(findingHref("a/b", "x y"), "/scans/a%2Fb?finding=x%20y");
});

test("matchesFocus pairs with the link: id, display_id, alias, cve, or package all hit", () => {
  const finding = {
    dependency: { name: "jinja2" },
    advisory: {
      id: "PYSEC-2019-217",
      display_id: "CVE-2019-10906",
      aliases: ["GHSA-462w-v97r-4m45"],
      cve_ids: ["CVE-2019-10906"],
    },
  };
  // The link the copilot emits uses advisory_id verbatim → that token must match.
  for (const hit of ["PYSEC-2019-217", "CVE-2019-10906", "GHSA-462w-v97r-4m45", "jinja2", "ghsa-462w-v97r-4m45"]) {
    assert.ok(matchesFocus(finding, hit), hit);
  }
  for (const miss of ["", "flask", "CVE-2020-0001"]) {
    assert.ok(!matchesFocus(finding, miss), miss);
  }
});

test("internal vs external href detection", () => {
  assert.ok(isInternalHref("/scans/abc?finding=x"));
  assert.ok(isInternalHref("/orgs/acme"));
  for (const ext of ["https://x.example", "//evil.example", "mailto:a@b.c", "javascript:alert(1)"]) {
    assert.ok(!isInternalHref(ext), ext);
  }
});

test("three suggested prompts, matching the task spec", () => {
  assert.deepEqual(SUGGESTED_PROMPTS, [
    "What should I fix first?",
    "Why is this deprioritized?",
    "Explain this call path",
  ]);
});
