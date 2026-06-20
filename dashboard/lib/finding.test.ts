// Tests for the SAST finding helpers (Task 16.4): the code/dependency discriminator, the stable
// key, the SAST tier styling, and focus-matching tolerance for code findings.
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  findingKey,
  isCodeFinding,
  provenanceLine,
  sastTierClass,
  sastTierLabel,
} from "./format.ts";
import { matchesFocus } from "./copilot-ui.ts";
import type { AnyFinding, CodeFinding, Finding } from "./types.ts";

const dep: Finding = {
  finding_type: "dependency",
  dependency: { name: "jinja2", version: "2.10" },
  advisory: { id: "GHSA-x", display_id: "CVE-2019-10906", cve_ids: ["CVE-2019-10906"] },
  epss: null,
  in_kev: true,
  score: { value: 90, band: "critical", verdict: "Fix now", rationale: "" },
  reachability: null,
  fix: { command: null, fixed_version: null, has_fix: false },
};

const code: CodeFinding = {
  finding_type: "code",
  rule: { cwe: "CWE-78", kind: "command-injection", title: "OS command injection" },
  location: { file: "app/run.py", line: 12, column: 4 },
  flow: {
    tier: "confirmed-flow",
    reason: "tainted parameter reaches os.system",
    source: { kind: "http-parameter", file: "app/run.py", line: 8 },
    sink: { kind: "command-injection", file: "app/run.py", line: 12 },
    path: ["run -> os.system (app/run.py:12)"],
    sanitizers: [],
  },
  score: { value: 95, band: "critical", verdict: "Fix now", rationale: "", cvss_known: false },
  fix: { direction: "Avoid shell=True.", has_fix: false },
};

test("isCodeFinding discriminates the two kinds", () => {
  assert.equal(isCodeFinding(code), true);
  assert.equal(isCodeFinding(dep), false);
  // A pre-1.2 dependency finding has no finding_type and must read as a dependency.
  const legacy = { ...dep } as AnyFinding;
  delete (legacy as { finding_type?: string }).finding_type;
  assert.equal(isCodeFinding(legacy), false);
});

test("findingKey is stable and distinct per kind", () => {
  assert.equal(findingKey(dep), "jinja2:GHSA-x");
  assert.equal(findingKey(code), "code:command-injection:app/run.py:12");
  assert.notEqual(findingKey(dep), findingKey(code));
});

test("SAST tier styling: confirmed=risk, dynamic=dashed amber, sanitized=safe", () => {
  assert.equal(sastTierLabel("confirmed-flow"), "CONFIRMED-FLOW");
  assert.equal(sastTierLabel("possible-flow"), "POSSIBLE-FLOW");
  assert.match(sastTierClass("confirmed-flow"), /risk/);
  assert.match(sastTierClass("dynamic-unknown"), /dashed/);
  assert.match(sastTierClass("sanitized"), /safe/);
  // Uncertainty is never styled as safe.
  assert.doesNotMatch(sastTierClass("dynamic-unknown"), /safe/);
});

test("provenanceLine credits external detectors but only for fused findings (Task 21.4)", () => {
  // Native-only: no provenance line (we found and ranked it — the default).
  assert.equal(provenanceLine(["vulnadvisor"]), null);
  assert.equal(provenanceLine(undefined), null);
  assert.equal(provenanceLine([]), null);
  // Corroborated: every detector credited, ranking always ours.
  assert.equal(
    provenanceLine(["vulnadvisor", "semgrep-oss"]),
    "Found by VulnAdvisor + Semgrep OSS · ranked by VulnAdvisor reachability",
  );
  // Semgrep-only (un-overlayable, escalated): still credited, still ranked by us.
  assert.equal(
    provenanceLine(["semgrep-oss"]),
    "Found by Semgrep OSS · ranked by VulnAdvisor reachability",
  );
});

test("matchesFocus handles code findings without crashing on a missing dependency", () => {
  assert.equal(matchesFocus(code, "CWE-78"), true);
  assert.equal(matchesFocus(code, "command-injection"), true);
  assert.equal(matchesFocus(code, "app/run.py:12"), true);
  assert.equal(matchesFocus(code, "jinja2"), false);
  // Dependency matching still works.
  assert.equal(matchesFocus(dep, "CVE-2019-10906"), true);
  assert.equal(matchesFocus(dep, "jinja2"), true);
});
