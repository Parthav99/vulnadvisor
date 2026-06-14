// Tests for the proposed-fix helpers (Task 17.5): the finding<->fix join key and the unified-diff
// parser/styling. Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";

import { codeFindingId, diffLineClass, parseDiffLines } from "./fix.ts";
import type { CodeFinding } from "./types.ts";

const code: CodeFinding = {
  finding_type: "code",
  rule: { cwe: "CWE-78", kind: "command-injection", title: "OS command injection" },
  location: { file: "app/run.py", line: 12, column: 4 },
  flow: {
    tier: "confirmed-flow",
    source: { kind: "http-parameter", file: "app/run.py", line: 8 },
    sink: { kind: "command-injection", file: "app/run.py", line: 12 },
    path: ["run -> os.system (app/run.py:12)"],
    sanitizers: [],
  },
  score: { value: 95, band: "critical", verdict: "Fix now", rationale: "", cvss_known: false },
  fix: { direction: "Avoid shell=True.", has_fix: false },
};

test("codeFindingId matches the CLI's <file>:<line>:<kind> id", () => {
  // This is exactly the finding_id the platform stores each ProposedFix under, so the join works.
  assert.equal(codeFindingId(code), "app/run.py:12:command-injection");
});

test("parseDiffLines classifies headers, additions, removals, and context", () => {
  const diff = [
    "--- a/app/run.py",
    "+++ b/app/run.py",
    "@@ -10,3 +10,3 @@",
    " def run(cmd):",
    "-    os.system(cmd)",
    "+    subprocess.run(cmd, shell=False)",
    "     return",
  ].join("\n");
  const lines = parseDiffLines(diff);
  assert.deepEqual(
    lines.map((l) => l.kind),
    ["meta", "meta", "meta", "context", "del", "add", "context"],
  );
  // The raw text (with its prefix) is preserved so the panel reads like a diff.
  assert.equal(lines[4].text, "-    os.system(cmd)");
  assert.equal(lines[5].text, "+    subprocess.run(cmd, shell=False)");
});

test("parseDiffLines is defensive: empty string yields no lines, never throws", () => {
  assert.deepEqual(parseDiffLines(""), []);
  // A non-diff string parses as a single context line rather than throwing.
  assert.deepEqual(parseDiffLines("just text"), [{ kind: "context", text: "just text" }]);
});

test("diffLineClass: added is safe-teal, removed is risk-red, never the reverse", () => {
  assert.match(diffLineClass("add"), /safe/);
  assert.match(diffLineClass("del"), /risk/);
  // Removed (vulnerable) lines are never styled safe.
  assert.doesNotMatch(diffLineClass("del"), /safe/);
  assert.match(diffLineClass("meta"), /muted/);
});
