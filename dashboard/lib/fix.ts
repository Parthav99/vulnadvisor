// Proposed-fix helpers (Task 17.5): the stable join key between a code finding and its stored
// validated patch, and a pure unified-diff parser the "Proposed fix" panel renders with Aegis
// add/remove styling. Pure and dependency-free so it is unit-testable (see lib/fix.test.ts).

import type { CodeFinding } from "@/lib/types";

// The id the CLI assigns a SAST finding (`<file>:<line>:<kind>`, src/vulnadvisor/llm/fix.py) and
// the key the platform stores each ProposedFix under. Built from the JSON code finding so the
// dashboard can join a finding to its fix without the server pre-attaching it.
export function codeFindingId(finding: CodeFinding): string {
  return `${finding.location.file}:${finding.location.line}:${finding.rule.kind}`;
}

export type DiffLineKind = "add" | "del" | "meta" | "context";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
}

// Aegis palette semantics for diff lines: the removed (vulnerable) line is risk-red, the added
// (fixed) line is safe-teal, file/hunk headers are muted. Never implies the finding is "safe" —
// teal here marks the *patch's* new code, the conventional diff colour.
const DIFF_LINE_CLASSES: Record<DiffLineKind, string> = {
  add: "text-safe bg-safe/10",
  del: "text-risk bg-risk/10",
  meta: "text-muted-foreground",
  context: "text-foreground/80",
};

export function diffLineClass(kind: DiffLineKind): string {
  return DIFF_LINE_CLASSES[kind];
}

/**
 * Parse a unified diff into classified lines for display. Defensive: any string parses (an empty
 * or malformed diff just yields context lines), so a hostile/odd patch can never throw in render.
 * The raw line text (including its +/-/space prefix) is preserved so the panel reads like a diff.
 */
export function parseDiffLines(diff: string): DiffLine[] {
  if (!diff) return [];
  return diff.split("\n").map((text) => ({ kind: classify(text), text }));
}

function classify(line: string): DiffLineKind {
  // Headers first: `+++`/`---` start with +/- but are metadata, not added/removed code.
  if (
    line.startsWith("+++ ") ||
    line.startsWith("--- ") ||
    line.startsWith("@@") ||
    line.startsWith("diff ") ||
    line.startsWith("index ")
  ) {
    return "meta";
  }
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  return "context";
}
