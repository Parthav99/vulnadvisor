// Proposed-fix helpers (Task 17.5): the stable join key between a code finding and its stored
// validated patch, and a pure unified-diff parser the "Proposed fix" panel renders with Aegis
// add/remove styling. Pure and dependency-free so it is unit-testable (see lib/fix.test.ts).

import type { CodeFinding, Finding } from "@/lib/types";

// The id the CLI assigns a SAST finding (`<file>:<line>:<kind>`, src/vulnadvisor/llm/fix.py) and
// the key the platform stores each ProposedFix under. Built from the JSON code finding so the
// dashboard can join a finding to its fix without the server pre-attaching it.
export function codeFindingId(finding: CodeFinding): string {
  return `${finding.location.file}:${finding.location.line}:${finding.rule.kind}`;
}

// The id the CLI assigns a dependency (SCA) finding (`<package>:<advisory_id>`, `sca_finding_id`
// in src/vulnadvisor/llm/fix.py), the dependency analogue of `codeFindingId`. A validated SCA fix
// is stored under this key (Task 19.2); recomputing it here joins the fix to its finding (19.4).
export function dependencyFindingId(finding: Finding): string {
  return `${finding.dependency.name}:${finding.advisory.id}`;
}

// The fixed sequence of checks every emitted patch cleared before it was ever surfaced (Task 17.1
// validation loop). Shown verbatim on the card as the patch's provenance line — it is honest for
// any ProposedFix because the loop never emits a patch that did not pass all of these.
export const FIX_VALIDATION_STEPS = ["applied", "ruff", "mypy", "tests", "re-scan clean"] as const;

export type FixProvenance = "deterministic" | "model";

// Human label for how a patch was produced (Task 19.3). A deterministic quick-fix earns more trust
// than a model rewrite (an unambiguous AST rewrite, not a generated guess), so the card badges it
// distinctly. Both still cleared the same validator — the label never implies a different verdict.
export function fixProvenanceLabel(provenance: FixProvenance | undefined): string {
  return provenance === "deterministic" ? "Deterministic" : "AI-generated";
}

// Badge palette: a deterministic rewrite is the safe-teal "trusted" accent; a model patch is
// neutral. Mirrors the Aegis semantics in lib/format.ts (teal = earned trust, never "safe finding").
export function fixProvenanceClass(provenance: FixProvenance | undefined): string {
  return provenance === "deterministic"
    ? "border-safe/40 bg-safe/10 text-safe"
    : "border-muted-foreground/40 text-muted-foreground";
}

/**
 * Reconstruct the patched ("after") code from a unified diff, for the "copy fixed code" button.
 * Keeps context and added lines (stripping the leading ` `/`+` marker), drops removed lines and
 * file/hunk headers. Defensive: any string yields a string (a non-diff returns its own lines), so
 * a hostile/odd patch can never throw. Not a full apply — it is the readable post-fix hunk text.
 */
export function fixedCodeFromDiff(diff: string): string {
  if (!diff) return "";
  const out: string[] = [];
  for (const line of diff.split("\n")) {
    const kind = classify(line);
    if (kind === "meta" || kind === "del") continue;
    // Strip the single leading marker (`+` or a context space); a bare line passes through.
    out.push(line.length > 0 && (line[0] === "+" || line[0] === " ") ? line.slice(1) : line);
  }
  return out.join("\n");
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
