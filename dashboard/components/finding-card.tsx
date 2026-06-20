"use client";

import { useEffect, useId, useRef, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Check, ChevronDown, Copy, ShieldCheck, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  bandClass,
  displayId,
  isCodeFinding,
  provenanceLine,
  sastTierClass,
  sastTierLabel,
  tierClass,
  tierLabel,
} from "@/lib/format";
import {
  diffLineClass,
  FIX_VALIDATION_STEPS,
  fixProvenanceClass,
  fixProvenanceLabel,
  fixedCodeFromDiff,
  parseDiffLines,
} from "@/lib/fix";
import { EASE_AEGIS, FADE_DURATION } from "@/lib/motion";
import { cn } from "@/lib/utils";
import type { AnyFinding, CodeFinding, Finding, ProposedFix } from "@/lib/types";

// Call paths arrive as the engine's rendered string: "a -> b -> vuln (file:line)"
// (model/callpath.py CallPath.render). Split into steps for the chain UI.
function parseCallPath(path: string): { steps: string[]; location: string | null } {
  const m = /^(.*?)\s*\(([^()]+:\d+)\)\s*$/.exec(path);
  const chain = m ? m[1] : path;
  return {
    steps: chain
      .split(" -> ")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    location: m ? m[2] : null,
  };
}

function CallPathChain({ path }: { path: string }) {
  const { steps, location } = parseCallPath(path);
  return (
    <li className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
      {steps.map((step, i) => (
        <span key={`${i}-${step}`} className="flex items-center gap-1.5">
          {i > 0 ? (
            <span aria-hidden className="text-muted-foreground">
              →
            </span>
          ) : null}
          <span
            className={cn(
              "mono rounded bg-secondary px-1.5 py-0.5 text-xs break-all",
              i === steps.length - 1 && "bg-risk/10 text-risk ring-1 ring-risk/40",
            )}
          >
            {step}
          </span>
        </span>
      ))}
      {location ? (
        <span className="mono text-xs text-muted-foreground">({location})</span>
      ) : null}
    </li>
  );
}

function CopyFixButton({
  command,
  ariaLabel = "Copy fix command",
  label = "Copy",
}: {
  command: string;
  ariaLabel?: string;
  /** Visible button text; the copied state always reads "Copied". */
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      aria-label={ariaLabel}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(command);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // Clipboard unavailable (permissions / insecure context) — the command stays visible.
        }
      }}
    >
      {copied ? <Check aria-hidden className="text-safe" /> : <Copy aria-hidden />}
      <span aria-live="polite">{copied ? "Copied" : label}</span>
    </Button>
  );
}

/** Collapsed-row chip shown when a validated patch exists for this finding (Task 19.4). */
function FixReadyBadge() {
  return (
    <Badge variant="outline" className="border-safe/40 bg-safe/10 text-safe">
      <ShieldCheck aria-hidden className="size-3" />
      Fix ready
    </Badge>
  );
}

function Card3({
  letter,
  title,
  children,
}: {
  letter: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg bg-background/60 p-3 ring-1 ring-border">
      <div className="mb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {`${letter} · ${title}`}
      </div>
      <div className="text-sm">{children}</div>
    </div>
  );
}

/** Second-level disclosure: call paths as step chains + import sites as file:line chips. */
function EvidenceDrawer({
  reason,
  callPaths,
  evidence,
  defaultOpen,
}: {
  reason: string | null;
  callPaths: string[];
  evidence: { file: string; line: number }[];
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const drawerId = useId();
  const reduceMotion = useReducedMotion() ?? false;
  const counts = [
    callPaths.length > 0 ? `${callPaths.length} call path${callPaths.length === 1 ? "" : "s"}` : null,
    evidence.length > 0 ? `${evidence.length} import site${evidence.length === 1 ? "" : "s"}` : null,
  ]
    .filter((c) => c !== null)
    .join(" · ");

  return (
    <div className="rounded-lg bg-background/60 ring-1 ring-border">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={drawerId}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-semibold tracking-wide text-muted-foreground uppercase focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset focus-visible:outline-none"
      >
        <ChevronDown
          aria-hidden
          className={cn("size-3.5 shrink-0 transition-transform duration-200", open && "rotate-180")}
        />
        Evidence
        {counts ? <span className="font-normal normal-case">— {counts}</span> : null}
      </button>
      <motion.div
        id={drawerId}
        inert={!open}
        initial={false}
        animate={open ? { height: "auto", opacity: 1 } : { height: 0, opacity: 0 }}
        transition={{ duration: reduceMotion ? 0 : FADE_DURATION, ease: EASE_AEGIS }}
        className="overflow-hidden"
      >
        <div className="space-y-3 px-3 pb-3">
          {reason ? <p className="text-sm text-muted-foreground">{reason}</p> : null}
          {callPaths.length > 0 ? (
            <div>
              <div className="mb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                Call paths
              </div>
              <ul className="space-y-1.5">
                {callPaths.map((p) => (
                  <CallPathChain key={p} path={p} />
                ))}
              </ul>
            </div>
          ) : null}
          {evidence.length > 0 ? (
            <div>
              <div className="mb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                Imported at
              </div>
              <div className="flex flex-wrap gap-1.5">
                {evidence.map((e) => (
                  <span
                    key={`${e.file}:${e.line}`}
                    className="mono rounded bg-secondary px-1.5 py-0.5 text-xs break-all"
                  >
                    {`${e.file}:${e.line}`}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </motion.div>
    </div>
  );
}

/**
 * The hero of the finding card (Task 19.4): the validated, machine-checked patch leads the expanded
 * view. Renders the unified diff with Aegis add/remove styling, a **deterministic vs model**
 * provenance badge (Task 19.3), a confidence chip, the rationale, copy-diff and copy-fixed-code
 * buttons, and the provenance line proving the patch earned trust (every emitted patch cleared the
 * full 17.1 validator). Wording keeps the soundness contract — it is a *suggested* patch committed
 * on the PR, never auto-applied here, and it never affects the deterministic tier/score.
 */
function ProposedFixPanel({ fix }: { fix: ProposedFix }) {
  const lines = parseDiffLines(fix.diff);
  const provenance = fix.provenance ?? "model";
  return (
    <div
      className="rounded-lg bg-safe/5 p-3 ring-1 ring-safe/30"
      data-testid="proposed-fix"
      data-provenance={provenance}
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Wrench aria-hidden className="size-4 text-safe" />
          <span className="text-sm font-semibold">Proposed fix</span>
          <Badge variant="outline" className={fixProvenanceClass(provenance)}>
            {fixProvenanceLabel(provenance)}
          </Badge>
          <Badge variant="outline" className="border-muted-foreground/40 text-muted-foreground">
            {fix.confidence} confidence
          </Badge>
        </div>
        <div className="flex items-center gap-1.5">
          <CopyFixButton command={fix.diff} ariaLabel="Copy patch diff" label="Copy diff" />
          <CopyFixButton
            command={fixedCodeFromDiff(fix.diff)}
            ariaLabel="Copy fixed code"
            label="Copy code"
          />
        </div>
      </div>
      <pre className="mono overflow-x-auto rounded bg-background/80 p-2 text-xs leading-relaxed ring-1 ring-border">
        {lines.map((line, i) => (
          <div key={i} className={cn("px-1", diffLineClass(line.kind))}>
            {line.text || " "}
          </div>
        ))}
      </pre>
      {fix.rationale ? (
        <p className="mt-2 text-sm text-muted-foreground">{fix.rationale}</p>
      ) : null}
      <p className="mono mt-2 flex flex-wrap items-center gap-1.5 text-xs text-safe">
        <ShieldCheck aria-hidden className="size-3.5 shrink-0" />
        <span>validated: {FIX_VALIDATION_STEPS.join(" · ")}</span>
      </p>
      <p className="mt-2 text-xs text-muted-foreground">
        Suggested, machine-validated patch — review and commit it on the pull request. It is never
        applied automatically and does not change this finding&rsquo;s priority.
      </p>
    </div>
  );
}

/**
 * One finding with progressive disclosure: a scannable collapsed row (identity, badges,
 * one-line verdict) that expands into the signature three cards plus an evidence drawer.
 * Dispatches on the finding kind — dependency (SCA) or first-party code (SAST).
 *
 * The expanded panel is always in the DOM (SSR renders the full story); collapsing
 * animates height to 0 and marks the panel `inert`, so hidden content never traps
 * keyboard focus or appears to assistive tech.
 */
export function FindingCard({
  finding,
  defaultOpen = false,
  focus = false,
  proposedFix,
}: {
  finding: AnyFinding;
  defaultOpen?: boolean;
  /** When the copilot deep-links here (?finding=…), scroll this card into view on mount. */
  focus?: boolean;
  /** The stored validated patch for this finding (Task 17.5/19.2); SAST or SCA. */
  proposedFix?: ProposedFix;
}) {
  if (isCodeFinding(finding)) {
    return (
      <CodeFindingCard
        finding={finding}
        defaultOpen={defaultOpen}
        focus={focus}
        proposedFix={proposedFix}
      />
    );
  }
  return (
    <DependencyFindingCard
      finding={finding}
      defaultOpen={defaultOpen}
      focus={focus}
      proposedFix={proposedFix}
    />
  );
}

function DependencyFindingCard({
  finding,
  defaultOpen = false,
  focus = false,
  proposedFix,
}: {
  finding: Finding;
  defaultOpen?: boolean;
  focus?: boolean;
  proposedFix?: ProposedFix;
}) {
  const { dependency, advisory, score, reachability, fix, epss, in_kev } = finding;
  const tier = reachability?.tier ?? "unknown";
  const version = dependency.version || "(unpinned)";
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const cardRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus) cardRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [focus]);
  const reduceMotion = useReducedMotion() ?? false;
  const callPaths = reachability?.call_paths ?? [];
  const evidence = reachability?.evidence ?? [];
  const story = score.verdict || advisory.summary || "No summary available.";

  return (
    <Card ref={cardRef} size="sm" className="gap-0 py-0" data-tour="finding-card">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset focus-visible:outline-none"
      >
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
            <span className="mono font-semibold">{displayId(advisory)}</span>
            <span aria-hidden className="text-muted-foreground">
              ·
            </span>
            <span className="mono">
              {dependency.name} {version}
            </span>
          </span>
          <span className="mt-0.5 block truncate text-xs text-muted-foreground">{story}</span>
        </span>
        <span className="flex shrink-0 items-center gap-1.5">
          <Badge variant="outline" className={bandClass(score.band)}>
            {score.band} · {Math.round(score.value)}
          </Badge>
          <Badge
            variant="outline"
            data-tour="tier-badge"
            className={cn("max-sm:hidden", tierClass(tier))}
          >
            {tierLabel(tier)}
          </Badge>
          {in_kev ? (
            <Badge variant="outline" className={bandClass("critical")}>
              KEV
            </Badge>
          ) : null}
          {proposedFix ? <FixReadyBadge /> : null}
        </span>
        <ChevronDown
          aria-hidden
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </button>

      <motion.div
        id={panelId}
        inert={!open}
        initial={false}
        animate={open ? { height: "auto", opacity: 1 } : { height: 0, opacity: 0 }}
        transition={{ duration: reduceMotion ? 0 : FADE_DURATION, ease: EASE_AEGIS }}
        className="overflow-hidden"
      >
        <article className="space-y-3 border-t px-3 py-3">
          <Badge variant="outline" className={cn("sm:hidden", tierClass(tier))}>
            {tierLabel(tier)}
          </Badge>

          {/* The validated patch leads the card (Task 19.4): the fix is the hero, evidence follows. */}
          {proposedFix ? <ProposedFixPanel fix={proposedFix} /> : null}

          <Card3 letter="A" title="Attack story">
            <p className="leading-relaxed">{story}</p>
            {advisory.summary && score.verdict && advisory.summary !== score.verdict ? (
              <p className="mt-2 text-muted-foreground">{advisory.summary}</p>
            ) : null}
            {score.rationale ? <p className="mt-2 text-muted-foreground">{score.rationale}</p> : null}
          </Card3>

          <div className="grid gap-3 md:grid-cols-2">
            <Card3 letter="B" title="Risk">
              <ul className="space-y-0.5">
                <li>
                  Priority <span className="font-semibold">{Math.round(score.value)}</span> (
                  {score.band})
                </li>
                <li>
                  Reachability <span className="font-semibold">{tierLabel(tier)}</span>
                </li>
                {epss ? (
                  <li>
                    EPSS {(epss.probability * 100).toFixed(1)}% (p
                    {Math.round(epss.percentile * 100)})
                  </li>
                ) : (
                  <li className="text-muted-foreground">EPSS unavailable</li>
                )}
                <li className={in_kev ? "text-risk" : undefined}>
                  {in_kev ? "Listed in CISA KEV" : "Not in CISA KEV"}
                </li>
                {typeof advisory.cvss_base === "number" ? (
                  <li>CVSS base {advisory.cvss_base.toFixed(1)}</li>
                ) : null}
              </ul>
            </Card3>

            <Card3 letter="C" title="Action">
              {fix.command ? (
                <div className="flex items-start gap-2">
                  <code className="mono block min-w-0 flex-1 rounded bg-secondary px-2 py-1 break-all">
                    {fix.command}
                  </code>
                  <CopyFixButton command={fix.command} />
                </div>
              ) : (
                <p className="text-muted-foreground">No fixed version available yet.</p>
              )}
              {fix.fixed_version ? (
                <p className="mt-2 text-muted-foreground">
                  Fixed in <span className="mono">{fix.fixed_version}</span>
                </p>
              ) : null}
            </Card3>
          </div>

          {reachability?.reason || callPaths.length > 0 || evidence.length > 0 ? (
            <EvidenceDrawer
              reason={reachability?.reason ?? null}
              callPaths={callPaths}
              evidence={evidence}
              defaultOpen={callPaths.length > 0}
            />
          ) : null}
        </article>
      </motion.div>
    </Card>
  );
}

/**
 * A first-party (SAST) finding: same progressive-disclosure shape as the dependency card, but the
 * identity is the CWE rule + sink location, the tier is the SAST confidence tier, Card C carries
 * the *remediation direction* (the validated fix is M17), and the evidence drawer shows the
 * source->sink taint path (the engine's `a -> b -> sink (file:line)` strings).
 */
function CodeFindingCard({
  finding,
  defaultOpen = false,
  focus = false,
  proposedFix,
}: {
  finding: CodeFinding;
  defaultOpen?: boolean;
  focus?: boolean;
  proposedFix?: ProposedFix;
}) {
  const { rule, location, flow, score, fix } = finding;
  const tier = flow.tier;
  const sink = `${location.file}:${location.line}`;
  // Fusion provenance (Task 21.4): the "Found by Semgrep OSS · ranked by VulnAdvisor" credit line,
  // shown only when an external scanner corroborated/located the finding (null for native-only).
  const provenance = provenanceLine(finding.provenance);
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const cardRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus) cardRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [focus]);
  const reduceMotion = useReducedMotion() ?? false;
  const story = flow.reason || rule.title;

  return (
    <Card ref={cardRef} size="sm" className="gap-0 py-0" data-tour="finding-card">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset focus-visible:outline-none"
      >
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
            <span className="mono font-semibold">{rule.cwe}</span>
            <span aria-hidden className="text-muted-foreground">
              ·
            </span>
            <span className="mono">{rule.title}</span>
            <span aria-hidden className="text-muted-foreground">
              ·
            </span>
            <span className="mono text-xs text-muted-foreground break-all">{sink}</span>
          </span>
          <span className="mt-0.5 block truncate text-xs text-muted-foreground">{story}</span>
        </span>
        <span className="flex shrink-0 items-center gap-1.5">
          <Badge variant="outline" className={bandClass(score.band)}>
            {score.band} · {Math.round(score.value)}
          </Badge>
          <Badge
            variant="outline"
            data-tour="tier-badge"
            className={cn("max-sm:hidden", sastTierClass(tier))}
          >
            {sastTierLabel(tier)}
          </Badge>
          {proposedFix ? <FixReadyBadge /> : null}
        </span>
        <ChevronDown
          aria-hidden
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </button>

      <motion.div
        id={panelId}
        inert={!open}
        initial={false}
        animate={open ? { height: "auto", opacity: 1 } : { height: 0, opacity: 0 }}
        transition={{ duration: reduceMotion ? 0 : FADE_DURATION, ease: EASE_AEGIS }}
        className="overflow-hidden"
      >
        <article className="space-y-3 border-t px-3 py-3">
          <Badge variant="outline" className={cn("sm:hidden", sastTierClass(tier))}>
            {sastTierLabel(tier)}
          </Badge>

          {/* The validated patch leads the card (Task 19.4): the fix is the hero, evidence follows. */}
          {proposedFix ? <ProposedFixPanel fix={proposedFix} /> : null}

          <Card3 letter="A" title="Attack story">
            {provenance ? (
              <p
                className="mb-2 text-xs font-medium text-muted-foreground"
                data-testid="finding-provenance"
              >
                {provenance}
              </p>
            ) : null}
            <p className="leading-relaxed">{story}</p>
            <p className="mt-2 text-muted-foreground">
              {rule.title} ({rule.cwe}) at <span className="mono">{sink}</span>.
            </p>
            {score.rationale ? (
              <p className="mt-2 text-muted-foreground">{score.rationale}</p>
            ) : null}
          </Card3>

          <div className="grid gap-3 md:grid-cols-2">
            <Card3 letter="B" title="Risk">
              <ul className="space-y-0.5">
                <li>
                  Priority <span className="font-semibold">{Math.round(score.value)}</span> (
                  {score.band})
                </li>
                <li>
                  Confidence <span className="font-semibold">{sastTierLabel(tier)}</span>
                </li>
                <li>
                  Weakness <span className="mono">{rule.cwe}</span>
                </li>
                {flow.source.kind ? (
                  <li className="text-muted-foreground">Source: {flow.source.kind}</li>
                ) : null}
              </ul>
            </Card3>

            <Card3 letter="C" title="Action">
              <p>{fix.direction}</p>
              <p className="mt-2 text-xs text-muted-foreground">
                {proposedFix ? (
                  <>A validated patch is proposed above.</>
                ) : (
                  <>
                    No validated fix in this scan — run <span className="mono">vulnadvisor fix</span>{" "}
                    for a validated patch.
                  </>
                )}
              </p>
            </Card3>
          </div>

          {flow.reason || flow.path.length > 0 ? (
            <EvidenceDrawer
              reason={flow.reason ?? null}
              callPaths={flow.path}
              evidence={[]}
              defaultOpen={flow.path.length > 0}
            />
          ) : null}
        </article>
      </motion.div>
    </Card>
  );
}
