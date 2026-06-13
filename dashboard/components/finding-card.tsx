"use client";

import { useEffect, useId, useRef, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Check, ChevronDown, Copy } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { bandClass, displayId, tierClass, tierLabel } from "@/lib/format";
import { EASE_AEGIS, FADE_DURATION } from "@/lib/motion";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/types";

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

function CopyFixButton({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      aria-label="Copy fix command"
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
      <span aria-live="polite">{copied ? "Copied" : "Copy"}</span>
    </Button>
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
 * One finding with progressive disclosure: a scannable collapsed row (identity, badges,
 * one-line verdict) that expands into the signature three cards plus an evidence drawer.
 *
 * The expanded panel is always in the DOM (SSR renders the full story); collapsing
 * animates height to 0 and marks the panel `inert`, so hidden content never traps
 * keyboard focus or appears to assistive tech.
 */
export function FindingCard({
  finding,
  defaultOpen = false,
  focus = false,
}: {
  finding: Finding;
  defaultOpen?: boolean;
  /** When the copilot deep-links here (?finding=…), scroll this card into view on mount. */
  focus?: boolean;
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
