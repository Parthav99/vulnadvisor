import { Shield, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Posture, PostureLevel } from "@/lib/posture";

// Visual semantics follow the Aegis palette contract (lib/format.ts): teal only for
// provably-safe, red only for confirmed risk, amber for uncertainty — and "unverified"
// gets the dashed border so uncertainty reads as unresolved, never as a softer safe.
const STYLES: Record<
  PostureLevel,
  { icon: LucideIcon; text: string; frame: string; pulse: boolean }
> = {
  "at-risk": { icon: ShieldAlert, text: "text-risk", frame: "ring-1 ring-risk/40", pulse: true },
  "under-watch": { icon: Shield, text: "text-warn", frame: "ring-1 ring-warn/40", pulse: true },
  unverified: {
    icon: Shield,
    text: "text-warn",
    frame: "border border-dashed border-warn/60",
    pulse: true,
  },
  protected: { icon: ShieldCheck, text: "text-safe", frame: "ring-1 ring-safe/40", pulse: true },
  awaiting: {
    icon: Shield,
    text: "text-muted-foreground",
    frame: "ring-1 ring-border",
    pulse: false,
  },
};

/** The org-home shield hero: answers "am I protected?" in one glance. */
export function PostureHero({ posture }: { posture: Posture }) {
  const s = STYLES[posture.level];
  const Icon = s.icon;
  return (
    <section
      aria-label="Security posture"
      className={cn("mb-6 rounded-xl bg-card p-4 sm:p-5", s.frame)}
    >
      <div className="flex items-start gap-4">
        <div className={cn("relative mt-0.5 shrink-0", s.text)}>
          <Icon aria-hidden className="size-9" strokeWidth={1.5} />
          {s.pulse ? (
            <span aria-hidden className="absolute -top-0.5 -right-0.5 flex size-2.5">
              <span className="status-pulse absolute h-full w-full rounded-full bg-current" />
              <span className="relative size-2.5 rounded-full bg-current" />
            </span>
          ) : null}
        </div>
        <div className="min-w-0">
          <h2 className={cn("font-heading text-lg leading-snug font-semibold", s.text)}>
            {posture.headline}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{posture.detail}</p>
        </div>
      </div>
    </section>
  );
}
