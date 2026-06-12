import { Badge } from "@/components/ui/badge";

// Per-repo onboarding status chip (Task 14.2). Palette semantics from lib/format.ts:
// teal only for the provably-good state (scans arriving), amber for the in-between
// (merged but unverified), blue for wayfinding (a PR awaits action), muted for not set up.
const CHIPS: Record<string, { label: string; className: string }> = {
  "receiving-scans": { label: "Receiving scans", className: "border-safe/50 text-safe bg-safe/10" },
  "pr-open": { label: "Setup PR open", className: "border-info/50 text-info bg-info/10" },
  "pr-merged": {
    label: "Merged · awaiting first scan",
    className: "border-warn/50 text-warn bg-warn/10",
  },
  "not-set-up": {
    label: "Not set up",
    className: "border-muted-foreground/40 text-muted-foreground",
  },
};

export function SetupChip({ status }: { status: string }) {
  const chip = CHIPS[status] ?? CHIPS["not-set-up"];
  return (
    <Badge variant="outline" className={chip.className}>
      {chip.label}
    </Badge>
  );
}
