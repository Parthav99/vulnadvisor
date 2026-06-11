// Presentation helpers: colors for priority bands and reachability tiers, date formatting.
//
// Aegis palette semantics (the source of truth for state colors app-wide):
//   red = confirmed risk only · amber = uncertainty · blue = low/wayfinding ·
//   teal (--safe) = the ONE guarded accent, used solely for provably-safe states
//   (not-imported is the only "confidently safe" tier).

const BAND_CLASSES: Record<string, string> = {
  critical: "border-risk/50 text-risk bg-risk/10",
  high: "border-elevated/50 text-elevated bg-elevated/10",
  medium: "border-warn/50 text-warn bg-warn/10",
  low: "border-info/50 text-info bg-info/10",
  info: "border-muted-foreground/50 text-muted-foreground bg-muted-foreground/10",
};

const TIER_CLASSES: Record<string, string> = {
  "imported-and-called": "border-risk/50 text-risk bg-risk/10",
  imported: "border-warn/50 text-warn bg-warn/10",
  // Dashed border: uncertainty is visibly *unresolved*, never styled as safe.
  "dynamic-unknown": "border-dashed border-warn/60 text-warn bg-warn/10",
  "not-imported": "border-safe/50 text-safe bg-safe/10",
  unknown: "border-muted-foreground/50 text-muted-foreground bg-muted-foreground/10",
};

const TIER_LABELS: Record<string, string> = {
  "imported-and-called": "IMPORTED-AND-CALLED",
  imported: "IMPORTED",
  "dynamic-unknown": "DYNAMIC-UNKNOWN",
  "not-imported": "NOT-IMPORTED",
  unknown: "UNKNOWN",
};

export function bandClass(band: string): string {
  return BAND_CLASSES[band] ?? BAND_CLASSES.info;
}

export function tierClass(tier: string): string {
  return TIER_CLASSES[tier] ?? TIER_CLASSES.unknown;
}

export function tierLabel(tier: string): string {
  return TIER_LABELS[tier] ?? tier.toUpperCase();
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

// Canonical CVE-first display identity — mirrors src/vulnadvisor/model/display.py.
// Order: lowest-numbered CVE (by year, then number) → GHSA → PYSEC → raw advisory id.
// Display contexts never use "==" between package and version (that's for fix commands only).

const CVE_RE = /^CVE-(\d{4})-(\d{4,})$/i;
const GHSA_RE = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
const PYSEC_RE = /^PYSEC-\d{4}-\d+$/i;

export interface AdvisoryIdentity {
  id: string;
  display_id?: string;
  aliases?: string[];
}

export function displayId(advisory: AdvisoryIdentity): string {
  if (advisory.display_id) return advisory.display_id;
  const candidates = [advisory.id, ...(advisory.aliases ?? [])]
    .filter((c): c is string => typeof c === "string")
    .map((c) => c.trim())
    .filter((c) => c.length > 0);

  const cves = candidates
    .map((c) => {
      const m = CVE_RE.exec(c);
      return m ? { year: Number(m[1]), num: Number(m[2]), id: c.toUpperCase() } : null;
    })
    .filter((c): c is { year: number; num: number; id: string } => c !== null)
    .sort((a, b) => a.year - b.year || a.num - b.num);
  if (cves.length > 0) return cves[0].id;

  const ghsa = candidates.find((c) => GHSA_RE.test(c));
  if (ghsa) return ghsa;
  const pysec = candidates.find((c) => PYSEC_RE.test(c));
  if (pysec) return pysec;
  return advisory.id;
}

export function displayTitle(finding: {
  dependency: { name: string; version: string | null };
  advisory: AdvisoryIdentity;
}): string {
  const version = finding.dependency.version || "(unpinned)";
  return `${displayId(finding.advisory)} · ${finding.dependency.name} ${version}`;
}

// Null or placeholder ("0000…") SHAs mean "no commit recorded" — callers render a neutral
// "local scan" badge instead of fabricated provenance (Task 12.2).
const PLACEHOLDER_SHA_RE = /^0+$/;

export function shortSha(sha: string | null | undefined): string | null {
  if (!sha) return null;
  const trimmed = sha.trim();
  if (!trimmed || PLACEHOLDER_SHA_RE.test(trimmed)) return null;
  return trimmed.slice(0, 7);
}

export function shortRef(ref: string | null | undefined): string | null {
  if (!ref) return null;
  const short = ref.replace(/^refs\/heads\//, "").replace(/^refs\/tags\//, "").trim();
  return short || null;
}
