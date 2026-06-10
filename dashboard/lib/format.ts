// Presentation helpers: colors for priority bands and reachability tiers, date formatting.

const BAND_CLASSES: Record<string, string> = {
  critical: "border-[#f85149] text-[#ff7b72] bg-[#f8514922]",
  high: "border-[#db6d28] text-[#ffa657] bg-[#db6d2822]",
  medium: "border-[#d29922] text-[#e3b341] bg-[#d2992222]",
  low: "border-[#388bfd] text-[#79c0ff] bg-[#388bfd22]",
  info: "border-[#6e7681] text-[#8b949e] bg-[#6e768122]",
};

const TIER_CLASSES: Record<string, string> = {
  "imported-and-called": "border-[#f85149] text-[#ff7b72] bg-[#f8514922]",
  imported: "border-[#d29922] text-[#e3b341] bg-[#d2992222]",
  "dynamic-unknown": "border-[#a371f7] text-[#d2a8ff] bg-[#a371f722]",
  "not-imported": "border-[#3fb950] text-[#56d364] bg-[#3fb95022]",
  unknown: "border-[#6e7681] text-[#8b949e] bg-[#6e768122]",
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

export function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

export function shortRef(ref: string): string {
  return ref.replace(/^refs\/heads\//, "").replace(/^refs\/tags\//, "");
}
