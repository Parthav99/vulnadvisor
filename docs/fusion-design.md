# VulnAdvisor Multi-Tool Fusion — Design (M21)

> **Status: APPROVED 2026-06-20 (maintainer).** This is the architecture agreement that precedes M21
> code (Tasks 21.2–21.4). Tasks 21.2–21.4 implement exactly what this document specifies; a
> deviation requires amending this doc first. The §12 reviewer decisions are resolved in favor of the
> recommendations: (1) **±1 line** merge tolerance; (2) `provenance` added **additively under
> `schema_version` 1.2, no bump** (platform ingest tested for the additive field); (3) a **pinned
> offline Semgrep ruleset** as the default, `--config auto` opt-in.

M20 widened the *native* taint engine (containers, cross-module flow, object state, ~10 new CWE
families). M21 makes us bigger than our own ruleset: we ingest a **second scanner's** findings and
re-rank them through our Python-deep reachability/taint engine. The pitch is not "we have more
rules than Semgrep" — it is **"we make any scanner smarter"**: Semgrep (and friends) emit a flat
list of pattern matches; we turn that list into the same evidence-backed,
deprioritized-vs-actionable, tiered output that is our whole story. Semgrep's own marketing claims
"up to 98% fewer critical false positives" *with* reachability; both Semgrep and Endor have
"limited capabilities for dynamic languages like Python." That is precisely the seam M21 drives
into — we measure how much of Semgrep's raw Python output our reachability deprioritizes, on the
ecosystem where they are weak (Task 21.4 benchmark).

The non-negotiable rule from `CLAUDE.md` applies to fusion without exception: **a false negative is
release-blocking.** An external finding we cannot locate or overlay is **never silently dropped** —
it escalates and stays in the list (§4). Every default in this design is chosen so that uncertainty
escalates and is never silently downgraded to "safe".

---

## 1. Guiding principles (carried from the SCA + SAST engines)

1. **Soundness over precision.** When we cannot overlay an external finding with our own evidence,
   it escalates to `DYNAMIC-UNKNOWN` (§4) and remains in the merged list. We never drop a finding
   because we couldn't reason about it; we never re-rank it to "quiet" on a guess.
2. **Never a binary "reachable / not".** Every imported finding carries one of our confidence tiers
   (`SastTier`, `docs/sast-design.md` §4), exactly as native SAST and SCA findings do.
3. **Deterministic ranking.** The merged list is ordered by the **existing deterministic engine**
   (`engine.sast_scoring.order_unified`), reproducibly, no randomness. The LLM only *explains*.
4. **Show the evidence + the provenance.** We show *why* a finding ranks where it does — our
   source→sink path when we have one — and *who found it* ("found by: Semgrep OSS · ranked by
   VulnAdvisor"). Provenance is a first-class, honest field, never hidden.
5. **Pure and testable core.** The result-parse layer is a pure function over Semgrep's JSON; the
   subprocess shell is a thin, separately-tested wrapper. Parsing is unit-tested with **no Semgrep
   installed** (recorded fixtures).
6. **Zero cost, source never leaves the machine.** Semgrep OSS + community rules are free and run
   locally as a subprocess. No new network call, no new paid service, no telemetry.

---

## 2. What we reuse (and why this is cheap to build)

Fusion is mostly *plumbing into machinery that already exists*. The overlay — proving (or failing
to prove) a flow to a sink — is the M16/M20 taint engine, used as-is.

| Existing component | Fusion reuse |
|---|---|
| `sast/taint.py` (demand-driven taint over the call graph) | The **overlay**: given an external finding's `(file, line, cwe)`, ask the native engine whether a flow reaches that sink → assign a tier (§3). |
| `sast/sinks.py` + `sast/rules.py` (sink detection, CWE rule pack) | Map an external rule's location to a known sink kind when one matches; corroborate the CWE. |
| `sast/model.py` (`SastFinding`, `SastTier`, `tier_concern`) | External findings are normalized into `SastFinding` — **one finding model**, so they flow through scoring/output unchanged. |
| `engine/sast_scoring.py` (`score_sast_findings`, `order_unified`, CWE→severity table) | Scoring + the single ranked list across native + external + SCA findings. No new ranking path. |
| `model/callpath.py` (`CallPath`, `.render()`) | The source→sink evidence when the overlay corroborates a flow (`CONFIRMED-FLOW`). |
| `output/json_report.py`, `output/sarif.py`, `output/gating.py` | JSON (additive `provenance`/`source`), SARIF tool extensions, `--fail-on` over fused findings (Task 21.4). |
| `cli/pipeline.py`, `cli/render.py` | `scan --with-semgrep`; the 3-card output renders provenance (Task 21.4). |

New code is concentrated in one package, `src/vulnadvisor/sast/external/`, plus thin additive hooks
in the shared output/CLI layers.

---

## 3. The external-tool adapter protocol (Task 21.2)

An adapter is the bridge from a third-party scanner to a list of `SastFinding`s. Every adapter is
three pure-ish stages — **run → parse → normalize** — with the impure `run` isolated so `parse` and
`normalize` are unit-testable without the tool installed.

```python
# Conceptual shape — final code lands in sast/external/ (Task 21.2).

class ExternalToolAdapter(Protocol):
    name: str                                  # "semgrep-oss"  (stable provenance id)

    def available(self) -> bool:               # is the tool importable/on PATH? (impure)
        ...

    def run(self, target: Path) -> str:        # subprocess → raw JSON text (impure, isolated)
        ...

    def parse(self, raw: str) -> list[ExternalRawFinding]:
        # PURE. Defensive JSON parse → tool-shaped records. Never raises on malformed input.
        ...

    def normalize(self, records: list[ExternalRawFinding]) -> list[SastFinding]:
        # PURE. Tool record → our SastFinding (rule-id → CWE map, file/line, best-effort tier).
        ...
```

- **`ExternalRawFinding`** is the tool-neutral intermediate: `check_id`/`rule_id`, `file`, `line`,
  `col`, `severity`, `cwe` (when the tool provides one), `message`. Defensive: any missing field
  degrades to a safe default; a record we cannot place (no resolvable file/line) is **kept** and
  marked for `DYNAMIC-UNKNOWN` overlay, never discarded.
- **`run` is the only impure stage** and is shelled with a **fixed argv, no shell** (`semgrep
  --config <ruleset> --json <target>`), a defensive timeout, and tool-absent handled as a clean
  no-op (§7), never a crash. The Task 21.2 tests shell `run` through a mock and assert the
  tool-absent path returns an empty list with a logged reason.
- **`parse` is pure and total.** Malformed JSON → empty list + a logged reason (a "degraded source"
  in the same spirit as SCA `degraded_sources`), never an exception that aborts the scan.
- **Normalization is defensive about CWE.** Semgrep rules expose CWE(s) in
  `extra.metadata.cwe` (e.g. `["CWE-89: ..."]`); we extract the `CWE-\d+` token. An **unknown or
  missing CWE** maps to our default-severity bucket (`engine.sast_scoring.DEFAULT_CWE_SEVERITY`) and
  the overlay later assigns at best `DYNAMIC-UNKNOWN` — the finding survives with honest uncertainty,
  it is never dropped for lacking a CWE.

The protocol is tool-agnostic by construction: Semgrep OSS is the first adapter; `pip-audit` /
Bandit are future corroborators (§9 roadmap) implementing the same three stages.

---

## 4. The reachability-overlay contract (Task 21.3 — the soundness core)

This is where an external finding earns one of *our* tiers. Given a normalized `SastFinding` from an
adapter, the overlay asks the native engine what it knows about that exact sink location and assigns
a tier per the table below. **The contract: every external finding leaves the overlay with exactly
one `SastTier`, or it escalates — it is never returned as "not a finding".**

| Overlay outcome | Tier assigned | Condition |
|---|---|---|
| Our taint engine corroborates a source→sink flow to the external finding's location | **`CONFIRMED-FLOW`** | A native flow reaches the same sink (matched by `(file, line, cwe)` or a containing sink call); the source→sink `CallPath` is attached as evidence. |
| The sink is present and reachable on the call graph but no entry-point source ties to it | **`POSSIBLE-FLOW`** | Mirrors the native `POSSIBLE-FLOW` semantics — discounted (`POSSIBLE_FLOW_PRIORITY_FACTOR`), never zeroed. |
| A dynamic construct on the relevant path blocks certainty | **`DYNAMIC-UNKNOWN`** | Same `has_opaque_dynamic`/unresolved-reflection signals the native engine produces. |
| We **cannot locate or overlay** the external finding at all (file not in our graph, unparseable location, rule we can't map to a sink) | **`DYNAMIC-UNKNOWN`** (escalation) | **Soundness floor.** The finding stays in the list with a reason naming the gap ("located by Semgrep OSS; VulnAdvisor could not overlay reachability"). It is **never** `SANITIZED` and **never** dropped. |
| Our engine proves *every* path to the sink is sanitized for the CWE | **`SANITIZED`** | Only when the native engine itself would say so (total sanitizer coverage); reported for visibility, deprioritized hard, never dropped. |

### Soundness proof obligations (release-blocking invariants)

The SAST analogue of the SCA "zero missed reachable findings" gate, extended to fusion. The Task
21.3 fixture suite must demonstrate each, and any future change must preserve them:

1. **No external finding is silently lost.** Every record an adapter emits appears in the merged
   list with a tier. The Task 21.3 gate asserts `count(external_in) == count(external_in_merged)`
   (modulo dedup, §5, where the survivor still carries the external provenance). This is
   release-blocking.
2. **Un-overlayable escalates, never disappears and never clears.** A finding we cannot place is
   `DYNAMIC-UNKNOWN`, never `SANITIZED`, never absent.
3. **The overlay can only *raise* an external finding's tier, or report what we independently
   prove.** We do not downgrade Semgrep's "error" to quiet on a guess — `SANITIZED` is assigned
   **only** when our own engine proves total sanitizer coverage, identically to native findings. A
   missing overlay never reads as safety.
4. **CWE corroboration disagreement escalates.** If Semgrep's CWE and our matched sink's CWE
   disagree, we keep **both** CWEs in provenance and tier on the *more concerning* outcome — we
   never silently pick the quieter one.
5. **Determinism.** Given the same inputs, overlay tiers and the merged ordering are byte-for-byte
   reproducible (no clock, no set-iteration order leaking into output).

---

## 5. Dedup / merge (Task 21.3)

Native and external scanners will report the same vulnerability. We merge so the user sees **one
record per real issue, with every provenance preserved**.

- **Merge key:** `(file, normalized_line, cwe)`. `normalized_line` tolerates ±1 line drift between
  tools' line attribution for the same call (documented; conservative — a near-miss merges rather
  than duplicating).
- **Survivor selection:** the **richer-evidence record wins** as the displayed record. "Richer" is
  ordered: a record with a source→sink `CallPath` (`flow is not None`) beats one without; among
  those, the higher `tier_concern` wins; ties broken by native-over-external (our evidence is the
  one we can show) then by stable id for determinism.
- **Both provenances are kept.** The survivor's provenance becomes a *set*: e.g.
  `["vulnadvisor", "semgrep-oss"]` — "found by both, ranked by VulnAdvisor". Merging never erases
  that Semgrep also flagged it (corroboration is a *feature* to display), and never erases that we
  flagged it natively.
- **No merge across different CWEs at the same line.** Two genuinely different weaknesses on one
  line (e.g. SSRF + disabled-TLS on one `requests.get`, already a native multi-finding case) stay
  two records — the CWE is part of the key.
- **Ordering:** the merged, de-duplicated list is ordered through the existing deterministic engine
  (`engine.sast_scoring.order_unified`) alongside SCA findings — one ranked list, no separate
  external bucket.

---

## 6. Provenance model

Provenance answers "who found this, and who ranked it" — the honest core of the fusion story.

- A `provenance` (or `source`) field is added to the finding, additive in JSON (§7). For a native
  finding it is `["vulnadvisor"]`; for a Semgrep-only finding `["semgrep-oss"]`; for a corroborated
  finding `["vulnadvisor", "semgrep-oss"]`.
- The display string is fixed and honest: **"found by: Semgrep OSS · ranked by VulnAdvisor
  reachability"** (Task 21.4 renders this in the 3-card output and the dashboard). The *ranking* is
  always attributed to VulnAdvisor because the tier and priority are *our* engine's output, even
  when the *detection* came from Semgrep.
- The external tool's original rule id and severity are preserved in provenance metadata (so a user
  can trace back to the Semgrep rule), but they **never** drive our priority — our deterministic
  engine does.

---

## 7. Licensing / subprocess boundary (the clean-wheel guarantee)

- **Semgrep is invoked only as a subprocess**, never imported. It lives in an **optional `[semgrep]`
  extra**; the published *core* wheel stays at exactly its current runtime-dependency count. A
  metadata test (same pattern as 15.3 / the SAST no-new-dep guard) asserts the core dependency count
  is unchanged.
- **The subprocess boundary is also the license boundary.** Semgrep OSS is LGPL-family / its own
  license; shelling out to a separate process (rather than linking/importing) keeps our
  permissively-licensed core clean. This is documented here as the explicit reason the adapter never
  imports Semgrep.
- **Tool absent → clean skip.** If Semgrep is not installed (or not on PATH), `available()` is
  `False` and the scan proceeds native-only with a one-line "install the `[semgrep]` extra to fuse
  Semgrep OSS findings" notice — never a crash, never a silent failure that looks like "no external
  findings exist".
- **No network, no telemetry.** Semgrep runs offline against local rules; we pin/Configure the
  ruleset and do not send code anywhere. The privacy posture is unchanged.

---

## 8. Output / CLI integration (Task 21.4)

- **CLI:** `scan --with-semgrep` (and a general `--external none|semgrep` selector). Default stays
  native-only (zero behavior change for existing users); fusion is opt-in.
- **JSON:** additive `provenance` (array) / `source` field on each finding; `schema_version` bumps
  if and only if a consumer-visible field is added (additive, and the platform `parse_report` accepts
  the prior versions plus the new one — same compatibility discipline as 1.0→1.1→1.2). Older
  consumers ignore the new field.
- **SARIF:** Semgrep provenance is surfaced via SARIF tool/`toolComponent` extensions; `ruleId`
  stays our stable id, the external rule id rides in properties. CWE taxa and `codeFlows` (when we
  have a flow) are unchanged from the SAST mapping.
- **Gating:** `--fail-on <tier|band|score>` covers fused findings identically — the gate operates on
  the unified band/score, so a `CONFIRMED-FLOW` corroborated from Semgrep fails the build just like a
  native one.
- **3-card + dashboard:** the provenance line renders in Card A's header / the finding card ("found
  by Semgrep OSS · ranked by VulnAdvisor reachability"); the evidence drawer shows our source→sink
  path when present.

---

## 9. Tool roadmap (beyond Semgrep)

Documented so the adapter protocol's generality is intentional, not accidental:

- **Semgrep OSS — first and the focus of M21.** Broadest free Python rule coverage; the strongest
  demonstration of the re-ranking story.
- **`pip-audit` / Bandit — future optional corroborators.** Each implements the same three-stage
  adapter (`run → parse → normalize`). Bandit corroborates first-party CWEs; `pip-audit` corroborates
  dependency advisories. They are *not* in M21 scope; the protocol simply leaves room for them.

---

## 10. Explicit non-goals (M21)

- **We do not re-implement or out-rule Semgrep.** Fusion *ranks* its output; it does not try to
  match its rule breadth. Our value is the reachability overlay, not a bigger pattern library.
- **No execution of external rules in-process.** Semgrep stays a subprocess (§7); we never load its
  rule engine into our process.
- **No new network call and no new paid service.** Everything is local and free.
- **No silent trust of the external tool's tier/severity.** Semgrep's severity is metadata, never
  our priority; our deterministic engine always re-ranks.
- **No overlay beyond what the native engine can prove.** Fusion does not invent reachability — if
  the native engine can't reach a sink, the external finding is `POSSIBLE-FLOW`/`DYNAMIC-UNKNOWN`,
  not a fabricated `CONFIRMED-FLOW`.
- **No cross-language / non-Python external findings in scope.** Semgrep can scan other languages;
  M21 fuses its **Python** output only (our overlay is Python-specific). Non-Python external
  findings are out of scope this phase (a documented under-approximation, not a silent drop —
  they are simply not requested from the tool).

---

## 11. Test & fixture strategy

Mirrors the SCA/SAST discipline (table-driven, fixture-backed, soundness-gated):

- **21.2 parse tests** — table-driven over recorded Semgrep JSON: single finding, multi-finding,
  unknown rule (→ best-effort CWE / `DYNAMIC-UNKNOWN`), malformed JSON (→ safe skip with a logged
  reason). Subprocess shelled through a mock; **tool-absent → clean skip** tested; core wheel
  dependency count unchanged (metadata test).
- **21.3 overlay + dedup tests** — fixtures where our taint **agrees** with Semgrep (→
  `CONFIRMED-FLOW` with a path) and **disagrees** / can't locate (→ `POSSIBLE-FLOW` /
  `DYNAMIC-UNKNOWN`, never dropped). Dedup keeps exactly one record with **both** provenances;
  ordering deterministic via the engine. **Zero external findings silently lost** is
  release-blocking (the count invariant, §4.1).
- **21.4 integration + benchmark** — mixed native+Semgrep ranked list snapshot-tested; JSON/SARIF
  validate; ingest accepts the new field; dashboard renders a seeded fused finding. The fusion
  benchmark (extending `benchmarks/SAST-REPORT.md`) measures **how much of Semgrep's Python output
  our reachability deprioritizes**, reproducible by one command — our honest answer to Semgrep's
  "up to 98%" claim, measured on Python where they are weak.
- **Global gate every task** — `ruff check` + `ruff format --check`, `mypy --strict src`, `pytest`
  green, `PROGRESS.md` updated, commit + push.

---

## 12. Reviewer decisions (resolved 2026-06-20)

1. **Merge line tolerance** — **±1 line** (§5). Absorbs tool line-attribution drift for the same
   call; conservative (a near-miss merges rather than showing a duplicate). A fixture documents the
   ±1 behavior in 21.3.
2. **`schema_version` bump** — **no bump; `provenance` is added additively under `1.2`.** Old
   consumers ignore the unknown key and the platform already tolerates additive fields; 21.4 tests
   platform ingest of a `1.2` report carrying the new field.
3. **Default ruleset for Semgrep** — **pinned offline ruleset is the default**, `--config auto`
   opt-in. Keeps the run fully local ("source never leaves the machine") and the benchmark numbers
   reproducible by a stranger.
