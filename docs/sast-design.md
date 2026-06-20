# VulnAdvisor SAST v1 — Design (M16)

> **Status: APPROVED 2026-06-13 (maintainer).** This is the architecture agreement that precedes
> M16 code. Tasks 16.2–16.6 implement exactly what this document specifies; a deviation requires
> amending this doc first. Reviewer decisions on the §13 open questions are folded in below:
> (1) the `POSSIBLE-FLOW` discount factor is fixed in **16.4** with a table-driven test;
> (2) **CWE-798 stays in v1** as a literal-pattern finding; (3) **stdin/argv/env are untrusted by
> default**.

This is the pivot: VulnAdvisor stops being SCA-only and starts triaging **first-party Python
vulnerabilities** — bugs in the user's *own* code — using the same call graph, the same
deterministic engine, and the same tiers-and-evidence output as the dependency reachability
engine. The motto holds verbatim: **stop scanning, start triaging.** Bandit (and friends) emit a
flat list of pattern matches; we report *which sink is reachable from a real entry point, with the
source→sink path shown*, ranked by the same priority math, with the same soundness guarantees.

The non-negotiable rule from `CLAUDE.md` applies to SAST without exception: **a false negative is
release-blocking.** A missed reachable flow can cause a breach. Every tier and every default in
this design is chosen so that uncertainty escalates and is never silently downgraded to "safe".

---

## 1. Guiding principles (carried from the SCA engine)

1. **Soundness over precision.** When taint cannot be proven *or disproven*, the finding escalates
   (`POSSIBLE-FLOW` or `DYNAMIC-UNKNOWN`), never silently disappears. The only confidently-clear
   outcome is `SANITIZED` on *every* path, with the sanitizer shown.
2. **Never a binary "vulnerable / not".** Every SAST finding carries a confidence tier (§4),
   exactly as SCA findings carry a reachability tier.
3. **Deterministic ranking.** Priority is computed by code from a fixed CWE→severity table and the
   tier (§5). Reproducible, no randomness, no clock, no I/O. The LLM only *explains*.
4. **Show the evidence.** Card A tells the story; the evidence drawer shows the **source→sink
   path** in the exact `a -> b -> sink (file:line)` format reachability already uses
   (`model/callpath.py`). The path *is* the demo.
5. **Pure and testable core.** Rule matching, taint propagation, and tier assignment are pure
   functions over parsed ASTs and the existing call graph — no hidden I/O, table-driven tests.
6. **One engine, one output.** SAST findings flow through the existing `engine/` scoring and
   `output/` (JSON + SARIF + exit codes). The CLI shows **one ranked list** mixing first-party
   (SAST) and third-party (SCA) risk.

---

## 2. What we reuse (and why this is cheap to build)

The differentiator — proving a flow from a real entry point — already exists for dependencies.
SAST reuses it almost wholesale:

| Existing component | SAST reuse |
|---|---|
| `callgraph/import_graph.py` (`_iter_python_files`, defensive parse) | File walk + AST parse; skip-on-error semantics inherited. |
| `callgraph/call_paths.py` (demand-driven BFS, `_Node`, edges) | The same intra-/inter-procedural call graph; taint rides these edges (§6). |
| `callgraph/frameworks/` (FastAPI, Django plugins, `EntryPoint`) | **Sources** = framework entry-point parameters. Entry-point breadth expands in 16.3. |
| `callgraph/type_resolver.py` (Pyright, optional) | Narrows reflective/attribute dispatch — same precision lever, same soundness fallback. |
| `model/callpath.py` (`CallPath`, `CallStep`, `.render()`) | The source→sink evidence path, byte-for-byte the same shape. |
| `engine/scoring.py` (`compute_score`, bands, `order_findings`) | Scoring; SAST supplies severity from the CWE table instead of CVSS/EPSS (§5). |
| `output/json_report.py`, `output/sarif.py`, `output/gating.py` | JSON `1.2`, SARIF, `--fail-on` — additive, both finding types in one report (§7–8). |
| `cli/render.py` (the 3-card terminal output) | SAST findings render in the same 3 cards (16.4). |

New code is concentrated in one package, `src/vulnadvisor/sast/`, plus thin additive hooks in the
shared layers.

---

## 3. Rule schema (sources / sinks / sanitizers as data)

Rules are **data, matched by pure functions** — never imperative per-CWE code paths. A rule pack is
a frozen, versioned table; adding a CWE or a sink is a data edit plus a test, not a new code branch.
The proposed shape (final pydantic models land in 16.2; this fixes the contract):

```python
# Conceptual shape — see sast/rules.py (Task 16.2) for the pydantic models.

class SinkRule:
    cwe: str                      # "CWE-89"
    kind: str                     # "sql-injection"  (stable machine id)
    # How the sink call is recognized, resolved through the existing import graph
    # so aliases work (`import yaml as y`, `from os import system`):
    callee: CalleePattern         # module+attr ("yaml.load") | bare-from-import ("system")
    tainted_args: ArgSelector     # which positional/keyword args carry the dangerous value
    # A sink that is *only* dangerous under a flag (e.g. subprocess(..., shell=True)):
    guard: ArgPredicate | None    # require shell=True; else not a sink
    # Args whose presence proves the call is safe (mirrors call_paths guarded_apis):
    safe_args: frozenset[str]     # e.g. {"SafeLoader"} for yaml.load(Loader=...)

class SourceRule:
    kind: str                     # "http-request-body", "argv", "env", ...
    origin: SourceOrigin          # framework-param | stdin | argv | env | file-read(advisory)

class SanitizerRule:
    cwe: str                      # the CWE(s) this sanitizer clears
    callee: CalleePattern         # e.g. "shlex.quote", parameterized-query construction
    # A sanitizer clears taint for its CWE only; an SQL escaper does not clear command injection.
```

Key properties:

- **Attribute resolution via the existing import graph.** A sink is matched on the *resolved*
  callee, so `import yaml as y; y.load(x)`, `from os import system; system(x)`, and
  `os.system(x)` all match the same rule. This is the same binding logic `call_paths._bindings`
  already implements; 16.2 reuses it rather than re-parsing imports.
- **Sanitizers are CWE-scoped.** `shlex.quote` clears CWE-78 (command injection) but not CWE-89
  (SQLi). A sanitizer never clears taint globally — only for the CWE(s) it actually addresses.
- **Guards model conditional sinks.** `subprocess.run(cmd, shell=True)` is a sink; the same call
  without `shell=True` (list argv) is not. The `guard` predicate keeps this in data.
- **Defensive matching.** Every matcher tolerates malformed/unusual AST (computed callees, starred
  args, unparseable name args) by falling back to the *conservative* classification
  (`POSSIBLE-FLOW`/`DYNAMIC-UNKNOWN`), never by crashing and never by clearing the sink.

### Initial CWE set (v1)

| CWE | Name | Representative sinks (resolved) | Recognized sanitizers (v1) |
|---|---|---|---|
| **CWE-89** | SQL injection | `cursor.execute` / `executemany` with non-literal SQL; SQLAlchemy `text()` on non-literal; string-built queries | parameterized query (placeholders + params arg); ORM query builders |
| **CWE-78** | OS command injection | `os.system`; `subprocess.*` with `shell=True`; `os.popen` | list-argv form (no shell); `shlex.quote` on every interpolated value |
| **CWE-94 / CWE-95** | Code injection (`eval`/`exec`) | `eval`, `exec`, `compile` on non-literal; `__import__` on non-literal | none — non-literal `eval`/`exec` of user data has no recognized v1 sanitizer (stays `POSSIBLE`/`CONFIRMED`) |
| **CWE-502** | Unsafe deserialization | `pickle.load(s)`/`loads`; `yaml.load` without `SafeLoader`; `marshal.loads`; `jsonpickle` | `yaml.safe_load` / `Loader=SafeLoader`; `json.loads` |
| **CWE-22** | Path traversal | `open` / `os.path.join` / `pathlib.Path` / `send_file` with non-literal path component | path confinement check (`os.path.realpath` + prefix assertion); `werkzeug.secure_filename` |
| **CWE-918** | SSRF | `requests.*` / `urllib.request.urlopen` / `httpx.*` / `aiohttp` with non-literal URL | allowlist/scheme-host validation against a constant set |
| **CWE-798** | Hardcoded secrets | string literals matching curated secret patterns (AWS keys, private-key headers, high-entropy assignment to `password`/`token`/`secret`) | n/a — a literal-only, non-taint finding (§4 note) |

### Breadth CWE families (Task 20.4)

Added in M20 to roughly double the vuln classes. Taint-based families fit the v1 source→sink model;
**intrinsic** families (marked) are decided in the intra-procedural pass (the call pattern *is* the
weakness, independent of argument taint — same posture as CWE-798), honoring `guard` /
`safe_keyword_values`.

| CWE | Name | Representative sinks (resolved) | Safe form |
|---|---|---|---|
| **CWE-1336** | Server-side template injection | `flask.render_template_string`; `jinja2.Template`; `Environment().from_string` on taint | pass user input as template *context*, not as the template |
| **CWE-611** | XXE | `lxml.etree.*`; `xml.etree.ElementTree.*`; `xml.dom.*`; `xml.sax.*` on taint | `defusedxml` (a different module → not a finding) |
| **CWE-601** | Open redirect | `flask.redirect`; `werkzeug.utils.redirect`; `django.shortcuts.redirect` / `HttpResponseRedirect` on taint | allowlist / relative-only target |
| **CWE-90** | LDAP injection | `search` / `search_s` / `search_ext_s` filter arg (index 1–2) on taint | `ldap.filter.escape_filter_chars` |
| **CWE-643** | XPath injection | `.xpath(...)`; `lxml.etree.XPath` / `ETXPath` on taint | parameterized XPath / strict validation |
| **CWE-1333** | ReDoS | `re.compile`/`match`/`search`/`sub`/… with a non-literal **pattern** | fixed pattern; bounded input; non-backtracking engine |
| **CWE-22** (intrinsic) | Archive path traversal (tarbomb/zip-slip) | `extractall` | `filter="data"`/`"tar"` (Python 3.12+) |
| **CWE-327/328** (intrinsic) | Weak cryptographic hash | `hashlib.md5` / `hashlib.sha1` | SHA-256+; `usedforsecurity=False` for non-security checksums |
| **CWE-330** (intrinsic) | Insecure randomness | `random.*` generators in a security context | `secrets` / `os.urandom` (a different module → not a finding) |
| **CWE-295** (intrinsic, guarded) | Disabled TLS verification | `requests.*` / `httpx.*` with `verify=False`; `ssl._create_unverified_context` | keep verification on; supply a CA bundle if needed |

A single call can be **multiple** findings: `requests.get(url, verify=False)` is both SSRF (the
tainted URL) and disabled-TLS (the keyword), so the matcher returns every matching rule.
**Conservative limitation:** weak *ciphers* (DES/RC4 via `Crypto.Cipher.*.new`) are not yet covered —
their `from-import`-then-`.new()` shape is not module-resolvable by the current binding model;
covering them is future work (the dominant `hashlib.md5`/`sha1` hash case is covered).

CWE-798 is special: it is a **literal-pattern** finding, not a taint flow (the "source" *is* the
literal). It is reported as a standalone tier (`CONFIRMED-FLOW` meaning "the secret literal is
present in source"), and does not participate in source→sink propagation. This is documented
explicitly so the soundness model stays coherent.

---

## 4. Confidence tiers (the soundness contract)

SAST findings carry their own tier enum (`sast/` model, additive — it does **not** reuse
`ReachabilityTier`, whose vocabulary is import-centric). The four tiers and their **proof
obligations**:

| Tier | Meaning | Proof obligation (what the engine must establish) |
|---|---|---|
| **`CONFIRMED-FLOW`** | A taint path from a recognized source to a recognized sink is proven, with no recognized sanitizer on that path. | There exists a concrete source→sink path on the call graph (§6) along which the tainted value reaches a `tainted_arg` of the sink, and **no** `SanitizerRule` for the sink's CWE was applied on that path. The path is rendered as evidence. |
| **`POSSIBLE-FLOW`** | The sink is reached with a non-literal argument, but a full source→sink taint path was not proven (e.g. the value's provenance is intra-procedural-only, or the entry-point connection is unproven). | A sink call with a non-literal `tainted_arg` exists and is reachable on the call graph, but no entry-point source was tied to it. **Never** downgraded below this on the basis of "probably fine". |
| **`DYNAMIC-UNKNOWN`** | A dynamic construct on the path blocks certainty: `eval`/`exec`/`__import__`, reflective dispatch (`getattr`) the resolver cannot pin down, a computed callee, or a file that failed to parse on the relevant path. | The same `has_opaque_dynamic` / unresolved-reflection signals `call_paths.py` already produces. Escalation-only: a dynamic block **upgrades** uncertainty, never reduces it. |
| **`SANITIZED`** | Every path from source to the sink applies a recognized sanitizer for the sink's CWE. | For **every** discovered source→sink path, a matching `SanitizerRule` was applied before the sink. If even one path is unsanitized → `CONFIRMED-FLOW`/`POSSIBLE-FLOW`, never `SANITIZED`. |

### Soundness proof obligations (release-blocking invariants)

These are the invariants the 16.3 fixture suite must demonstrate and that any future change must
preserve. They are the SAST analogue of the SCA "zero missed reachable findings" gate:

1. **No silent clear.** No input — malformed AST, partial parse, exotic construct, partial
   sanitization — may cause a real sink to be reported as `SANITIZED` or dropped. The failure mode
   of every matcher is *toward* a higher tier.
2. **`SANITIZED` requires total coverage.** A finding is `SANITIZED` only when *every* path is
   sanitized for the sink's CWE. Partially-sanitized → the unsanitized tier (a fixture proves a
   two-path function where one path is sanitized comes out `CONFIRMED-FLOW`).
3. **Dynamic never downgrades.** A dynamic construct on a path can only move a finding *up* the
   concern order (toward `DYNAMIC-UNKNOWN`); it can never turn `CONFIRMED-FLOW` into something
   quieter, and `DYNAMIC-UNKNOWN` never becomes `SANITIZED`.
4. **Entry-point completeness is sacred.** A missed source (un-modeled entry point) is a
   catastrophic false negative. 16.3 expands entry-point breadth (Celery `@task`, Flask routes,
   Django `@receiver`) precisely because of this, and the fixture suite includes framework-routed
   flows for FastAPI and Django.
5. **Cross-language boundaries escalate** (see §9 FFI policy) — a trace into a native extension
   never silently terminates as "clean".

Concern ordering for ranking/aggregation (most → least): `CONFIRMED-FLOW` >
`DYNAMIC-UNKNOWN` > `POSSIBLE-FLOW` > `SANITIZED`. (`DYNAMIC-UNKNOWN` outranks `POSSIBLE-FLOW`
because a dynamic block on a sink-reaching path is *more* alarming than an unproven-source sink.)

---

## 5. Scoring (deterministic, no EPSS for first-party)

SCA scoring blends CVSS + EPSS + KEV (`engine/scoring.py`). **None of those exist for a
first-party bug** — there is no CVE, no EPSS probability, no KEV listing for code we just wrote.
So SAST severity comes from a fixed **CWE→base-severity table**, fed into the *same*
`compute_score` machinery with EPSS and KEV absent (the formula already handles
`epss_probability=None` by falling back to `risk = severity/10`, and `in_kev=False`):

| CWE | Base severity (0–10) | Rationale |
|---|---|---|
| CWE-89 SQLi | 9.0 | Direct data exfiltration / RCE-adjacent. |
| CWE-78 Command injection | 9.5 | Direct RCE. |
| CWE-94/95 Code injection | 9.5 | Direct RCE. |
| CWE-502 Unsafe deserialization | 9.0 | RCE in practice for pickle/`yaml.load`. |
| CWE-22 Path traversal | 7.5 | Arbitrary file read/write, often pre-auth. |
| CWE-918 SSRF | 7.5 | Internal network pivot, metadata theft. |
| CWE-798 Hardcoded secret | 7.0 | Credential exposure; impact depends on the secret. |

**Tier weighting.** The CWE base severity is the ceiling; the tier discounts it the way
reachability discounts SCA findings (`apply_reachability`), so an unproven-source sink does not
outrank a proven cloud-CVE-grade dependency flaw:

- `CONFIRMED-FLOW` → full severity (no discount).
- `DYNAMIC-UNKNOWN` → full severity retained (uncertainty is **not** a discount — soundness), but
  the rationale records the dynamic block.
- `POSSIBLE-FLOW` → a documented partial discount (proposed factor mirrors the IMPORTED-vs-CALLED
  gap; exact constant fixed in 16.4 with a table-driven test) — still ranked, never zeroed.
- `SANITIZED` → scaled into the INFO band and relabeled (mirrors `NOT_IMPORTED_PRIORITY_FACTOR`):
  reported for visibility, deprioritized hard, never dropped.

The exact constants live in `engine/` next to the SCA ones, fully unit-tested, and are
**reproducible** — the LLM never touches them. This table and the discount factors are published
in the docs so the ranking is auditable.

---

## 6. Taint propagation (16.3 — the differentiator)

Demand-driven, over the **existing** call graph (`call_paths.py`), not a new whole-program engine:

- **Sources** seed taint: framework entry-point parameters (request body/query/path/headers via
  the FastAPI/Django plugins, expanded in 16.3 to Celery/Flask/signals) plus `stdin`, `argv`,
  `os.environ`.
- **Propagation** is conservative and intra-/inter-procedural: assignments (`x = tainted`),
  augmented assignments, calls passing a tainted value as an argument (taint flows to the callee
  parameter — riding the same edges the call-path BFS walks), returns (a function returning a
  tainted value taints its call site), f-strings / `%` / `+` concatenation, and containers
  (list/dict/tuple membership) handled conservatively (a tainted element taints the container).
- **Sinks** are the §3 rule pack. When a tainted value reaches a `tainted_arg` of a sink with no
  CWE-matching sanitizer on the path → `CONFIRMED-FLOW`, evidence = the source→sink `CallPath`.
- **Sanitizers** clear taint for their CWE when applied to the value before the sink.
- **Dynamic constructs** on the path → `DYNAMIC-UNKNOWN`, reusing the exact `has_opaque_dynamic` /
  reflection signals already produced.

Conservatism direction is always *toward* taint: when propagation is unsure whether a value is
tainted, it treats it as tainted (over-report, then let the tier and sanitizer evidence speak) —
never the reverse.

---

## 7. JSON output — `schema_version` 1.2 (additive)

`schema_version` bumps **1.1 → 1.2**, additive only. Every 1.1 field is unchanged, so 1.0 and 1.1
consumers (including the platform `parse_report`, which must accept `1.0`, `1.1`, and `1.2`)
keep reading 1.2 reports. The single additive change is a **`finding_type`** discriminator and a
SAST-specific finding sub-shape:

```jsonc
{
  "schema_version": "1.2",
  "tool": { "name": "vulnadvisor", "version": "<x.y.z>" },
  "degraded_sources": [ ... ],
  "summary": { "total": 0, "by_band": { ... } },   // unchanged
  "findings": [
    {
      "finding_type": "dependency",                 // NEW: present on every finding.
      "dependency": { ... }, "advisory": { ... },   // ...existing SCA shape unchanged...
      "reachability": { ... }, "score": { ... }, "fix": { ... }
    },
    {
      "finding_type": "code",                        // NEW first-party finding kind.
      "rule": {
        "cwe": "CWE-89",
        "kind": "sql-injection",
        "title": "SQL injection via tainted query string"
      },
      "location": { "file": "app/db.py", "line": 42, "column": 8 },
      "flow": {                                      // the source->sink evidence (may be empty for CWE-798)
        "tier": "confirmed-flow",
        "source": { "kind": "http-request-body", "file": "app/api.py", "line": 10 },
        "sink":   { "kind": "sql-injection",      "file": "app/db.py",  "line": 42 },
        "path":   [ "handle_order -> build_query -> cursor.execute (app/db.py:42)" ],
        "sanitizers": []
      },
      "score": { "value": 90.0, "band": "critical", "verdict": "Fix now",
                 "rationale": "CWE-89 base 9.0; CONFIRMED-FLOW", "cvss_known": false },
      "fix": { "direction": "Use a parameterized query; pass user input as a bound parameter.",
               "has_fix": false }   // the *real* validated fix is M17; v1 gives remediation direction
    }
  ]
}
```

Notes:

- `finding_type` is **required and present on existing dependency findings too** (set to
  `"dependency"`), so consumers can branch reliably. This is additive (a new key with a known
  default for old shapes), not a breaking change.
- `score` reuses the existing serialization; `cvss_known` is `false` for code findings (no CVSS).
- For CWE-798 the `flow` block carries the literal match site, `source == sink`, and an empty path.
- The platform ingest change (16.4) accepts `1.2` and, only if a code finding needs a denormalized
  column, adds it via an additive Alembic migration (the existing payload column already stores the
  full JSON, so most of this is free).

---

## 8. SARIF mapping

SARIF stays 2.1.0 and additive (`output/sarif.py`):

- **`ruleId`** for a code finding is the stable rule id, namespaced to avoid colliding with
  advisory ids: **`vulnadvisor/<kind>`** (e.g. `vulnadvisor/sql-injection`). SCA `ruleId` stays the
  raw advisory id, unchanged.
- **CWE taxonomy.** Each code rule's `reportingDescriptor` gets `relationships` referencing the
  **CWE taxonomy** (`taxa` with `toolComponent.name: "CWE"`), so GitHub code scanning shows the
  CWE. This is the proper SARIF mechanism for CWE and is purely additive.
- **`level`** maps the priority band exactly as SCA does (`error`/`warning`/`note`).
- **`security-severity`** = the CWE base severity (or priority/10), so GitHub orders by our triage
  priority.
- **`codeFlows`.** The source→sink path is emitted as a SARIF `codeFlow` /
  `threadFlow` (each `CallStep` → a `threadFlowLocation`), so GitHub renders the flow inline. This
  is the SARIF-native home for the evidence path and is new for code findings only.
- **`location`** points at the sink's real `file:line` (SCA still points at the manifest).

`--fail-on <tier|band|score>` (`output/gating.py`) covers **both** finding types in one threshold:
the gate operates on the unified `band`/`score`, with tier-name support extended to the SAST tier
vocabulary.

---

## 9. FFI boundary policy (cross-language)

A traced taint path that crosses into a **C/Rust/native extension** (a call resolved to a compiled
module — `.so`/`.pyd`, a C-extension import, or a `ctypes`/`cffi` invocation) **escalates** rather
than terminating the trace as clean:

- If the tainted value is passed *into* the native boundary and the trace cannot follow it, the
  finding is reported at **`DYNAMIC-UNKNOWN`** with a reason naming the native boundary — the same
  "we cannot rule this out" semantics as an opaque dynamic call. It is **never** treated as a
  sanitizer or as the end of a clean path.
- Full cross-language call graphs (following taint *through* native code into another language) are
  an **explicit non-goal this phase** (§10).

This keeps soundness intact at the one place naive static analyzers silently lose the trail.

---

## 10. Explicit non-goals (v1)

Documented so reviewers know the boundaries and the soundness model stays honest:

- **No cross-language call graphs.** Taint is not followed through C/Rust/native code; such
  boundaries escalate (§9), they are not traced.
- **No dataflow through I/O.** Taint is not tracked through the filesystem, a database round-trip,
  a message queue, or a network hop (write-then-read elsewhere). A value written to a file/DB and
  later read back is treated as a fresh, untainted read **unless** that read is itself a modeled
  source. (This is a known under-approximation; it is recorded here, and such reads are candidates
  for future source rules rather than silent flows.)
- **No inter-file aliasing beyond the call graph.** Module-level mutable global state passed
  implicitly is not tracked; only call-graph edges and explicit returns/args carry taint.
- **No taint through `eval`/`exec`-constructed code.** These are `DYNAMIC-UNKNOWN` by construction.
- **No automatic fix.** v1 emits *remediation direction* (Card C). The validated, machine-proven
  fix is M17 (`vulnadvisor fix`).
- **No new third-party runtime dependency.** SAST is stdlib `ast` + the existing call graph; the
  published core wheel stays at its current runtime-dependency count (a metadata test guards this,
  as in 15.3). Pyright stays the optional type-resolver lever it already is.

---

## 11. Package layout

```
src/vulnadvisor/sast/
  __init__.py
  rules.py        # 16.2 — the rule pack as data (Sink/Source/Sanitizer rules, the CWE table)
  sinks.py        # 16.2 — AST visitor locating + classifying sink calls (intra-procedural)
  taint.py        # 16.3 — demand-driven taint propagation over callgraph/, tier assignment
  model.py        # SAST finding + tier models (additive; pydantic v2, frozen)
  # scoring lives next to SCA scoring in engine/ (CWE table + tier discounts), not here.
```

Shared-layer touch points (all additive):

- `engine/` — CWE→severity table + SAST tier discounts, feeding the existing `compute_score`.
- `model/` — the SAST finding type + a unified finding union for the report.
- `output/json_report.py` — `finding_type`, `schema_version` 1.2, code-finding serialization.
- `output/sarif.py` — CWE taxa + `codeFlows` for code findings.
- `output/gating.py` — `--fail-on` over both types.
- `cli/main.py`, `cli/pipeline.py`, `cli/render.py` — `--sca-only`/`--sast-only`, run both
  analyses, render SAST findings in the 3 cards (16.4).

---

## 12. Test & fixture strategy

Mirrors the SCA discipline (table-driven, fixture-backed, soundness-gated):

- **16.2 rule/sink tests** — per rule: positive, negative, and *adversarial* (aliased imports
  `import yaml as y`, `from os import system`, attribute chains, computed callees). Runs over
  `fixtures/` and the repo's own `src/` without crashing; deterministic output.
- **16.3 taint fixture suite (≥12 cases)** — direct flow / cross-function / sanitized / **partially
  sanitized** / dynamic-blocked / **framework-routed (FastAPI + Django)** / not-reachable-from-
  entry-point. **Zero missed flows is release-blocking.** Not-reachable cases come out
  `POSSIBLE-FLOW` or lower, **never** `CONFIRMED-FLOW`. Performance: full SAST pass on the largest
  fixture repo < 10 s (documented).
- **Soundness regression tests** — encode the §4 invariants directly: no input causes a real sink
  to read as `SANITIZED`/dropped; partial sanitization → unsanitized tier; dynamic never
  downgrades; FFI boundary escalates.
- **16.5 benchmark vs Bandit** — findings, confirmed-tier precision, missed-known-vulns (seeded CVE
  patterns), wall time, on the fixture suite + 2–3 real OSS apps; honest table in
  `benchmarks/SAST-REPORT.md`, including where Bandit wins.
- **Global gate every task** — `ruff check` + `ruff format --check`, `mypy --strict src`, `pytest`
  green, `PROGRESS.md` updated, commit + push.

---

## 13. Reviewer decisions (resolved 2026-06-13)

1. **`POSSIBLE-FLOW` discount factor** (§5) — **fix it in 16.4 with a table-driven test.** No
   number is hard-coded here; 16.4 pins the constant next to the SCA discounts with a test that
   asserts the resulting cross-type ordering. Until then `POSSIBLE-FLOW` is "discounted but never
   zeroed".
2. **CWE-798 home** — **keep in v1.** Modeled as a literal-pattern finding outside the taint graph
   (§3/§4): `source == sink`, empty path, reported as `CONFIRMED-FLOW` ("the secret literal is
   present in source").
3. **Source set for stdin/argv/env** — **untrusted by default, confirmed.** They are modeled as
   sources in v1 (§6) per the soundness rule (over-report, then let the tier speak); trusted-operator
   tuning, if ever needed, is a later opt-out, not a v1 default.
