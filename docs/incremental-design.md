# Incremental & parallel scanning — design (M22)

> Status: **Task 22.1 approved-by-build** (this doc + the `store/` facts cache). Tasks 22.2
> (incremental scan) and 22.3 (parallelism) build on the schema fixed here.

VulnAdvisor must be fast enough to run on every save (pre-commit) and on large monorepos, **without
ever letting a stale cache hide a finding**. The strategy: cache each file's analysis facts by a
content-and-rules hash in the existing SQLite store, re-analyze only changed files and their
dependents, and parallelize per-file work — with a release-blocking equivalence guarantee that an
incremental scan returns *exactly* what a cold scan returns. No new runtime dependency (stdlib
`hashlib`, `sqlite3`, and later `concurrent.futures`).

This document is the contract for the whole milestone. **Soundness is the constraint; speed is the
objective** — never the reverse.

---

## 1. The cacheable unit: per-file analysis facts

The expensive part of a scan is parsing every `.py` file and walking its AST. That work is a pure
function of two inputs:

1. the file's **content** (its bytes), and
2. the **rule pack** the analysis runs under (which sinks/sanitizers/secret patterns exist).

If neither changed, the facts are unchanged. We cache, per file, a single `FileFacts` record
(`store/file_facts.py`) bundling the three fact kinds a scan needs from a file:

| Fact | Source today | Depends on rules? |
| --- | --- | --- |
| **imports / definitions / dynamic sites** (`FileAnalysis`) | `callgraph/import_graph._analyze_source` | no |
| **sinks** (`tuple[SinkHit, ...]`) | `sast/sinks.find_sinks_in_source` | **yes** |
| **per-function taint summaries** (`tuple[FunctionTaintSummary, ...]`) | `sast/taint.py` (demand-driven) | **yes** |

The pure, single-file facts (imports/defs + sinks) are built by `sast/facts.build_file_facts(rel,
text)` in Task 22.1. **Taint summaries** are a demand-driven, *cross-module* fact — a function's
summary can depend on callees in other files — so they are not a pure per-file product. They are
filled by the taint engine during the dependent-closure walk in **Task 22.2**, written into the same
`FileFacts` record under the same key. A summary is therefore never observed inconsistent with the
file and rules it was computed under: any change to either changes the key.

> **Why one record, not three caches.** A scan wants *all* of a file's facts together; a single
> keyed record means one lookup per file and one atomic invalidation. The pre-existing
> `AnalysisCache` (imports/defs only, no rule-pack component) remains for the import graph's own use
> and is a strict subset of `FileFacts`; 22.2 may migrate the import graph onto the unified record,
> but that is not required for correctness.

---

## 2. The cache key (the soundness core)

```
key = analyzer_version  ␀  rule_pack_hash  ␀  rel  ␀  sha256(content)
```

(`␀` = NUL, an unambiguous separator.) Three orthogonal invalidation signals, each busting exactly
the right scope:

- **`analyzer_version`** (`_FACTS_VERSION` in `store/file_facts.py`) — a hand-bumped integer. Bumped
  whenever the *shape or meaning* of the cached facts changes (a new `FileFacts`/`SinkHit` field, a
  change to how summaries are computed). Busts **every** entry. This is the catch-all for "the code
  that produces facts changed in a way the hash inputs don't capture."
- **`rule_pack_hash`** (`sast.rules.rule_pack_hash()`) — SHA-256 over the canonicalized rule pack
  (every `SinkRule`, its sanitizers/guards/safe-args, plus the secret patterns and constants; sets
  sorted, enums reduced to values, rule order preserved). Any rule edit changes this digest and so
  busts **every** entry — because sinks and summaries are computed under the rules, a rule change
  could surface a finding the old facts don't contain. Over-invalidation is deliberate and sound.
- **`sha256(content)`** — invalidates **exactly** the edited file. `rel` is also in the key so two
  identical-content files (e.g. empty `__init__.py`) don't share a record (a `FileFacts` embeds its
  own `rel`).

**Correctness obligation (release-blocking):** *a stale cache entry must never hide a current
finding.* Equivalently — for any (content, rule pack, analyzer) under which a finding exists, the
key computed for a lookup must differ from any key whose stored facts lack that finding. The three
components above discharge this: content covers the file, `rule_pack_hash` covers the rules, and
`analyzer_version` covers everything else. Invalidation is **never time-based** — there is no TTL on
analysis facts, because "the file is old" is not a reason its facts are wrong, and "the file is
recent" is not a reason they're right.

### Rule-pack hash determinism

`rule_pack_hash()` must return byte-identical output across processes and runs for identical rules.
The canonicalizer (`sast.rules._canonical_rule_pack`) therefore **sorts every `frozenset`/`set`**
(whose iteration order is not stable across interpreters) and reduces enums to their string values,
while **preserving `RULES` tuple order** (a reordering is a real semantic change and *should* bust
the cache). The digest is over a `json.dumps(..., sort_keys=True)` of that structure.

---

## 3. Defensive behavior (the cache never breaks a scan)

The cache is a pure optimization layer. Every failure mode degrades to a recompute, never a crash
and never a silent gap:

- **Missing row** → miss → analyze the file.
- **Corrupt / truncated / old-schema row** → `FileFacts.model_validate_json` raises
  `ValidationError`, caught → counted as a miss → analyze the file (and overwrite the bad row on
  `set`).
- **Unreadable cache file / SQLite error on open** → the caller passes no cache (or a fresh one);
  the scan runs uncached. (22.2 wires open-failure handling at the call site.)

`FileFactsCache` exposes `hits` / `misses` counters so tests can *prove* an unchanged file under
unchanged rules was served from cache (a hit) and that any of the invalidation signals produces a
miss.

---

## 4. Storage

A SQLite table `file_facts(key TEXT PRIMARY KEY, value TEXT NOT NULL)` in a `file_facts.sqlite`
database, sibling to the existing `analysis.sqlite` (same directory resolution, honoring
`VULNADVISOR_CACHE`; the cache stays on the user's machine — no telemetry). `value` is the
`FileFacts` pydantic JSON. A separate database file lets the richer facts schema version
independently of the import-only `AnalysisCache`. `:memory:` is supported for tests and ephemeral
runs.

---

## 5. Roadmap (what builds on this)

- **Task 22.2 — incremental scan.** `scan --incremental` / `--since <git-ref>`: compute the changed
  set (content hash vs. cache, or `git diff`), recompute their facts, then recompute the **dependent
  closure** over the import/call graph (a changed function summary re-triggers its callers), and
  merge cached + recomputed into a result **identical** to a cold scan. The release gate is a
  property test: *incremental result == cold-scan result* over the whole fixture suite. This is also
  where taint summaries are populated into `FileFacts`.
- **Task 22.3 — parallelism + perf benchmark.** Populate the cache with a `ProcessPoolExecutor` and
  a **deterministic merge** (output independent of worker count), then publish
  `benchmarks/PERF-REPORT.md` (cold vs. warm vs. incremental wall times, pyscan and Semgrep timed
  side by side).

## 6. Non-goals (this milestone)

- No distributed/shared cache — local SQLite only (privacy-first; no server).
- No partial-file caching — the file is the unit; a one-line edit re-analyzes the whole file (then
  the dependent closure). Sub-file granularity is unjustified complexity at our file sizes.
- No cache eviction policy yet — entries are overwritten by key; bounded growth (LRU/size cap) is a
  later concern, tracked separately from this correctness work.
