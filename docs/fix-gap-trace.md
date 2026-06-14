# Fix-gap root-cause trace (Task 19.1)

> **Diagnosis only — no production code changed in this task.** This document pins the two
> compounding failures behind the live pygoat outcome ("every finding came back *no safe fix*, and
> even a fix would never have shown in the dashboard"): the **yield** gap and the **visibility** gap.
> Each is reproduced on a seeded fixture and locked in by a failing test that turns green in the
> repair task (19.3 for yield, 19.2 for visibility).

Reproduction scripts and the test fixtures below were run on `main` at the start of M19.

---

## 1. Yield gap — "no safe fix for everything"

### Symptom
On the pygoat PR, all 22 alarming findings returned `no safe fix`. None were unfixable in principle —
several are textbook one-line rewrites (`yaml.load` → `yaml.safe_load`, `shell=True` → arg list, an
`md5` → `sha256`).

### Reproduction (seeded fixture)
Fixture — a single alarming, trivially-fixable CWE-502 sink:

```python
# app.py
import yaml


def load_config(data):
    return yaml.load(data)
```

Scanning it (`scan_project(..., run_sca=False, run_sast=True)`) yields exactly one finding:

| finding id (`<file>:<line>:<kind>`)   | cwe     | kind                   | tier            | alarming |
|---------------------------------------|---------|------------------------|-----------------|----------|
| `app.py:5:unsafe-deserialization`     | CWE-502 | unsafe-deserialization | `possible-flow` | yes      |

Driving the fix loop (`generate_fix`) over that finding, per the two real CI conditions:

| model client condition          | outcome       | recorded attempt note                        |
|---------------------------------|---------------|----------------------------------------------|
| no key set (`LLMError` raised)  | `no-safe-fix` | `model call failed: no model key configured` |
| key set, empty/garbage response | `no-safe-fix` | `response was not a valid fix JSON object`    |

### Root cause (attributed)
`generate_fix` (`src/vulnadvisor/llm/fix.py`) and `generate_suggestions`
(`src/vulnadvisor/llm/suggest.py`) are **model-only**: every candidate patch comes from
`client.complete(...)`. There is **no deterministic quick-fix path** — so:

1. **No model key / spent cap** → `LLMError` on every attempt → `no-safe-fix`. On the pygoat run the
   platform-proxy fallback (`PlatformSuggestClient`) latched "unavailable" after the first call, so
   *every* finding declined for the same reason: no usable model behind the proxy.
2. **Model present but weak** (e.g. the free `:free` fallback model) → unparseable/empty JSON or a
   patch the validator rejects (`apply` / `ruff` / `mypy` / `tests` / `rescan` fail) → `no-safe-fix`.
3. **Even an obvious rewrite declines** because nothing tries it before the model: `yaml.load` →
   `yaml.safe_load` is unambiguous and safe, but with no template and a declining model the loop has
   nothing to fall back on.

The decline reasons are *correct* (soundness holds — we never emit an unvalidated patch), but the
**yield is the bug**: a finding with an obvious safe fix must not return `no safe fix`.

### Repaired by
**Task 19.3** — a high-confidence deterministic quick-fix set (`yaml.load`→`safe_load`,
`shell=True`→arg list, `eval`→`ast.literal_eval`, `md5`/`sha1`→`sha256`, `random`→`secrets`,
`verify=False`→verified) that runs **before** the model and is accepted only after the same full
17.1 validation loop. Offline, no API key, the `yaml.load` case must then produce a validated fix.

### Red test
`tests/test_fix_gap.py::test_yaml_load_yields_a_validated_fix_offline` — runs `generate_suggestions`
on the fixture above with a **declining** model client and the real `build_validator`. Today it gets
zero fixes (RED); 19.3's deterministic quick-fix makes it produce one validated patch offline.

---

## 2. Visibility gap — "a fix would never reach the card"

Even if a fix *were* produced, the dashboard finding card (Task 17.5) would still show nothing,
because the validated fixes never reach the platform's `Scan.suggestions`.

### The pipeline, hop by hop

```
fix --suggest-json / suggest      →  scan --upload          →  ingest            →  read join         →  CodeFindingCard
(produces ValidatedFix[])            (uploads the report)      (Scan.suggestions)   (_proposed_fixes)    (joins by finding_id)
```

| hop | code | payload / behavior today | status |
|-----|------|--------------------------|--------|
| produce | `llm/suggest.py: generate_suggestions` | `SuggestionReport{ fixes: ValidatedFix[] }`, each keyed `finding_id = "<file>:<line>:<kind>"` | OK (when yield > 0) |
| upload (suggest) | generated workflow `vulnadvisor suggest` | posts in-line comments to GitHub via `GITHUB_TOKEN`; **never uploads the fixes to the platform** | **BROKEN** |
| upload (scan) | generated workflow `vulnadvisor scan . --upload` | uploads the report **without** `--suggestions` | **BROKEN** |
| ingest | `routers/ingest.py: _store_scan` → `parse_suggestions` | `Scan.suggestions = parse_suggestions(None) = []` (no suggestions in the body) | empty in, empty out |
| read | `routers/read.py: _proposed_fixes(scan)` | `scan.suggestions or []` → `[]` → `FindingsResponse.suggestions = []` | returns none |
| render | `CodeFindingCard` (`lib/fix.ts: codeFindingId`) | joins `finding.suggestions` by `${file}:${line}:${kind}` → no match → **no panel** | nothing shown |

### Where it breaks (the rendered workflow proves it)
`render_workflow` (`platform/.../setup_pr.py`) emits two steps:

```yaml
      - name: Scan and upload the report
        run: vulnadvisor scan . --upload          # <-- no --suggestions
      - name: Suggest validated fixes on the pull request
        if: github.event_name == 'pull_request'
        run: vulnadvisor suggest                  # <-- posts to GitHub only; no platform upload
```

Programmatic confirmation on the rendered workflow:

```
scan upload step has --suggestions : False
suggest step uploads to platform    : False
suggest only posts to GitHub        : True
```

So `Scan.suggestions` is **always empty** for CI scans, and 17.5's read join has nothing to return —
independent of whether any fix was produced.

### Two sub-problems for 19.2 to close
1. **No platform upload of suggestions.** The CLI plumbing already exists
   (`scan --upload --suggestions <file>` → `body["suggestions"]` → ingest stores it), but the
   generated workflow never uses it, and `suggest` only posts to GitHub. 19.2 must make the workflow
   produce a suggestions document and upload it (one single source of truth: either
   `scan --upload --suggestions` or a unified `suggest --upload`).
2. **SCA findings get no fix at all.** `generate_suggestions` iterates only `ScoredSastFinding`
   (SAST). A validated fix for a dependency (SCA) finding is never produced, so it can never persist
   or join. 19.2 must persist + join SCA fixes too.

### Join-key parity (verified — *not* the break)
The join key is consistent across the stack, so once a suggestion is uploaded it will match:

- CLI: `llm/fix.py: sast_finding_id` → `f"{file}:{line}:{kind}"` → e.g. `app.py:5:unsafe-deserialization`
- Stored: `reports.py: parse_suggestions` keeps `finding_id` verbatim
- Read: `read.py: _proposed_fixes` returns `ProposedFix.finding_id` verbatim
- Dashboard: `lib/fix.ts: codeFindingId` → `` `${finding.location.file}:${finding.location.line}:${finding.rule.kind}` ``

All four produce `<file>:<line>:<kind>`. The visibility failure is purely the missing upload, not a
key mismatch.

### Repaired by
**Task 19.2** — wire the generated workflow + CLI so a validated fix (SAST **and** SCA) is uploaded
to `Scan.suggestions` and joined by the read API.

### Red test
`platform/tests/test_fix_gap.py::test_setup_workflow_uploads_validated_suggestions` — asserts the
generated workflow uploads its validated fixes to the platform (so `Scan.suggestions` is populated
and the read join returns them). Today the workflow uploads no suggestions (RED); 19.2 makes it pass.

---

## 3. Status of the two red tests

Both are encoded with `@pytest.mark.xfail(strict=True)` so the gate stays green while they genuinely
run and fail today (reported as `xfailed`). When 19.3 / 19.2 repair the behavior they will `XPASS`,
which `strict=True` turns into a gate failure — forcing that task to remove the marker and leave a
plain, green regression test. **Action for 19.2 / 19.3:** delete the `xfail` marker as the behavior
is fixed.

| test | gap | turns green in |
|------|-----|----------------|
| `tests/test_fix_gap.py::test_yaml_load_yields_a_validated_fix_offline` | yield | 19.3 |
| `platform/tests/test_fix_gap.py::test_setup_workflow_uploads_validated_suggestions` | visibility | 19.2 |
