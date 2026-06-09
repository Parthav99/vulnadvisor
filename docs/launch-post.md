# Stop scanning, start triaging: VulnAdvisor 1.0

Your dependency scanner just told you about 40 vulnerabilities. How many can an attacker actually
reach through *your* code? With most tools, you have no idea — so you either chase all 40 or, more
honestly, ignore the list. Both are bad.

**VulnAdvisor** is an open-source CLI that answers the question scanners skip: *is this
vulnerability reachable from my code?* It ranks what's left by real-world exploit likelihood (EPSS +
CISA KEV) and explains each one in plain English. It runs locally, sends your source code nowhere,
and has no telemetry.

## The result, in one number

We ran VulnAdvisor against a naive baseline (`pip-audit`, which flags every advisory on every
declared dependency) over a reproducible corpus exercised through the real engine:

> **54% less noise — 39 findings cut to 18 — with zero missed reachable criticals.**

That last clause is the whole game. Noise reduction is easy if you're willing to hide real bugs.
VulnAdvisor's hard rule is the opposite: **a reachable vulnerability is never reported as safe.**
The benchmark enforces it — any reachable finding that gets deprioritized is a build failure. Full
numbers: [`benchmarks/REPORT.md`](../benchmarks/REPORT.md), reproducible with
`python -m benchmarks`.

## How it decides "reachable"

VulnAdvisor never gives a binary verdict. Every finding carries a **confidence tier**:

- **IMPORTED-AND-CALLED** — there's a concrete call path from your code to the vulnerable symbol,
  and we show it to you: `request_handler -> parse_config -> yaml.load`.
- **IMPORTED** — the package is imported; no confirmed call yet.
- **DYNAMIC-UNKNOWN** — reflection, `eval`/`exec`, or an uncertain mapping means we *can't rule out*
  a call. We escalate rather than guess.
- **NOT-IMPORTED** — the package is never imported. The only "confidently safe" tier — and where
  most of the noise goes.

Because soundness beats precision: a false "you're safe" can cause a breach, so anything uncertain
escalates instead of being silently downgraded.

It also handles the cases naive call graphs miss:

- **Reflective dispatch** (`getattr(yaml, name)`) is resolved with optional Pyright type info —
  `name = "safe_load"` is provably *not* the vulnerable `load`, so the false positive disappears;
  with no type info we stay conservative.
- **Framework routing** — a FastAPI route handler or a Django URLconf view is never called from
  your module's top level, but the framework calls it. VulnAdvisor knows that, so a vuln reached
  through a handler is found and rooted at the route.

## Deterministic priority, plain-English explanation

Priority is computed by code — pure, reproducible, no randomness or clock. KEV-listed vulns are
floored to CRITICAL; unknown CVSS falls back to a flagged default instead of zero. The optional LLM
layer (your own `ANTHROPIC_API_KEY`) writes the "attack story" and a one-line rationale — but it
**cannot change the number**. The model explains; the engine decides.

## Try it

```bash
uvx vulnadvisor scan examples/quickstart
```

```bash
# In CI: fail the build on any reachable High+ and upload to the Security tab
vulnadvisor scan . --format sarif --fail-on high > results.sarif
```

Open source, Apache-2.0, local-only. Stop scanning — start triaging.
