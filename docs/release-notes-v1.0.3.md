# VulnAdvisor v1.0.3

The reachability-first vulnerability triage CLI for Python — now installable from PyPI.

VulnAdvisor tells you which of your vulnerable dependencies are *actually reachable from your own
code*, ranked by real-world exploit likelihood (EPSS + CISA KEV) and explained in plain English. It
runs locally, sends your source nowhere, and has no telemetry.

## Install

```bash
pip install vulnadvisor      # or: uvx vulnadvisor scan .
vulnadvisor scan .
```

## What's new in 1.0.3

- **`scan --top N`** — limit output to the N highest-priority findings. It's a pure display limit on
  the already-ranked list: ranking is unchanged, and `--fail-on` still gates over *every* finding, so
  the cap can never weaken your CI exit code.

## Fixed

- The release workflow could not check out the private repository during publishing. The job now has
  `contents: read` (alongside `id-token: write` for PyPI Trusted Publishing) and an explicit checkout
  token. This is the first version published to PyPI.

## The 1.0 engine (recap)

- **Four-tier reachability** (`IMPORTED-AND-CALLED`, `IMPORTED`, `DYNAMIC-UNKNOWN`, `NOT-IMPORTED`) —
  soundness-first, never a binary verdict.
- **Demand-driven call graph** that shows a concrete path from your code to the vulnerable symbol,
  with **type-informed resolution** of reflective `getattr` dispatch via optional Pyright.
- **Framework plugins** for FastAPI and Django so framework-routed vulnerabilities are rooted at the
  real entry point.
- **Deterministic priority scoring** (CVSS + EPSS + CISA KEV); the optional LLM "attack story" only
  explains — it never changes the score.
- **Output**: three-card terminal view, stable JSON, and SARIF 2.1.0 for the GitHub Security tab,
  with `--fail-on <band|score>` for CI gating.

Measured on 13 real-world apps (1,210 OSV advisories): deprioritizes where code is statically
analyzable (paperless 37%, BookWyrm 10%, Mathesar 14%) and stays conservative wherever dynamic
dispatch could hide a call — with **zero missed reachable findings**.

Apache-2.0. Full history in [CHANGELOG.md](../CHANGELOG.md).
