# Changelog

All notable changes to VulnAdvisor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to semantic versioning.

## [1.0.0] - 2026-06-09

The first stable release: reachability-first triage for Python with the signature three-card
experience.

### Added
- **Reachability engine** with four confidence tiers (`IMPORTED-AND-CALLED`, `IMPORTED`,
  `DYNAMIC-UNKNOWN`, `NOT-IMPORTED`) — soundness-first, never a binary "reachable / not".
- **Demand-driven call graph** that finds a concrete path from your code to the vulnerable symbol.
- **Type-informed resolution** of reflective `getattr` dispatch via optional Pyright (degrades
  cleanly when Pyright is absent).
- **Framework plugins** for FastAPI (route/websocket decorators) and Django (URLconf views and
  `@receiver` signals), so framework-routed vulnerabilities are rooted at the real entry point.
- **Deterministic priority scoring** from CVSS + EPSS + CISA KEV, with KEV-dominates and
  unknown-CVSS soundness guards.
- **Plain-English "attack story"** (Card A) via your own `ANTHROPIC_API_KEY`, with a deterministic
  template fallback. The LLM never changes the priority.
- **Output formats**: three-card terminal view, stable JSON (`schema_version` 1.0), and SARIF 2.1.0
  for the GitHub Security tab. `--fail-on <band|score>` for CI gating.
- **Advisory → vulnerable-symbol dataset** with a `backfill` command (the data moat).
- **Incremental analysis cache** keyed on file-content hashes for fast CI re-runs.
- **Benchmark harness** (`python -m benchmarks`) proving the noise-reduction claim with zero missed
  reachable criticals.
- Privacy by design: local analysis, no telemetry, network only to public advisory APIs and your
  own LLM key.

[1.0.0]: https://github.com/Parthav99/vulnadvisor_v2/releases/tag/v1.0
