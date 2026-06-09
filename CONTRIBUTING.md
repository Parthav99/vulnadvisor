# Contributing to VulnAdvisor

Thanks for helping make dependency triage less noisy. This guide gets you productive fast.

## Principles (please read before a big change)

VulnAdvisor wins on three things — protect them in every change:

1. **Python depth** — one ecosystem, understood better than any generalist tool.
2. **Developer trust** — open source, runs locally, **no telemetry**. Network calls go only to
   public vuln/risk APIs and the user's own LLM key.
3. **Soundness over precision** — a false "you're safe" can cause a breach. When uncertain,
   escalate (`DYNAMIC-UNKNOWN`); never silently downgrade. A missed *reachable* finding is
   release-blocking.

Two more rules that keep the engine trustworthy:

- **Deterministic priority.** Scoring is pure and reproducible (no randomness, clock, or I/O). The
  LLM only *explains*; it must never change the number.
- **Defensive parsing.** Validate all external data (OSV/EPSS JSON, fix-commit diffs, LLM output);
  fall back to safe defaults; never crash on malformed input.

## Setup

```bash
uv sync          # Python 3.12+; creates the env and installs dev tooling
```

## The quality gate (all must pass)

```bash
uv run ruff check
uv run ruff format --check
uv run mypy --strict src
uv run pytest
```

`main` stays green. New behavior needs tests — table-driven where it makes sense, and a fixture
under `fixtures/` for anything reachability-related (with **zero missed reachable findings**).

## Conventions

- Full type hints; `mypy --strict` clean. Docstrings on public symbols (Google style).
- No hardcoded secrets — `os.environ` only. No bare `except`; raise/return typed errors with
  context. Core analysis stays pure (no hidden I/O in parsing/graph/scoring).
- Don't add a dependency without discussion; pin versions.
- Keep terminal output ASCII (it has to render on legacy Windows consoles and in snapshot tests).

## Pull requests

1. Branch off `main`.
2. Make the change with tests; run the gate above.
3. Open a PR describing *what* and *why*. Note any soundness implications explicitly.

By contributing you agree your contributions are licensed under [Apache-2.0](LICENSE).
