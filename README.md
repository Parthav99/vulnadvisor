# VulnAdvisor

> **Stop scanning, start triaging.**

VulnAdvisor is an open-source CLI that tells you which of your Python dependency
vulnerabilities are *actually reachable from your own code* — ranked by real-world exploit
likelihood (EPSS + CISA KEV) and explained in plain English.

It runs **locally**. Your source code never leaves your machine, and there is **no telemetry**.
Network calls are only to public vulnerability/risk APIs (OSV, GitHub Advisory, EPSS, CISA KEV)
and, optionally, your own LLM key.

## Status

Early scaffolding (milestone **M0**). Not yet usable — see [`task.md`](task.md) for the build
plan and [`PROGRESS.md`](PROGRESS.md) for current state.

## Requirements

- Python **3.12+**
- [uv](https://docs.astral.sh/uv/) for environment and dependency management

## Develop

```bash
uv sync                 # create the environment and install dev tooling
uv run ruff check       # lint
uv run ruff format --check
uv run mypy --strict src
uv run pytest
```

## License

Apache-2.0 (planned for the open-core engine).
