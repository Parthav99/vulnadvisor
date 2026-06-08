# PROGRESS

Running log of state + decisions. Newest entry on top. Updated after every task.

---

## Task 0.2 — CLI skeleton + CI  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- Added `typer==0.26.7` as the first runtime dependency (pinned; CLI framework from the stack).
- Built `src/vulnadvisor/cli/main.py`: a Typer app with a `scan PATH [--public/--internal]
  [--fail-on ...]` stub command (echoes the resolved invocation, exits 0) and a top-level
  `--version` callback. Registered the `vulnadvisor` console script via `[project.scripts]`.
- Added `.github/workflows/ci.yml`: runs `uv sync --frozen` + ruff check + ruff format --check +
  `mypy --strict src` + pytest on push and pull_request (mirrors the local gate exactly), using
  `astral-sh/setup-uv` pinned to 0.11.19 and Python 3.12.
- Added `tests/test_cli.py` (Typer `CliRunner`): `--version` exits 0, scan stub exits 0 for
  `--public`/`--internal`, and a missing path errors non-zero.

**Why these choices**
- Used Typer's `Annotated[...]` parameter style so the `typer.Option/Argument` calls live in
  annotation metadata, not default values — this keeps Ruff's `B008` (function-call-in-default)
  clean without a per-file ignore.
- Console-script entry points at `vulnadvisor.cli.main:app` (Typer instances are callable).
- Switched the scan stub's plain `typer.echo` line from an em-dash to an ASCII hyphen: the
  Windows console codepage mangled the em-dash. Help text (rendered via Rich) keeps Unicode.

**Validation evidence**
- `uv run vulnadvisor scan .` → stub printed, `exit=0`.
- `uv run vulnadvisor --version` → `vulnadvisor 0.0.0`, `exit=0`.
- CI YAML parses and contains all four local checks (verified with an ephemeral PyYAML parse).
- ruff check / ruff format --check clean; `mypy --strict src` clean (13 files); pytest 5 passed.

**Open questions**
- None blocking. First CI run will execute once this is pushed; will confirm green on GitHub.

---

## Task 0.1 — Repo + toolchain  (2026-06-08)

**Status:** complete, Validation Gate passing.

**What changed**
- Added `pyproject.toml` (uv-managed) configuring Ruff (lint + format), `mypy --strict`, and
  pytest. Dev tooling pinned: `ruff==0.14.4`, `mypy==1.18.2`, `pytest==8.4.2`.
- Created the full empty package tree under `src/vulnadvisor/` per `instructions.md`: `cli`,
  `deps`, `advisories`, `symbols`, `callgraph`, `reachability`, `engine`, `output`, `llm`,
  `model`, `store` — each with an `__init__.py` carrying a one-line docstring.
- Added `tests/` (mirrors `src/`) with one smoke test, plus `fixtures/` and `benchmarks/`
  placeholders.
- Added `README.md` (one-liner + run instructions), this `PROGRESS.md`, and `.gitignore`.

**Why these choices**
- `requires-python = ">=3.12"` per the stack rule (we analyze 3.12+ Python; local env is 3.13).
- `hatchling` build backend with an explicit `src/` layout so the package is importable and
  installable without extra config.
- Ruff rule set `E,F,I,UP,B,SIM,D` with the Google docstring convention enforces module
  docstrings from day one; `tests/*` is exempt from docstring (`D`) rules.
- Added one trivial smoke test so `pytest` exits 0 (an empty suite exits 5 = "no tests
  collected", which would read as a failed gate).

**Open questions**
- GitHub remote is not yet configured (`origin`). Push discipline can't run until the remote
  exists — flagging for setup before/at Task 0.2.
