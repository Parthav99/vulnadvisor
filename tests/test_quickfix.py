"""Task 19.3 — deterministic quick-fixes: pure candidate generation + end-to-end validation.

Two layers of coverage:

* **Pure** (`quick_fix_candidates`) — no subprocess: each builder produces the expected AST-targeted
  diff for its CWE, and *declines* (returns ``[]``) for the call shapes it cannot rewrite safely, so
  the loop falls through to the model. This is where the "never bogus" contract is pinned cheaply.
* **End-to-end** — the real validated-fix sweep over a seeded fixture with a model client that must
  never be called: the quick-fix runs first, is proven by the actual 17.1 validator (git apply,
  ruff, re-scan), and a validated, ``deterministic``-provenance fix comes back **offline**.

The end-to-end cases need ``git`` (and use ``ruff`` if present); they mirror ``test_fix_gap.py``.
"""

from pathlib import Path

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.llm.client import LLMError
from vulnadvisor.llm.fix_validate import build_validator
from vulnadvisor.llm.quickfix import quick_fix_candidates
from vulnadvisor.llm.suggest import (
    deterministic_fixable,
    fix_yield,
    generate_suggestions,
)
from vulnadvisor.model.fix import FixProvenance
from vulnadvisor.sast.model import SastFinding, SastTier, ScoredSastFinding
from vulnadvisor.sast.sinks import find_sinks_in_source

# --- fixtures: one alarming sink each, with an unambiguous safe rewrite --------------------------

_YAML = "import yaml\n\n\ndef load_config(data):\n    return yaml.load(data)\n"
_YAML_ALIASED = "import yaml as y\n\n\ndef load_config(data):\n    return y.load(data)\n"
_YAML_LOADER = (
    "import yaml\n\n\ndef load_config(data):\n    return yaml.load(data, Loader=yaml.Loader)\n"
)
_SUBPROCESS = (
    "import subprocess\n\n\ndef run_cmd(cmd):\n    return subprocess.run(cmd, shell=True)\n"
)
_EVAL = "def calc(expr):\n    return eval(expr)\n"

# --- decline fixtures: an alarming finding, but no safe deterministic rewrite --------------------

_PICKLE = (
    "import pickle\n\n\ndef load(data):\n    return pickle.loads(data)\n"  # CWE-502, no safe form
)
_SUBPROCESS_VAR = (
    "import subprocess\n\n\ndef run_cmd(cmd, flag):\n    return subprocess.run(cmd, shell=flag)\n"
)
_EVAL_GLOBALS = "def calc(expr, ns):\n    return eval(expr, ns)\n"
_OS_SYSTEM = (
    "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n"  # CWE-78, no shell= to flip
)


def _finding(source: str, rel: str = "app.py") -> SastFinding:
    """The first alarming finding the engine reports for ``source`` (intra-procedural classify)."""
    hits = [h for h in find_sinks_in_source(source, rel) if h.tier is not SastTier.SANITIZED]
    assert hits, "fixture should produce an alarming sink"
    return SastFinding.from_sink_hit(hits[0])


def _candidate_diff(source: str) -> str:
    finding = _finding(source)
    candidates = quick_fix_candidates(finding, lambda _rel: source)
    assert len(candidates) == 1, "expected exactly one deterministic candidate"
    candidate = candidates[0]
    assert candidate.provenance is FixProvenance.DETERMINISTIC
    return candidate.diff


# --- pure: the rewrite the builder proposes -----------------------------------------------------


def test_yaml_candidate_rewrites_to_safe_load() -> None:
    diff = _candidate_diff(_YAML)
    assert "-    return yaml.load(data)" in diff
    assert "+    return yaml.safe_load(data)" in diff
    assert diff.startswith("--- a/app.py\n+++ b/app.py\n")


def test_yaml_candidate_preserves_an_import_alias() -> None:
    # Only the attribute is rewritten; the `y` alias from `import yaml as y` is untouched.
    diff = _candidate_diff(_YAML_ALIASED)
    assert "+    return y.safe_load(data)" in diff


def test_yaml_candidate_drops_the_loader_argument() -> None:
    # safe_load takes only the stream, so the Loader= argument is dropped (the safe form).
    diff = _candidate_diff(_YAML_LOADER)
    assert "+    return yaml.safe_load(data)" in diff
    added = [ln for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    assert not any("Loader" in ln for ln in added)  # gone from every added line


def test_subprocess_candidate_uses_shlex_split_and_shell_false() -> None:
    diff = _candidate_diff(_SUBPROCESS)
    assert "+import shlex" in diff
    assert "shlex.split(cmd)" in diff
    assert "shell=False" in diff


def test_eval_candidate_uses_ast_literal_eval() -> None:
    diff = _candidate_diff(_EVAL)
    assert "+import ast" in diff
    assert "ast.literal_eval(expr)" in diff


# --- pure: the builder declines (never a bogus rewrite) -----------------------------------------


def test_pickle_declines_no_safe_drop_in() -> None:
    # Same CWE-502/kind as yaml, but pickle has no safe_load — must not be mangled.
    assert quick_fix_candidates(_finding(_PICKLE), lambda _r: _PICKLE) == []


def test_subprocess_non_literal_shell_declines() -> None:
    # shell=<variable>: we cannot prove it is True, so we never flip it.
    assert quick_fix_candidates(_finding(_SUBPROCESS_VAR), lambda _r: _SUBPROCESS_VAR) == []


def test_eval_with_globals_declines() -> None:
    # eval(expr, ns): literal_eval takes no globals/locals, so this shape declines to the model.
    assert quick_fix_candidates(_finding(_EVAL_GLOBALS), lambda _r: _EVAL_GLOBALS) == []


def test_os_system_declines_no_shell_keyword() -> None:
    # CWE-78 but not a subprocess shell call — the subprocess builder declines cleanly.
    assert quick_fix_candidates(_finding(_OS_SYSTEM), lambda _r: _OS_SYSTEM) == []


def test_unreadable_source_declines() -> None:
    assert quick_fix_candidates(_finding(_YAML), lambda _r: None) == []


def test_non_quickfix_cwe_declines() -> None:
    # A SQL-injection finding (CWE-89) has no quick-fix entry at all.
    sql = (
        "def get(db, name):\n"
        "    cur = db.cursor()\n"
        "    return cur.execute('select * from t where n = ' + name)\n"
    )
    finding = _finding(sql)
    assert finding.cwe == "CWE-89"
    assert quick_fix_candidates(finding, lambda _r: sql) == []


# --- end-to-end: a validated, offline, deterministic fix ----------------------------------------


class _NeverCalledClient:
    """A model client whose use is a hard failure — proves the quick-fix needs no model call."""

    model = "must-not-be-called"

    def complete(self, *, system: str, user: str) -> str:
        raise AssertionError("a deterministic quick-fix must not call the model")


class _DecliningClient:
    """A model client that always errors — "no model key" once the quick-fix has declined."""

    model = "scripted"

    def complete(self, *, system: str, user: str) -> str:
        raise LLMError("no model key configured")


class _NullMatcher:
    def match(self, dependencies: object) -> object:  # pragma: no cover - SAST-only scan
        raise AssertionError("SAST-only scan must not run SCA matching")


def _sweep_offline(
    proj: Path, client: object | None = None
) -> tuple[list[ScoredSastFinding], object]:
    matcher: AdvisoryMatcher = _NullMatcher()  # type: ignore[assignment]
    findings = scan_project(proj, matcher, run_sca=False, run_sast=True).sast_findings

    def source_for(rel: str) -> str | None:
        try:
            return (proj / rel).read_text(encoding="utf-8")
        except OSError:
            return None

    def validator_for(target: ScoredSastFinding) -> object:
        return build_validator(project_root=proj, target=target, baseline=findings)

    report = generate_suggestions(
        findings=findings,
        client=client or _NeverCalledClient(),  # default: never called (quick-fix validates first)
        validator_for=validator_for,  # type: ignore[arg-type]
        source_for=source_for,  # type: ignore[arg-type]
        tool_version="19.3-test",
        max_attempts=1,
    )
    return findings, report


def _write(tmp_path: Path, name: str, source: str) -> Path:
    proj = tmp_path / name
    proj.mkdir()
    (proj / "app.py").write_text(source, encoding="utf-8")
    return proj


def test_yaml_load_validated_offline(tmp_path: Path) -> None:
    _findings, report = _sweep_offline(_write(tmp_path, "yaml_proj", _YAML))
    assert any(fix.cwe == "CWE-502" for fix in report.fixes)  # type: ignore[attr-defined]
    fix = report.fixes[0]  # type: ignore[attr-defined]
    assert fix.provenance is FixProvenance.DETERMINISTIC
    assert "yaml.safe_load" in fix.diff


def test_subprocess_shell_validated_offline(tmp_path: Path) -> None:
    _findings, report = _sweep_offline(_write(tmp_path, "subprocess_proj", _SUBPROCESS))
    fixes = report.fixes  # type: ignore[attr-defined]
    assert any(fix.cwe == "CWE-78" and "shlex.split" in fix.diff for fix in fixes)


def test_eval_validated_offline(tmp_path: Path) -> None:
    _findings, report = _sweep_offline(_write(tmp_path, "eval_proj", _EVAL))
    fixes = report.fixes  # type: ignore[attr-defined]
    assert any(fix.cwe == "CWE-94" and "ast.literal_eval" in fix.diff for fix in fixes)


def test_pickle_declines_then_no_offline_fix(tmp_path: Path) -> None:
    # No safe deterministic rewrite; the quick-fix declines and the (key-less) model yields nothing.
    _findings, report = _sweep_offline(_write(tmp_path, "pickle_proj", _PICKLE), _DecliningClient())
    assert report.fixes == ()  # type: ignore[attr-defined]


def test_fix_yield_is_total_for_the_quickfix_cwes(tmp_path: Path) -> None:
    # A project with all three quick-fix CWEs: every fixable finding comes back validated, offline.
    proj = tmp_path / "mixed"
    proj.mkdir()
    (proj / "a.py").write_text(_YAML, encoding="utf-8")
    (proj / "b.py").write_text(_SUBPROCESS, encoding="utf-8")
    (proj / "c.py").write_text(_EVAL, encoding="utf-8")
    _findings, report = _sweep_offline(proj)

    fixable = sum(1 for f in _findings if deterministic_fixable(f))
    validated = len(report.fixes)  # type: ignore[attr-defined]
    assert fixable == 3
    assert fix_yield(validated=validated, fixable=fixable) == 1.0


def test_fix_yield_metric_is_bounded() -> None:
    assert fix_yield(validated=0, fixable=0) == 0.0  # nothing to fix is not a regression
    assert fix_yield(validated=1, fixable=2) == 0.5
    assert fix_yield(validated=5, fixable=2) == 1.0  # clamped
