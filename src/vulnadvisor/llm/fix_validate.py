# File: src/vulnadvisor/llm/fix_validate.py
"""Prove a candidate patch by running it against a throwaway copy of the project (Task 17.1).

This is the impure half of ``vulnadvisor fix``: it copies the project to a temp directory, applies
the model's diff there (the user's real working tree is never touched until ``--apply``), and runs
a fixed validation sequence — the user's tree is never the proving ground:

1. **apply**   — ``git apply -p1`` the diff cleanly (``git`` does not require a repo).
2. **syntax**  — every changed ``.py`` file still parses (stdlib ``ast``; closes the soundness hole
   where a syntactically-broken file would silently drop out of the re-scan).
3. **ruff**    — ``ruff check`` the changed files (skipped if ``ruff`` is not installed).
4. **mypy**    — only if the project configures mypy (skipped otherwise / if absent).
5. **tests**   — only if the project has a test suite (skipped otherwise / if pytest is absent).
6. **rescan**  — re-run the SAST taint engine on the patched copy and *prove* the finding is gone
   (no longer alarming) **and** that no new alarming finding appeared.

The loop stops at the first failed step; its diagnostic is fed back to the model for the next try.
Everything here is local — no network — so a fix never sends code anywhere but the user's own model.
"""

import ast
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from vulnadvisor.callgraph.frameworks import DEFAULT_PLUGINS, FrameworkPlugin
from vulnadvisor.engine.sast_scoring import score_sast_findings
from vulnadvisor.llm.fix import Validator, is_alarming, sast_signature
from vulnadvisor.model.fix import FixSuggestion, StepStatus, ValidationReport, ValidationStep
from vulnadvisor.sast.model import ScoredSastFinding
from vulnadvisor.sast.taint import analyze_taint

__all__ = ["PatchApplyError", "apply_patch_to_tree", "build_validator", "validate_fix"]

# Directories never worth copying into the validation sandbox (caches, vcs, virtualenvs, builds).
_IGNORE = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "*.egg-info",
)
_SUBPROCESS_TIMEOUT = 300.0


class PatchApplyError(Exception):
    """Raised when ``git apply`` cannot apply a diff to a tree (used by ``--apply``)."""


def _git_apply(
    diff: str, cwd: Path, *, check_only: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run ``git apply`` (optionally ``--check``) with ``diff`` on stdin, in ``cwd``."""
    args = ["git", "apply", "-p1", "--recount", "--whitespace=nowarn"]
    if check_only:
        args.append("--check")
    args.append("-")
    return subprocess.run(
        args,
        input=diff,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        check=False,
    )


def _changed_files(diff: str) -> list[str]:
    """Extract the project-relative paths a diff touches (from its ``+++ b/<path>`` headers)."""
    paths: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target in {"/dev/null", ""}:
                continue
            if target.startswith("b/"):
                target = target[2:]
            # Strip a trailing tab-delimited timestamp if present.
            target = target.split("\t", 1)[0]
            if target and target not in paths:
                paths.append(target)
    return paths


def _which(tool: str) -> bool:
    """Whether an executable is available on PATH."""
    return shutil.which(tool) is not None


def _mypy_configured(root: Path) -> bool:
    """Whether the project configures mypy (so the patch should type-check)."""
    if (root / "mypy.ini").exists() or (root / ".mypy.ini").exists():
        return True
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            if "[tool.mypy]" in pyproject.read_text(encoding="utf-8"):
                return True
        except OSError:
            return False
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        try:
            return "[mypy]" in setup_cfg.read_text(encoding="utf-8")
        except OSError:
            return False
    return False


def _has_tests(root: Path) -> bool:
    """Whether the project has a runnable test suite worth re-running after the patch."""
    if (root / "tests").is_dir() or (root / "test").is_dir():
        return True
    for marker in ("pytest.ini", "tox.ini"):
        if (root / marker).exists():
            return True
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            return "[tool.pytest" in pyproject.read_text(encoding="utf-8")
        except OSError:
            return False
    return False


def _clip(text: str, limit: int = 1500) -> str:
    """Trim noisy tool output to a feedback-sized excerpt."""
    text = text.strip()
    return text if len(text) <= limit else text[:limit].rstrip() + " [...]"


def _alarming_signatures(findings: Sequence[ScoredSastFinding]) -> set[tuple[str, str, str]]:
    """The set of ``(file, cwe, kind)`` signatures of all alarming (non-sanitized) findings."""
    return {sast_signature(f) for f in findings if is_alarming(f)}


def validate_fix(
    suggestion: FixSuggestion,
    *,
    project_root: Path,
    target: ScoredSastFinding,
    baseline: Sequence[ScoredSastFinding],
    plugins: Sequence[FrameworkPlugin] = DEFAULT_PLUGINS,
) -> ValidationReport:
    """Validate one ``suggestion`` against a throwaway copy of ``project_root``.

    ``target`` is the finding being fixed; ``baseline`` is every SAST finding from the pre-fix scan
    (so "no *new* finding appeared" can be checked against what already existed). Returns a
    :class:`ValidationReport`; the loop stops at the first failed step.
    """
    steps: list[ValidationStep] = []
    tmp = Path(tempfile.mkdtemp(prefix="vulnadvisor-fix-"))
    try:
        sandbox = tmp / "proj"
        shutil.copytree(project_root, sandbox, ignore=_IGNORE, symlinks=False)

        applied = _git_apply(suggestion.diff, sandbox)
        if applied.returncode != 0:
            steps.append(
                ValidationStep(
                    name="apply",
                    status=StepStatus.FAILED,
                    detail=_clip(applied.stderr or applied.stdout or "git apply failed"),
                )
            )
            return ValidationReport(ok=False, steps=tuple(steps))
        steps.append(ValidationStep(name="apply", status=StepStatus.PASSED))

        changed = [p for p in _changed_files(suggestion.diff) if p.endswith(".py")]

        syntax = _check_syntax(sandbox, changed)
        steps.append(syntax)
        if syntax.status is StepStatus.FAILED:
            return ValidationReport(ok=False, steps=tuple(steps))

        for step in (
            _ruff_step(sandbox, changed),
            _mypy_step(sandbox, changed, project_root),
            _tests_step(sandbox, project_root),
        ):
            steps.append(step)
            if step.status is StepStatus.FAILED:
                return ValidationReport(ok=False, steps=tuple(steps))

        rescan = _rescan_step(sandbox, target, baseline, plugins)
        steps.append(rescan)
        return ValidationReport(ok=rescan.status is StepStatus.PASSED, steps=tuple(steps))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _check_syntax(sandbox: Path, changed: Sequence[str]) -> ValidationStep:
    """Ensure every changed Python file still parses (always run; no external tool)."""
    for rel in changed:
        path = sandbox / rel
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except OSError as exc:
            return ValidationStep(name="syntax", status=StepStatus.FAILED, detail=f"{rel}: {exc}")
        except SyntaxError as exc:
            return ValidationStep(
                name="syntax",
                status=StepStatus.FAILED,
                detail=f"{rel}: {exc.msg} (line {exc.lineno})",
            )
    return ValidationStep(name="syntax", status=StepStatus.PASSED)


def _ruff_step(sandbox: Path, changed: Sequence[str]) -> ValidationStep:
    """``ruff check`` the changed files; skipped when ruff is not installed."""
    if not changed:
        return ValidationStep(
            name="ruff", status=StepStatus.SKIPPED, detail="no Python files changed"
        )
    if not _which("ruff"):
        return ValidationStep(name="ruff", status=StepStatus.SKIPPED, detail="ruff not installed")
    result = subprocess.run(
        ["ruff", "check", "--no-cache", *changed],
        cwd=sandbox,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        check=False,
    )
    if result.returncode == 0:
        return ValidationStep(name="ruff", status=StepStatus.PASSED)
    return ValidationStep(
        name="ruff", status=StepStatus.FAILED, detail=_clip(result.stdout or result.stderr)
    )


def _mypy_step(sandbox: Path, changed: Sequence[str], project_root: Path) -> ValidationStep:
    """Type-check the changed files when the project configures mypy; skipped otherwise."""
    if not changed:
        return ValidationStep(
            name="mypy", status=StepStatus.SKIPPED, detail="no Python files changed"
        )
    if not _mypy_configured(project_root):
        return ValidationStep(name="mypy", status=StepStatus.SKIPPED, detail="mypy not configured")
    if not _which("mypy"):
        return ValidationStep(name="mypy", status=StepStatus.SKIPPED, detail="mypy not installed")
    result = subprocess.run(
        ["mypy", *changed],
        cwd=sandbox,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        check=False,
    )
    if result.returncode == 0:
        return ValidationStep(name="mypy", status=StepStatus.PASSED)
    return ValidationStep(
        name="mypy", status=StepStatus.FAILED, detail=_clip(result.stdout or result.stderr)
    )


def _tests_step(sandbox: Path, project_root: Path) -> ValidationStep:
    """Run the project's test suite when present; skipped otherwise."""
    if not _has_tests(project_root):
        return ValidationStep(name="tests", status=StepStatus.SKIPPED, detail="no test suite found")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x"],
            cwd=sandbox,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ValidationStep(name="tests", status=StepStatus.FAILED, detail="test run timed out")
    # pytest exit 5 == "no tests collected": treat as nothing to prove, not a failure.
    if result.returncode in (0, 5):
        return ValidationStep(name="tests", status=StepStatus.PASSED)
    return ValidationStep(
        name="tests", status=StepStatus.FAILED, detail=_clip(result.stdout or result.stderr)
    )


def _rescan_step(
    sandbox: Path,
    target: ScoredSastFinding,
    baseline: Sequence[ScoredSastFinding],
    plugins: Sequence[FrameworkPlugin],
) -> ValidationStep:
    """Re-run the SAST engine on the patched copy and prove the fix (the soundness gate).

    Passes only when the target finding is no longer alarming **and** no alarming finding appeared
    that was not already present before the fix (a regression introduced by the patch).
    """
    rescored = score_sast_findings(analyze_taint(sandbox, plugins=plugins))
    after = _alarming_signatures(rescored)
    target_sig = sast_signature(target)

    if target_sig in after:
        return ValidationStep(
            name="rescan",
            status=StepStatus.FAILED,
            detail=(
                f"the finding is still present after the patch "
                f"({target_sig[1]} {target_sig[2]} in {target_sig[0]})"
            ),
        )

    before = _alarming_signatures(baseline)
    introduced = sorted(after - before)
    if introduced:
        rendered = ", ".join(f"{cwe} {kind} in {file}" for file, cwe, kind in introduced)
        return ValidationStep(
            name="rescan",
            status=StepStatus.FAILED,
            detail=f"the patch introduced new finding(s): {rendered}",
        )
    return ValidationStep(name="rescan", status=StepStatus.PASSED)


def build_validator(
    *,
    project_root: Path,
    target: ScoredSastFinding,
    baseline: Sequence[ScoredSastFinding],
    plugins: Sequence[FrameworkPlugin] = DEFAULT_PLUGINS,
) -> Validator:
    """Bind :func:`validate_fix` to a project and target, yielding the injectable validator."""

    def _validate(suggestion: FixSuggestion) -> ValidationReport:
        return validate_fix(
            suggestion,
            project_root=project_root,
            target=target,
            baseline=baseline,
            plugins=plugins,
        )

    return _validate


def apply_patch_to_tree(diff: str, root: Path) -> None:
    """Apply ``diff`` to the real project tree at ``root`` (used by ``vulnadvisor fix --apply``).

    Verifies the patch applies cleanly first (``git apply --check``) so a failure leaves the tree
    untouched. Raises :class:`PatchApplyError` on any failure.
    """
    check = _git_apply(diff, root, check_only=True)
    if check.returncode != 0:
        raise PatchApplyError(_clip(check.stderr or check.stdout or "patch does not apply cleanly"))
    applied = _git_apply(diff, root)
    if applied.returncode != 0:
        raise PatchApplyError(_clip(applied.stderr or applied.stdout or "git apply failed"))
