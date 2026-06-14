"""Tests for ``vulnadvisor fix`` (Task 17.1): the validated, machine-proven patch.

Three layers, mirroring the task's Validation Gate:

* **Engine** — finding resolution, minimal code-context extraction, defensive JSON parsing, and the
  propose->validate->retry loop driven with a *fake* validator (no subprocess).
* **Validator** — the real apply/syntax/ruff/rescan loop over throwaway copies of tiny projects:
  a clean fix passes, a non-applying / syntax-breaking / regression-introducing patch fails.
* **Harness** — >=8 fixture vulns across the CWE set, each fixed by a canonical (git-generated)
  diff that must pass the *full* loop; a deliberately ineffective patch yields "no safe fix"; an
  ``--apply`` round-trip; and a network audit proving code only ever leaves via the model client.
"""

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from vulnadvisor.advisories.matcher import AdvisoryMatcher
from vulnadvisor.advisories.transport import Transport
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.llm.client import AnthropicClient, LLMError, OpenAICompatibleClient
from vulnadvisor.llm.fix import (
    AmbiguousFindingError,
    FindingNotFoundError,
    extract_code_context,
    generate_fix,
    parse_fix_suggestion,
    resolve_sast_finding,
    sast_finding_id,
    sast_signature,
)
from vulnadvisor.llm.fix_validate import (
    PatchApplyError,
    apply_patch_to_tree,
    build_validator,
    validate_fix,
)
from vulnadvisor.model.fix import (
    FixConfidence,
    FixOutcome,
    FixSuggestion,
    StepStatus,
    ValidationReport,
    ValidationStep,
)
from vulnadvisor.sast import SastTier, analyze_source
from vulnadvisor.sast.model import ScoredSastFinding

# --- helpers ------------------------------------------------------------------------------------


@dataclass
class ScriptedClient:
    """An :class:`LLMClient` that replays a fixed list of raw responses (no network)."""

    responses: list[str]
    model: str = "scripted"
    prompts: list[tuple[str, str]] = field(default_factory=list)

    def complete(self, *, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if not self.responses:
            raise LLMError("no scripted response left")
        return self.responses.pop(0)


def _suggestion_json(diff: str, *, rationale: str = "fix", confidence: str = "high") -> str:
    return json.dumps({"diff": diff, "rationale": rationale, "confidence": confidence})


def _canonical_diff(rel: str, before: str, after: str) -> str:
    """Produce a real ``git diff`` for ``rel`` going from ``before`` to ``after``.

    Using git to author the diff guarantees it is exactly what ``git apply`` round-trips, so the
    harness proves the *validation loop*, not our diff-formatting.
    """
    import tempfile

    repo = Path(tempfile.mkdtemp(prefix="va-difftool-"))
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(before, encoding="utf-8")
    env = ["-c", "user.email=t@t.t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", *env, "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", *env, "commit", "-qm", "base"], cwd=repo, check=True)
    target.write_text(after, encoding="utf-8")
    diff = subprocess.run(
        ["git", *env, "diff"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    assert diff.strip(), "expected a non-empty diff"
    return diff


def _make_project(tmp_path: Path, name: str, rel: str, source: str) -> Path:
    proj = tmp_path / name
    target = proj / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return proj


class _NullMatcher:
    """A matcher that is never called (SAST-only scans pass ``run_sca=False``)."""

    def match(self, dependencies: object) -> object:  # pragma: no cover - defensive
        raise AssertionError("SCA matching must not run during a fix")


def _sast_scan(proj: Path) -> list[ScoredSastFinding]:
    matcher: AdvisoryMatcher = _NullMatcher()  # type: ignore[assignment]
    return scan_project(proj, matcher, run_sca=False, run_sast=True).sast_findings


# --- the fixture corpus: vuln -> canonical fix, across the CWE set ------------------------------

REL = "vuln.py"

# Each entry: (id, vulnerable source, fixed source). The fix is either a recognized sanitizer
# (finding survives as SANITIZED, not alarming) or a safe API (finding disappears entirely). The
# sources are kept as multi-line literals so each physical line stays readable.
_CMD_VULN = "import os\nimport sys\n\n\ndef run():\n    os.system(sys.argv[1])\n"
_CMD_SANITIZE = (
    "import os\nimport shlex\nimport sys\n\n\ndef run():\n    os.system(shlex.quote(sys.argv[1]))\n"
)
_CMD_ARGV = (
    "import subprocess\nimport sys\n\n\n"
    "def run():\n    subprocess.run([sys.argv[1]], check=False)\n"
)
_SQL_VULN = (
    "import sys\n\n\ndef q(conn):\n"
    '    conn.cursor().execute("SELECT * FROM t WHERE a = \'" + sys.argv[1] + "\'")\n'
)
_SQL_FIXED = (
    "import sys\n\n\ndef q(conn):\n"
    '    conn.cursor().execute("SELECT * FROM t WHERE a = ?", (sys.argv[1],))\n'
)
_EVAL_VULN = "import sys\n\n\ndef run():\n    return eval(sys.argv[1])\n"
_EVAL_FIXED = "import ast\nimport sys\n\n\ndef run():\n    return ast.literal_eval(sys.argv[1])\n"
_YAML_VULN = "import sys\n\nimport yaml\n\n\ndef run():\n    return yaml.load(sys.argv[1])\n"
_YAML_FIXED = "import sys\n\nimport yaml\n\n\ndef run():\n    return yaml.safe_load(sys.argv[1])\n"
_PICKLE_VULN = (
    "import pickle\nimport sys\n\n\ndef run():\n    return pickle.loads(sys.argv[1].encode())\n"
)
_PICKLE_FIXED = "import json\nimport sys\n\n\ndef run():\n    return json.loads(sys.argv[1])\n"
_PATH_VULN = "import sys\n\n\ndef read():\n    return open(sys.argv[1])\n"
_PATH_FIXED = (
    "import sys\n\nfrom werkzeug.utils import secure_filename\n\n\n"
    "def read():\n    return open(secure_filename(sys.argv[1]))\n"
)
_SECRET_VULN = 'SECRET = "AKIAIOSFODNN7EXAMPLE"\n'
_SECRET_FIXED = 'import os\n\nSECRET = os.environ["AWS_KEY"]\n'

FIXTURES: list[tuple[str, str, str]] = [
    ("cwe78-cmd-sanitize", _CMD_VULN, _CMD_SANITIZE),
    ("cwe78-cmd-argv-list", _CMD_VULN, _CMD_ARGV),
    ("cwe89-sql-parameterize", _SQL_VULN, _SQL_FIXED),
    ("cwe94-eval-literal", _EVAL_VULN, _EVAL_FIXED),
    ("cwe502-yaml-safe", _YAML_VULN, _YAML_FIXED),
    ("cwe502-pickle-json", _PICKLE_VULN, _PICKLE_FIXED),
    ("cwe22-path-secure", _PATH_VULN, _PATH_FIXED),
    ("cwe798-secret-env", _SECRET_VULN, _SECRET_FIXED),
]


def test_fixture_corpus_covers_at_least_eight_vulns(tmp_path: Path) -> None:
    assert len(FIXTURES) >= 8
    # Every fixture's vulnerable source must produce exactly one alarming finding (full scan, so
    # CWE-798 hardcoded secrets — which come from the find_sinks baseline — are included).
    for name, vuln, _ in FIXTURES:
        proj = _make_project(tmp_path, name, REL, vuln)
        findings = _sast_scan(proj)
        alarming = [f for f in findings if f.finding.tier is not SastTier.SANITIZED]
        assert len(alarming) == 1, (name, [(f.finding.kind, f.finding.tier) for f in findings])


@pytest.mark.parametrize("name,vuln,fixed", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_harness_every_fixture_fix_passes_full_validation(
    tmp_path: Path, name: str, vuln: str, fixed: str
) -> None:
    """Each fixture's canonical fix must pass the entire validation loop (apply..rescan)."""
    proj = _make_project(tmp_path, name, REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)

    diff = _canonical_diff(REL, vuln, fixed)
    client = ScriptedClient([_suggestion_json(diff)])
    context = extract_code_context(target.finding, lambda r: (proj / r).read_text(encoding="utf-8"))
    validate = build_validator(project_root=proj, target=target, baseline=findings)
    result = generate_fix(
        finding=target.finding, code_context=context, client=client, validate=validate
    )

    assert result.outcome is FixOutcome.VALIDATED, [
        (s.name, s.status.value, s.detail)
        for a in result.attempts
        if a.report
        for s in a.report.steps
    ]
    assert result.suggestion is not None
    # Re-running the engine on the fixed source confirms the finding is no longer alarming.
    fixed_findings = analyze_source(fixed, REL)
    assert all(f.tier is SastTier.SANITIZED for f in fixed_findings)


def test_harness_unfixable_fixture_yields_no_safe_fix(tmp_path: Path) -> None:
    """A patch that does not remove the finding is never emitted; the loop reports no safe fix."""
    vuln = "import os\nimport sys\n\n\ndef run():\n    os.system(sys.argv[1])\n"
    proj = _make_project(tmp_path, "unfixable", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)

    # A diff that only adds a comment: it applies and parses, but the sink is untouched.
    ineffective = _canonical_diff(REL, vuln, "# attempted fix\n" + vuln)
    client = ScriptedClient([_suggestion_json(ineffective)] * 3)
    validate = build_validator(project_root=proj, target=target, baseline=findings)
    result = generate_fix(
        finding=target.finding, code_context="", client=client, validate=validate, max_attempts=3
    )

    assert result.outcome is FixOutcome.NO_SAFE_FIX
    assert result.suggestion is None
    assert len(result.attempts) == 3
    last = result.attempts[-1].report
    assert last is not None
    failure = last.first_failure()
    assert failure is not None and failure.name == "rescan"
    assert "still present" in failure.detail


def test_apply_round_trip_matches_printed_diff(tmp_path: Path) -> None:
    """``--apply`` writes exactly the validated diff: a git repo's diff equals the patch."""
    name, vuln, fixed = FIXTURES[0]
    proj = _make_project(tmp_path, "applyroundtrip", REL, vuln)
    env = ["-c", "user.email=t@t.t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
    subprocess.run(["git", *env, "add", "-A"], cwd=proj, check=True)
    subprocess.run(["git", *env, "commit", "-qm", "base"], cwd=proj, check=True)

    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    diff = _canonical_diff(REL, vuln, fixed)
    client = ScriptedClient([_suggestion_json(diff)])
    validate = build_validator(project_root=proj, target=target, baseline=findings)
    result = generate_fix(finding=target.finding, code_context="", client=client, validate=validate)
    assert result.suggestion is not None

    apply_patch_to_tree(result.suggestion.diff, proj)
    # The on-disk file now equals the intended fix, and a clean re-scan confirms it.
    assert (proj / REL).read_text(encoding="utf-8") == fixed
    after = _sast_scan(proj)
    alarming = {sast_signature(f) for f in after if f.finding.tier is not SastTier.SANITIZED}
    assert sast_signature(target) not in alarming


def test_network_audit_only_the_model_endpoint_is_contacted(tmp_path: Path) -> None:
    """The only outbound request during a full fix is to the user's own Anthropic endpoint."""
    name, vuln, fixed = FIXTURES[1]
    proj = _make_project(tmp_path, "netaudit", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    diff = _canonical_diff(REL, vuln, fixed)

    calls: list[str] = []

    class RecordingTransport:
        def request(self, method, url, *, body=None, headers=None):  # type: ignore[no-untyped-def]
            calls.append(url)
            payload = {"content": [{"type": "text", "text": _suggestion_json(diff)}]}
            return json.dumps(payload).encode("utf-8")

    transport: Transport = RecordingTransport()
    client = AnthropicClient(transport, api_key="sk-ant-test", model="claude-haiku-4-5-20251001")
    validate = build_validator(project_root=proj, target=target, baseline=findings)
    result = generate_fix(finding=target.finding, code_context="", client=client, validate=validate)

    assert result.outcome is FixOutcome.VALIDATED
    assert calls, "expected the model to be called"
    assert all("api.anthropic.com" in url for url in calls)


def test_full_loop_with_openai_compatible_client_validates_and_audits_host(tmp_path: Path) -> None:
    """Task 17.3: a scripted OpenAI-compatible (OpenRouter) client drives the *unchanged* 17.1 loop.

    The model response uses the chat-completions ``choices/message/content`` shape; the validation
    loop (apply -> syntax -> ruff -> rescan) is identical, and the only outbound host is
    ``openrouter.ai`` — never ``api.anthropic.com``.
    """
    name, vuln, fixed = FIXTURES[1]  # CWE-78 -> argv list
    proj = _make_project(tmp_path, "openrouter", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    diff = _canonical_diff(REL, vuln, fixed)

    calls: list[str] = []

    class RecordingTransport:
        def request(self, method, url, *, body=None, headers=None):  # type: ignore[no-untyped-def]
            calls.append(url)
            # The OpenAI-compatible chat-completions response shape.
            payload = {"choices": [{"message": {"content": _suggestion_json(diff)}}]}
            return json.dumps(payload).encode("utf-8")

    transport: Transport = RecordingTransport()
    client = OpenAICompatibleClient(
        transport=transport,
        api_key="sk-or-test",
        base_url="https://openrouter.ai/api/v1/chat/completions",
        model="openrouter/auto",
    )
    context = extract_code_context(target.finding, lambda r: (proj / r).read_text(encoding="utf-8"))
    validate = build_validator(project_root=proj, target=target, baseline=findings)
    result = generate_fix(
        finding=target.finding, code_context=context, client=client, validate=validate
    )

    assert result.outcome is FixOutcome.VALIDATED
    assert result.suggestion is not None
    assert calls, "expected the model to be called"
    assert all("openrouter.ai" in url for url in calls)
    assert all("api.anthropic.com" not in url for url in calls)


# --- parsing ------------------------------------------------------------------------------------


def test_parse_valid_suggestion() -> None:
    raw = _suggestion_json("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b", confidence="low")
    suggestion = parse_fix_suggestion(raw)
    assert suggestion is not None
    assert suggestion.confidence is FixConfidence.LOW
    assert suggestion.diff.endswith("\n")  # trailing newline added for git apply


def test_parse_tolerates_code_fence_and_prose() -> None:
    raw = 'Here is the fix:\n```json\n{"diff": "--- a/x\\n+++ b/x\\n", "rationale": "ok"}\n```'
    suggestion = parse_fix_suggestion(raw)
    assert suggestion is not None
    assert suggestion.confidence is FixConfidence.MEDIUM  # absent -> default


def test_parse_rejects_missing_or_empty_diff() -> None:
    assert parse_fix_suggestion('{"rationale": "ok"}') is None
    assert parse_fix_suggestion('{"diff": "  ", "rationale": "ok"}') is None
    assert parse_fix_suggestion('{"diff": "x", "rationale": ""}') is None


def test_parse_rejects_non_json() -> None:
    assert parse_fix_suggestion("not json at all") is None
    assert parse_fix_suggestion('["a", "b"]') is None


def test_parse_coerces_unknown_confidence_to_medium() -> None:
    suggestion = parse_fix_suggestion(_suggestion_json("--- a\n+++ b\n", confidence="banana"))
    assert suggestion is not None
    assert suggestion.confidence is FixConfidence.MEDIUM


# --- finding resolution -------------------------------------------------------------------------


def _two_finding_scan(tmp_path: Path) -> list[ScoredSastFinding]:
    proj = tmp_path / "multi"
    (proj).mkdir()
    (proj / "a.py").write_text(
        "import os\nimport sys\n\n\ndef r():\n    os.system(sys.argv[1])\n", encoding="utf-8"
    )
    (proj / "b.py").write_text(
        "import sys\n\n\ndef r():\n    return eval(sys.argv[1])\n", encoding="utf-8"
    )
    return _sast_scan(proj)


def test_resolve_by_full_id_file_line_and_bare_file(tmp_path: Path) -> None:
    findings = _two_finding_scan(tmp_path)
    by_file = resolve_sast_finding(findings, "a.py")
    assert by_file.finding.file == "a.py"
    full = sast_finding_id(by_file)
    assert resolve_sast_finding(findings, full) is by_file
    short = f"{by_file.finding.file}:{by_file.finding.line}"
    assert resolve_sast_finding(findings, short) is by_file


def test_resolve_not_found_raises(tmp_path: Path) -> None:
    findings = _two_finding_scan(tmp_path)
    with pytest.raises(FindingNotFoundError):
        resolve_sast_finding(findings, "nope.py")


def test_resolve_ambiguous_kind_raises(tmp_path: Path) -> None:
    proj = tmp_path / "dup"
    proj.mkdir()
    (proj / "a.py").write_text(
        "import os\nimport sys\n\n\ndef r():\n    os.system(sys.argv[1])\n", encoding="utf-8"
    )
    (proj / "b.py").write_text(
        "import os\nimport sys\n\n\ndef r():\n    os.system(sys.argv[1])\n", encoding="utf-8"
    )
    findings = _sast_scan(proj)
    with pytest.raises(AmbiguousFindingError):
        resolve_sast_finding(findings, "command-injection")


# --- code context -------------------------------------------------------------------------------


def test_context_includes_enclosing_function_and_flow_steps() -> None:
    source = (
        "import os\n"
        "import sys\n"
        "\n"
        "\n"
        "def helper(value):\n"
        "    os.system(value)\n"
        "\n"
        "\n"
        "def entry():\n"
        "    helper(sys.argv[1])\n"
    )
    findings = analyze_source(source, "m.py")
    confirmed = next(f for f in findings if f.tier is SastTier.CONFIRMED_FLOW)
    context = extract_code_context(confirmed, lambda r: source)
    assert "# File: m.py" in context
    assert "def helper(value):" in context
    assert "os.system(value)" in context
    # The cross-function source step pulls in the entry function too.
    assert "def entry():" in context


def test_context_handles_unreadable_file() -> None:
    findings = analyze_source(
        "import os\nimport sys\n\n\ndef r():\n    os.system(sys.argv[1])\n", "m.py"
    )
    context = extract_code_context(findings[0], lambda r: None)
    assert "could not read" in context


def test_context_module_scope_secret_uses_window(tmp_path: Path) -> None:
    source = 'SECRET = "AKIAIOSFODNN7EXAMPLE"\n'
    proj = _make_project(tmp_path, "secretctx", "s.py", source)
    findings = _sast_scan(proj)
    context = extract_code_context(findings[0].finding, lambda r: source)
    assert "AKIAIOSFODNN7EXAMPLE" in context


# --- the loop (fake validator) ------------------------------------------------------------------


def _ok_report() -> ValidationReport:
    step = ValidationStep(name="rescan", status=StepStatus.PASSED)
    return ValidationReport(ok=True, steps=(step,))


def _fail_report(detail: str) -> ValidationReport:
    return ValidationReport(
        ok=False, steps=(ValidationStep(name="rescan", status=StepStatus.FAILED, detail=detail),)
    )


_FINDING_SRC = "import os\nimport sys\n\n\ndef r():\n    os.system(sys.argv[1])\n"


def test_loop_succeeds_on_first_attempt() -> None:
    finding = analyze_source(_FINDING_SRC, "m.py")[0]
    client = ScriptedClient([_suggestion_json("--- a\n+++ b\n")])
    result = generate_fix(
        finding=finding, code_context="", client=client, validate=lambda s: _ok_report()
    )
    assert result.outcome is FixOutcome.VALIDATED
    assert len(result.attempts) == 1
    assert len(client.prompts) == 1


def test_loop_retries_with_feedback_then_succeeds() -> None:
    finding = analyze_source(_FINDING_SRC, "m.py")[0]
    client = ScriptedClient(
        [_suggestion_json("--- a\n+++ b1\n"), _suggestion_json("--- a\n+++ b2\n")]
    )
    reports = [_fail_report("the sink survived"), _ok_report()]
    result = generate_fix(
        finding=finding,
        code_context="",
        client=client,
        validate=lambda s: reports.pop(0),
    )
    assert result.outcome is FixOutcome.VALIDATED
    assert len(result.attempts) == 2
    # The second prompt carries the first failure's feedback.
    assert "the sink survived" in client.prompts[1][1]


def test_loop_all_attempts_fail_returns_no_safe_fix() -> None:
    finding = analyze_source(_FINDING_SRC, "m.py")[0]
    client = ScriptedClient([_suggestion_json("--- a\n+++ b\n")] * 3)
    result = generate_fix(
        finding=finding,
        code_context="",
        client=client,
        validate=lambda s: _fail_report("nope"),
        max_attempts=3,
    )
    assert result.outcome is FixOutcome.NO_SAFE_FIX
    assert result.suggestion is None
    assert len(result.attempts) == 3


def test_loop_records_parse_failure_attempt() -> None:
    finding = analyze_source(_FINDING_SRC, "m.py")[0]
    client = ScriptedClient(["not json", _suggestion_json("--- a\n+++ b\n")])
    result = generate_fix(
        finding=finding, code_context="", client=client, validate=lambda s: _ok_report()
    )
    assert result.outcome is FixOutcome.VALIDATED
    assert result.attempts[0].suggestion is None
    assert "not a valid fix" in result.attempts[0].note


def test_loop_records_model_error_attempt() -> None:
    finding = analyze_source(_FINDING_SRC, "m.py")[0]

    class Boom:
        model = "boom"

        def complete(self, *, system: str, user: str) -> str:
            raise LLMError("503")

    result = generate_fix(
        finding=finding,
        code_context="",
        client=Boom(),
        validate=lambda s: _ok_report(),
        max_attempts=1,
    )
    assert result.outcome is FixOutcome.NO_SAFE_FIX
    assert "model call failed" in result.attempts[0].note


# --- validator integration (real subprocess) ---------------------------------------------------


def _validate(
    proj: Path, target: ScoredSastFinding, baseline: Sequence[ScoredSastFinding], diff: str
) -> ValidationReport:
    return validate_fix(
        FixSuggestion(diff=diff, rationale="r", confidence=FixConfidence.MEDIUM),
        project_root=proj,
        target=target,
        baseline=baseline,
    )


def test_validator_rejects_non_applying_patch(tmp_path: Path) -> None:
    vuln = _FINDING_SRC
    proj = _make_project(tmp_path, "noapply", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    bad = "--- a/vuln.py\n+++ b/vuln.py\n@@ -99,1 +99,1 @@\n-nonexistent line\n+other\n"
    report = _validate(proj, target, findings, bad)
    assert not report.ok
    assert report.first_failure() is not None
    assert report.first_failure().name == "apply"  # type: ignore[union-attr]


def test_validator_rejects_syntax_breaking_patch(tmp_path: Path) -> None:
    vuln = _FINDING_SRC
    proj = _make_project(tmp_path, "broken", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    # Replace the call with invalid syntax.
    broken = _canonical_diff(REL, vuln, vuln.replace("os.system(sys.argv[1])", "os.system(("))
    report = _validate(proj, target, findings, broken)
    assert not report.ok
    assert report.first_failure().name == "syntax"  # type: ignore[union-attr]


def test_validator_rejects_patch_introducing_new_finding(tmp_path: Path) -> None:
    vuln = _FINDING_SRC
    # "Fix" the original sink but introduce a brand-new eval sink: net regression.
    regressed = "import sys\n\n\ndef r():\n    return eval(sys.argv[1])\n"
    proj = _make_project(tmp_path, "regress", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    diff = _canonical_diff(REL, vuln, regressed)
    report = _validate(proj, target, findings, diff)
    assert not report.ok
    failure = report.first_failure()
    assert failure is not None and failure.name == "rescan"
    assert "introduced new finding" in failure.detail


def test_validator_accepts_sanitizing_patch(tmp_path: Path) -> None:
    vuln, fixed = FIXTURES[0][1], FIXTURES[0][2]
    proj = _make_project(tmp_path, "sanitize", REL, vuln)
    findings = _sast_scan(proj)
    target = resolve_sast_finding(findings, REL)
    diff = _canonical_diff(REL, vuln, fixed)
    report = _validate(proj, target, findings, diff)
    assert report.ok
    assert [s.status for s in report.steps if s.name == "rescan"] == [StepStatus.PASSED]


def test_apply_patch_to_tree_raises_on_bad_patch(tmp_path: Path) -> None:
    proj = _make_project(tmp_path, "applyfail", REL, _FINDING_SRC)
    with pytest.raises(PatchApplyError):
        apply_patch_to_tree("--- a/vuln.py\n+++ b/vuln.py\n@@ -50 +50 @@\n-x\n+y\n", proj)
