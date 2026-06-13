"""Table-driven tests for the SAST sink detector (Task 16.2): positive, negative, adversarial."""

from pathlib import Path

import pytest

from vulnadvisor.sast import SastTier, find_sinks, find_sinks_in_source
from vulnadvisor.sast.model import SinkHit

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
SRC = REPO / "src"


def _hits(source: str) -> tuple[SinkHit, ...]:
    return find_sinks_in_source(source, "m.py")


def _kinds(source: str) -> set[str]:
    return {hit.kind for hit in _hits(source)}


def _only(source: str) -> SinkHit:
    hits = _hits(source)
    assert len(hits) == 1, [(h.kind, h.tier, h.callee) for h in hits]
    return hits[0]


# --- CWE-78 command injection ---------------------------------------------------------------


def test_os_system_non_literal_is_possible() -> None:
    hit = _only("import os\nos.system(cmd)\n")
    assert hit.cwe == "CWE-78"
    assert hit.callee == "os.system"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_os_system_literal_is_sanitized() -> None:
    hit = _only("import os\nos.system('ls -la')\n")
    assert hit.tier is SastTier.SANITIZED


def test_command_injection_from_import_alias() -> None:
    # Adversarial: `from os import system as run` -> bare call must still resolve to os.system.
    hit = _only("from os import system as run\nrun(cmd)\n")
    assert hit.cwe == "CWE-78"
    assert hit.callee == "os.system"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_shlex_quote_sanitizes_command() -> None:
    hit = _only("import os\nimport shlex\nos.system(shlex.quote(cmd))\n")
    assert hit.tier is SastTier.SANITIZED


def test_subprocess_shell_true_non_literal_is_possible() -> None:
    hit = _only("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    assert hit.cwe == "CWE-78"
    assert hit.callee == "subprocess.run"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_subprocess_without_shell_is_not_a_sink() -> None:
    # The safe list-argv form -> guard not satisfied -> no hit.
    assert _hits("import subprocess\nsubprocess.run([prog, arg])\n") == ()


def test_subprocess_shell_false_is_not_a_sink() -> None:
    assert _hits("import subprocess\nsubprocess.run(cmd, shell=False)\n") == ()


def test_subprocess_shell_variable_stays_cautious() -> None:
    # shell=<expr> cannot be proven False -> stays a sink (sound).
    hit = _only("import subprocess\nsubprocess.run(cmd, shell=flag)\n")
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_subprocess_getoutput_always_shells() -> None:
    hit = _only("import subprocess\nsubprocess.getoutput(cmd)\n")
    assert hit.cwe == "CWE-78"


# --- CWE-89 SQL injection -------------------------------------------------------------------


def test_execute_non_literal_is_possible() -> None:
    hit = _only("cursor.execute(query)\n")
    assert hit.cwe == "CWE-89"
    assert hit.callee == "execute"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_execute_literal_is_sanitized() -> None:
    hit = _only("cursor.execute('SELECT 1')\n")
    assert hit.tier is SastTier.SANITIZED


def test_execute_method_on_chained_receiver() -> None:
    # Adversarial: receiver is itself a call -> still matched by method heuristic.
    hit = _only("conn.cursor().execute(query)\n")
    assert hit.cwe == "CWE-89"
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-94 code injection ------------------------------------------------------------------


def test_eval_non_literal_is_possible() -> None:
    hit = _only("eval(user_input)\n")
    assert hit.cwe == "CWE-94"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_eval_literal_is_sanitized() -> None:
    assert _only("eval('1 + 1')\n").tier is SastTier.SANITIZED


def test_re_compile_is_not_code_injection() -> None:
    # `re.compile` is an attribute call, never the bare builtin `compile` -> no CWE-94 hit.
    assert "code-injection" not in _kinds("import re\nre.compile(pattern)\n")


# --- CWE-502 unsafe deserialization ---------------------------------------------------------


def test_pickle_loads_non_literal_is_possible() -> None:
    hit = _only("import pickle\npickle.loads(data)\n")
    assert hit.cwe == "CWE-502"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_yaml_load_aliased_import() -> None:
    # Adversarial: `import yaml as y` -> y.load must resolve to yaml.load.
    hit = _only("import yaml as y\ny.load(stream)\n")
    assert hit.cwe == "CWE-502"
    assert hit.callee == "yaml.load"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_yaml_load_safe_loader_is_sanitized() -> None:
    hit = _only("import yaml\nyaml.load(stream, Loader=yaml.SafeLoader)\n")
    assert hit.tier is SastTier.SANITIZED


def test_yaml_safe_load_is_not_a_sink() -> None:
    assert _hits("import yaml\nyaml.safe_load(stream)\n") == ()


# --- CWE-22 path traversal ------------------------------------------------------------------


def test_open_non_literal_is_possible() -> None:
    hit = _only("open(path)\n")
    assert hit.cwe == "CWE-22"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_open_literal_is_sanitized() -> None:
    assert _only("open('/etc/hosts')\n").tier is SastTier.SANITIZED


def test_open_no_args_is_not_a_sink() -> None:
    assert _hits("open()\n") == ()


def test_secure_filename_sanitizes_path() -> None:
    hit = _only("from werkzeug.utils import secure_filename\nopen(secure_filename(name))\n")
    assert hit.tier is SastTier.SANITIZED


# --- CWE-918 SSRF ---------------------------------------------------------------------------


def test_requests_get_non_literal_url_is_possible() -> None:
    hit = _only("import requests\nrequests.get(url)\n")
    assert hit.cwe == "CWE-918"
    assert hit.callee == "requests.get"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_urllib_urlopen_attribute_chain() -> None:
    # Adversarial: a three-segment attribute chain `urllib.request.urlopen`.
    hit = _only("import urllib.request\nurllib.request.urlopen(url)\n")
    assert hit.cwe == "CWE-918"
    assert hit.callee == "urllib.request.urlopen"


def test_requests_url_keyword_argument() -> None:
    hit = _only("import requests\nrequests.request(method='GET', url=target)\n")
    assert hit.cwe == "CWE-918"
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_requests_get_literal_url_is_sanitized() -> None:
    assert (
        _only("import requests\nrequests.get('https://example.com')\n").tier is SastTier.SANITIZED
    )


# --- CWE-798 hardcoded secrets --------------------------------------------------------------


def test_aws_key_pattern() -> None:
    hit = _only("key = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert hit.cwe == "CWE-798"
    assert hit.kind == "aws-access-key-id"
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_private_key_header_pattern() -> None:
    assert "private-key" in _kinds("k = '-----BEGIN RSA PRIVATE KEY-----'\n")


def test_secret_named_assignment() -> None:
    hit = _only("password = 'hunter2horse'\n")
    assert hit.cwe == "CWE-798"
    assert hit.kind == "hardcoded-credential"
    assert hit.callee == "password"


def test_secret_placeholder_is_ignored() -> None:
    assert _hits("password = 'changeme'\n") == ()


def test_short_secret_value_is_ignored() -> None:
    assert _hits("token = 'abc'\n") == ()


def test_secret_pattern_not_double_counted_in_assignment() -> None:
    # A literal matching a pattern AND assigned to a secret name is reported once (the pattern).
    hits = _hits("api_key = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert len(hits) == 1
    assert hits[0].kind == "aws-access-key-id"


# --- general negatives & robustness ---------------------------------------------------------


def test_benign_code_has_no_hits() -> None:
    assert _hits("import os\nx = os.path.join('a', 'b')\nprint(x)\n") == ()


def test_unparseable_source_returns_empty() -> None:
    assert find_sinks_in_source("def (:\n", "broken.py") == ()


def test_starred_args_stay_cautious() -> None:
    # *args splat hides the dangerous argument -> classify as POSSIBLE, never clear it.
    hit = _only("import os\nos.system(*parts)\n")
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_output_is_sorted_deterministically() -> None:
    source = "import os\nopen(p)\nos.system(cmd)\n"
    hits = _hits(source)
    keys = [(h.file, h.line, h.col) for h in hits]
    assert keys == sorted(keys)


# --- runs over the fixtures and the repo's own source without crashing -----------------------


def test_runs_over_fixtures_without_crashing() -> None:
    assert isinstance(find_sinks(FIXTURES), tuple)


def test_runs_over_repo_src_without_crashing() -> None:
    assert isinstance(find_sinks(SRC), tuple)


@pytest.mark.parametrize("target", [FIXTURES, SRC])
def test_scan_is_deterministic(target: Path) -> None:
    assert find_sinks(target) == find_sinks(target)
