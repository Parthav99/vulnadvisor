"""A ground-truth-labeled SAST corpus, run through the real VulnAdvisor taint engine and Bandit.

Each :class:`SastCase` is a tiny first-party app whose every sink site carries a ``# seed:`` marker
declaring the verdict a sound engine should reach (``vuln`` / ``safe`` / ``possible`` — see
:mod:`benchmarks.sast_metrics`). The cases are deliberately shaped to exercise the differentiator:

* **real, entry-point-reachable flows** (``vuln``) — must be caught (a miss is release-blocking),
* **sanitized / literal sinks** (``safe``) — must *not* be a top-tier alarm (the precision story:
  Bandit raises ``HIGH`` on ``shlex.quote``'d shell calls; VulnAdvisor marks them ``SANITIZED``),
* **real sinks unreachable from any entry point** (``possible``) — VulnAdvisor deprioritizes to
  ``POSSIBLE-FLOW`` while Bandit reports them at full severity (the triage/noise story).

Each case is materialized into its **own** temp directory and analyzed in isolation, so an entry
point in one case can never root an orphan helper in another (cross-rooting would corrupt the
ground truth). VulnAdvisor is run via the same :func:`~vulnadvisor.sast.analyze_taint` +
:func:`~vulnadvisor.engine.sast_scoring.score_sast_findings` path the CLI uses; Bandit is run as a
subprocess and is **optional** — when it is not installed the VulnAdvisor side (and the
release-blocking zero-missed gate) still runs.
"""

import json
import shutil
import subprocess  # noqa: S404 - fixed argv, never shell=True; invokes bandit only
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from benchmarks.sast_metrics import (
    TOOL_BANDIT,
    TOOL_VULNADVISOR,
    Detection,
    SastBenchmarkReport,
    Seed,
    build_sast_report,
    parse_seeds,
)
from vulnadvisor.engine.sast_scoring import score_sast_findings
from vulnadvisor.sast import analyze_taint

__all__ = ["CORPUS", "SastCase", "bandit_available", "run_sast_corpus"]


@dataclass(frozen=True)
class SastCase:
    """One labeled corpus app: a name and its source files (relpath -> source)."""

    name: str
    files: dict[str, str]


# --- The corpus. Every sink line ends in a `# seed:` marker giving the ground-truth verdict. ------

_CMD_INJECTION = '''\
"""Flask command execution: a reachable injection, a sanitized call, and an orphan sink."""
import os
import shlex

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c1 " + host)  # seed: CWE-78 vuln note="request param to os.system"
    return "ok"


@app.route("/ping-safe")
def ping_safe():
    host = request.args.get("host")
    os.system(shlex.quote(host))  # seed: CWE-78 safe note="shlex.quote sanitizer"
    return "ok"


def _orphan(host):
    os.system("ping -c1 " + host)  # seed: CWE-78 possible note="not reachable from any entry point"
'''

_SUBPROCESS_SHELL = '''\
"""FastAPI subprocess: a tainted shell=True call vs a sanitized one."""
import shlex
import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/run")
def run(cmd):
    subprocess.run("ls " + cmd, shell=True)  # seed: CWE-78 vuln note="shell=True with taint"


@app.get("/run-safe")
def run_safe(cmd):
    subprocess.run(shlex.quote(cmd), shell=True)  # seed: CWE-78 safe note="shlex.quote"
'''

_SQL_INJECTION = '''\
"""SQLi: a string-built query vs a parameterized one."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect("app.db")


@app.route("/user")
def user():
    name = request.args.get("name")
    cur = conn.cursor()
    cur.execute("SELECT * FROM u WHERE n = '" + name + "'")  # seed: CWE-89 vuln note="concat"
    return "ok"


@app.route("/user-safe")
def user_safe():
    name = request.args.get("name")
    cur = conn.cursor()
    cur.execute("SELECT * FROM u WHERE n = ?", (name,))  # seed: CWE-89 safe note="parameterized"
    return "ok"
'''

_CODE_INJECTION = '''\
"""Code injection via eval/exec from a request parameter."""
from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))  # seed: CWE-94 vuln note="eval of request param"


@app.route("/exec")
def run_exec():
    code = request.args.get("code")
    exec(code)  # seed: CWE-94 vuln note="exec of request param"
    return "ok"
'''

_DESERIALIZATION = '''\
"""Unsafe deserialization: yaml.load and pickle.loads on request bodies, plus a safe loader."""
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/yaml", methods=["POST"])
def load_yaml():
    return yaml.load(request.data)  # seed: CWE-502 vuln note="yaml.load on request body"


@app.route("/yaml-safe", methods=["POST"])
def load_yaml_safe():
    return yaml.safe_load(request.data)  # seed: CWE-502 safe note="yaml.safe_load is not a sink"


@app.route("/pickle", methods=["POST"])
def load_pickle():
    return pickle.loads(request.data)  # seed: CWE-502 vuln note="pickle.loads on request body"
'''

_PATH_TRAVERSAL = '''\
"""Path traversal: a tainted path into open(), and a fixed-literal path."""
import os

from flask import Flask, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    name = request.args.get("name")
    return open(os.path.join(BASE, name)).read()  # seed: CWE-22 vuln note="tainted path to open"


@app.route("/read-safe")
def read_safe():
    return open("/srv/files/readme.txt").read()  # seed: CWE-22 safe note="literal path"
'''

_SSRF = '''\
"""SSRF: a tainted URL into requests.get, vs a fixed literal URL (Bandit has no SSRF check)."""
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text  # seed: CWE-918 vuln note="tainted url to requests.get"


@app.route("/fetch-safe")
def fetch_safe():
    return requests.get("https://example.com").text  # seed: CWE-918 safe note="literal url"
'''

_HARDCODED_SECRET = '''\
"""Hardcoded secret: a literal token in source vs a value read from the environment."""
import os

GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"  # seed: CWE-798 vuln note="github PAT"

API_KEY = os.environ.get("API_KEY")  # seed: CWE-798 safe note="read from environment"


def client():
    return (GITHUB_TOKEN, API_KEY)
'''

_CROSS_FUNCTION = '''\
"""Cross-function flow: a request param reaches a sink through a helper (depth demo)."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/report")
def report():
    name = request.args.get("name")
    run_report(name)
    return "ok"


def run_report(part):
    os.system("report --for " + part)  # seed: CWE-78 vuln note="cross-function to os.system"
'''

_ARGV_SOURCE = '''\
"""Non-framework source: argv flows into a shell command."""
import os
import sys


def main():
    target = sys.argv[1]
    os.system("scan " + target)  # seed: CWE-78 vuln note="argv to os.system"
'''

CORPUS: tuple[SastCase, ...] = (
    SastCase("cmd_injection", {"app.py": _CMD_INJECTION}),
    SastCase("subprocess_shell", {"app.py": _SUBPROCESS_SHELL}),
    SastCase("sql_injection", {"app.py": _SQL_INJECTION}),
    SastCase("code_injection", {"app.py": _CODE_INJECTION}),
    SastCase("deserialization", {"app.py": _DESERIALIZATION}),
    SastCase("path_traversal", {"app.py": _PATH_TRAVERSAL}),
    SastCase("ssrf", {"app.py": _SSRF}),
    SastCase("hardcoded_secret", {"app.py": _HARDCODED_SECRET}),
    SastCase("cross_function", {"app.py": _CROSS_FUNCTION}),
    SastCase("argv_source", {"app.py": _ARGV_SOURCE}),
)


def bandit_available() -> bool:
    """Whether the ``bandit`` CLI can be invoked (the comparison is optional without it)."""
    return shutil.which("bandit") is not None or _bandit_module_runnable()


def _bandit_module_runnable() -> bool:
    """Whether ``python -m bandit`` works (covers a venv install without a PATH script)."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "bandit", "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _vulnadvisor_detections(case: SastCase, root: Path) -> list[Detection]:
    """Run the real taint engine + scorer over ``root`` and normalize findings to detections."""
    detections: list[Detection] = []
    for scored in score_sast_findings(analyze_taint(root)):
        finding = scored.finding
        detections.append(
            Detection(
                tool=TOOL_VULNADVISOR,
                file=f"{case.name}/{finding.file}",
                line=finding.line,
                cwe=finding.cwe,
                label=finding.tier.value,
            )
        )
    return detections


def _bandit_detections(case: SastCase, root: Path) -> list[Detection]:
    """Run Bandit over ``root`` (JSON output) and normalize its results to detections.

    Defensive: Bandit exits non-zero when it finds issues (that is expected, not an error); only an
    unparseable payload or a launch failure yields no detections.
    """
    argv = [sys.executable, "-m", "bandit"] if shutil.which("bandit") is None else ["bandit"]
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [*argv, "-r", "-f", "json", "-q", str(root)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    detections: list[Detection] = []
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        filename = item.get("filename")
        line = item.get("line_number")
        if not isinstance(filename, str) or not isinstance(line, int):
            continue
        try:
            rel = Path(filename).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = Path(filename).name
        cwe_obj = item.get("issue_cwe") or {}
        cwe_id = cwe_obj.get("id") if isinstance(cwe_obj, dict) else None
        cwe = f"CWE-{cwe_id}" if isinstance(cwe_id, int) else ""
        severity = item.get("issue_severity")
        detections.append(
            Detection(
                tool=TOOL_BANDIT,
                file=f"{case.name}/{rel}",
                line=line,
                cwe=cwe,
                label=severity if isinstance(severity, str) else "",
            )
        )
    return detections


def run_sast_corpus(
    corpus: Sequence[SastCase] = CORPUS, *, run_bandit: bool = True
) -> SastBenchmarkReport:
    """Materialize and analyze every corpus case, returning the aggregated benchmark report.

    Each case runs in its own temp directory (isolation preserves the ground truth). VulnAdvisor
    always runs; Bandit runs when ``run_bandit`` is set and the CLI is available.
    """
    have_bandit = run_bandit and bandit_available()
    seeds: list[Seed] = []
    detections: list[Detection] = []
    for case in corpus:
        with tempfile.TemporaryDirectory(prefix=f"vulnadvisor-sast-bench-{case.name}-") as tmp:
            root = Path(tmp)
            for rel, source in case.files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
                seeds.extend(parse_seeds(case.name, f"{case.name}/{rel}", source))
            detections.extend(_vulnadvisor_detections(case, root))
            if have_bandit:
                detections.extend(_bandit_detections(case, root))
    return build_sast_report(seeds, detections, bandit_available=have_bandit)
