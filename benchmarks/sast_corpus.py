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
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, never shell=True; invokes bandit/semgrep only
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from benchmarks.sast_metrics import (
    TOOL_BANDIT,
    TOOL_SEMGREP,
    TOOL_VULNADVISOR,
    Detection,
    SastBenchmarkReport,
    Seed,
    build_sast_report,
    parse_seeds,
)
from vulnadvisor.engine.sast_scoring import score_sast_findings
from vulnadvisor.sast import analyze_taint

__all__ = [
    "CORPUS",
    "SastCase",
    "bandit_available",
    "run_sast_corpus",
    "semgrep_available",
]


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

# --- Task 20 recall-depth cases: taint that survives containers, modules, and object state --------
# These exercise the M20.1-20.3 engine additions. A naive line/AST scanner (Bandit) catches the
# *sink* but cannot prove the *flow*, so it cannot distinguish the reachable case from an orphan;
# VulnAdvisor proves the source->sink path through the container/module/attribute and reserves
# CONFIRMED-FLOW for it. Seeded for recall (the flows must be caught) — a miss is release-blocking.

_CONTAINER_TAINT = '''\
"""Container taint (Task 20.1): a request value survives a list and a dict into a shell sink."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/list")
def via_list():
    host = request.args.get("host")
    parts = []
    parts.append(host)
    os.system("ping " + parts[0])  # seed: CWE-78 vuln note="taint via list element (20.1)"
    return "ok"


@app.route("/dict")
def via_dict():
    cfg = {"cmd": request.args.get("cmd")}
    os.system(cfg["cmd"])  # seed: CWE-78 vuln note="taint via dict value (20.1)"
    return "ok"
'''

_CROSS_MODULE_TAINT = {
    "app.py": '''\
"""Cross-module taint (Task 20.2): a request param reaches a sink defined in another module."""
from flask import Flask, request

from helpers import run_cmd, run_safe

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    return run_cmd(cmd)


@app.route("/run-safe")
def run_safe_route():
    cmd = request.args.get("cmd")
    return run_safe(cmd)
''',
    "helpers.py": '''\
"""The sink module, reached cross-file from app.py."""
import os
import shlex


def run_cmd(part):
    os.system("do " + part)  # seed: CWE-78 vuln note="cross-module sink (20.2)"
    return "ok"


def run_safe(part):
    os.system(shlex.quote(part))  # seed: CWE-78 safe note="sanitized across modules (20.2)"
    return "ok"


def _orphan(part):
    os.system("legacy " + part)  # seed: CWE-78 possible note="cross-module sink, no entry point"
    return "ok"
''',
}

_ATTRIBUTE_TAINT = '''\
"""Object/attribute taint (Task 20.3): taint stored on self.attr reaches a sink in a method."""
import os

from flask import Flask, request

app = Flask(__name__)


class Runner:
    def __init__(self, cmd):
        self.cmd = cmd

    def execute(self):
        os.system("run " + self.cmd)  # seed: CWE-78 vuln note="taint via self.attr (20.3)"


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    Runner(cmd).execute()
    return "ok"
'''

# --- Task 20.4 new CWE families: roughly double the vuln classes, each positive + safe ------------

_SSTI = '''\
"""SSTI (CWE-1336): a request param rendered as a Jinja template, vs a literal template."""
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/render")
def render():
    tpl = request.args.get("tpl")
    return render_template_string(tpl)  # seed: CWE-1336 vuln note="user template rendered"


@app.route("/render-safe")
def render_safe():
    return render_template_string("<p>hello</p>")  # seed: CWE-1336 safe note="literal template"
'''

_XXE = '''\
"""XXE (CWE-611): parsing an untrusted XML body with lxml, vs a literal document."""
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    return str(etree.fromstring(request.data))  # seed: CWE-611 vuln note="lxml parse of body"


@app.route("/parse-safe")
def parse_safe():
    return str(etree.fromstring("<a/>"))  # seed: CWE-611 safe note="literal xml"
'''

_OPEN_REDIRECT = '''\
"""Open redirect (CWE-601): redirecting to a user-controlled URL, vs a fixed path."""
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # seed: CWE-601 vuln note="redirect to request param"


@app.route("/home")
def home():
    return redirect("/home")  # seed: CWE-601 safe note="literal redirect target"
'''

_LDAP_INJECTION = '''\
"""LDAP injection (CWE-90): an unescaped filter from a request, vs an escaped one."""
import ldap
from flask import Flask, request
from ldap.filter import escape_filter_chars

app = Flask(__name__)
conn = ldap.initialize("ldap://x")


@app.route("/lookup")
def lookup():
    uid = request.args.get("uid")
    conn.search_s("dc=x", 2, "(uid=" + uid + ")")  # seed: CWE-90 vuln note="unescaped filter"
    return "ok"


@app.route("/lookup-safe")
def lookup_safe():
    uid = request.args.get("uid")
    conn.search_s("dc=x", 2, escape_filter_chars(uid))  # seed: CWE-90 safe note="escaped filter"
    return "ok"
'''

_XPATH_INJECTION = '''\
"""XPath injection (CWE-643): a user value concatenated into an XPath, vs a literal."""
from flask import Flask, request
from lxml import etree

app = Flask(__name__)
tree = etree.parse("data.xml")


@app.route("/find")
def find():
    q = request.args.get("q")
    return str(tree.xpath('//user[name="' + q + '"]'))  # seed: CWE-643 vuln note="tainted xpath"


@app.route("/find-safe")
def find_safe():
    return str(tree.xpath("//user"))  # seed: CWE-643 safe note="literal xpath"
'''

_REDOS = '''\
"""ReDoS (CWE-1333): a request-controlled regex pattern compiled, vs a literal pattern."""
import re

from flask import Flask, request

app = Flask(__name__)


@app.route("/match")
def match():
    pat = request.args.get("pat")
    return str(re.compile(pat))  # seed: CWE-1333 vuln note="user-controlled regex pattern"


@app.route("/match-safe")
def match_safe():
    return str(re.compile(r"\\d+"))  # seed: CWE-1333 safe note="literal pattern"
'''

_WEAK_CRYPTO = '''\
"""Weak hash (CWE-327, intrinsic): MD5 used for security vs an explicit non-security use."""
import hashlib


def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # seed: CWE-327 vuln note="md5 used for security"


def checksum(data):
    digest = hashlib.md5(data, usedforsecurity=False)  # seed: CWE-327 safe note="non-security use"
    return digest.hexdigest()
'''

_INSECURE_RANDOM = '''\
"""Insecure randomness (CWE-330, intrinsic): the random module for a token vs the secrets module."""
import random
import secrets


def weak_token():
    return random.getrandbits(128)  # seed: CWE-330 vuln note="random for a security token"


def strong_token():
    return secrets.token_hex(16)  # seed: CWE-330 safe note="secrets module is not a sink"
'''

_DISABLED_TLS = '''\
"""Disabled TLS verification (CWE-295, intrinsic): verify=False vs the verified default."""
import requests


def fetch_insecure(url):
    return requests.get(url, verify=False)  # seed: CWE-295 vuln note="verify=False"


def fetch_secure():
    return requests.get("https://example.com")  # seed: CWE-295 safe note="verified, literal url"
'''

_ARCHIVE_EXTRACT = '''\
"""Archive path traversal (CWE-22, intrinsic): extractall without a filter vs with one."""
import tarfile
import zipfile


def unpack(path):
    tarfile.open(path).extractall("/tmp")  # seed: CWE-22 vuln note="extractall, no filter"


def unpack_safe(path):
    zipfile.ZipFile(path).extractall("/tmp", filter="data")  # seed: CWE-22 safe note="filter set"
'''

CORPUS: tuple[SastCase, ...] = (
    # M16 originals (the seven founding CWE classes).
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
    # M20.1-20.3 recall-depth: containers, cross-module, object state.
    SastCase("container_taint", {"app.py": _CONTAINER_TAINT}),
    SastCase("cross_module_taint", dict(_CROSS_MODULE_TAINT)),
    SastCase("attribute_taint", {"app.py": _ATTRIBUTE_TAINT}),
    # M20.4 new CWE families (taint-based and intrinsic).
    SastCase("ssti", {"app.py": _SSTI}),
    SastCase("xxe", {"app.py": _XXE}),
    SastCase("open_redirect", {"app.py": _OPEN_REDIRECT}),
    SastCase("ldap_injection", {"app.py": _LDAP_INJECTION}),
    SastCase("xpath_injection", {"app.py": _XPATH_INJECTION}),
    SastCase("redos", {"app.py": _REDOS}),
    SastCase("weak_crypto", {"app.py": _WEAK_CRYPTO}),
    SastCase("insecure_random", {"app.py": _INSECURE_RANDOM}),
    SastCase("disabled_tls", {"app.py": _DISABLED_TLS}),
    SastCase("archive_extract", {"app.py": _ARCHIVE_EXTRACT}),
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


def semgrep_available() -> bool:
    """Whether the ``semgrep`` CLI can be invoked (the M21-forward-referencing comparison).

    Semgrep OSS is the scanner the fusion milestone (M21) re-ranks; this benchmark measures it side
    by side now. Like Bandit it is optional: when absent, the VulnAdvisor side and the
    release-blocking zero-missed gate still run, and the Semgrep column is simply omitted.
    """
    return shutil.which("semgrep") is not None


def _parse_semgrep_results(stdout: str, case: SastCase, root: Path) -> list[Detection]:
    """Defensively parse ``semgrep --json`` output into normalized detections (pure, no I/O).

    Kept separate from the subprocess shell so the (attacker-shaped, externally-produced) JSON
    parsing is unit-testable without Semgrep installed. Anything malformed is skipped, never raised:
    a missing field drops that one result, never the whole run.
    """
    try:
        payload = json.loads(stdout)
    except (ValueError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    detections: list[Detection] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        filename = item.get("path")
        start = item.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        if not isinstance(filename, str) or not isinstance(line, int):
            continue
        try:
            rel = Path(filename).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = Path(filename).name
        extra_raw = item.get("extra")
        extra = extra_raw if isinstance(extra_raw, dict) else {}
        severity = extra.get("severity")
        metadata_raw = extra.get("metadata")
        metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
        detections.append(
            Detection(
                tool=TOOL_SEMGREP,
                file=f"{case.name}/{rel}",
                line=line,
                cwe=_semgrep_cwe(metadata.get("cwe")),
                label=severity if isinstance(severity, str) else "",
            )
        )
    return detections


def _semgrep_cwe(raw: object) -> str:
    """Extract a ``CWE-NNN`` id from Semgrep's ``metadata.cwe`` (free text, a list or a scalar).

    Best-effort: Semgrep states the CWE as free text; we only need the numeric id, and a missing or
    unrecognized value degrades to ``""`` (the metric matches on file/line, not CWE).
    """
    candidates = raw if isinstance(raw, list) else [raw]
    for entry in candidates:
        if isinstance(entry, str):
            match = re.search(r"CWE-\d+", entry)
            if match is not None:
                return match.group(0)
    return ""


def _semgrep_detections(case: SastCase, root: Path) -> list[Detection]:
    """Run Semgrep over ``root`` (auto-config, JSON output) and normalize its results.

    Defensive: Semgrep exits non-zero on findings or config issues; only an unparseable payload or a
    launch failure yields no detections. The ``--config auto`` ruleset is the free community pack.
    """
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["semgrep", "--config", "auto", "--json", "-q", str(root)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return _parse_semgrep_results(result.stdout, case, root)


def run_sast_corpus(
    corpus: Sequence[SastCase] = CORPUS, *, run_bandit: bool = True, run_semgrep: bool = True
) -> SastBenchmarkReport:
    """Materialize and analyze every corpus case, returning the aggregated benchmark report.

    Each case runs in its own temp directory (isolation preserves the ground truth). VulnAdvisor
    always runs; Bandit runs when ``run_bandit`` is set and the CLI is available; Semgrep OSS runs
    when ``run_semgrep`` is set and it is installed. Both comparators are optional — their columns
    are simply omitted when absent, and the release-blocking gate is VulnAdvisor's alone.
    """
    have_bandit = run_bandit and bandit_available()
    have_semgrep = run_semgrep and semgrep_available()
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
            if have_semgrep:
                detections.extend(_semgrep_detections(case, root))
    return build_sast_report(
        seeds, detections, bandit_available=have_bandit, semgrep_available=have_semgrep
    )
