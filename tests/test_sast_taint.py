"""Taint-propagation tests (Task 16.3): source->sink flow proof, tiers, evidence, soundness.

Covers the design's required fixture set (docs/sast-design.md §12): direct flow, cross-function,
sanitized, *partially* sanitized, dynamic-blocked, framework-routed (FastAPI/Flask/Django/Celery),
and not-reachable-from-entry-point — across the v1 CWE set. The release-blocking invariant is
**zero missed flows**: every genuinely-reachable sink escalates, and a partial sanitizer never
clears a real sink.
"""

import time
from pathlib import Path

from vulnadvisor.sast import SastTier, analyze_source, analyze_taint
from vulnadvisor.sast.model import SastFinding

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
SRC = REPO / "src"
PROJECTS = FIXTURES / "projects"


def _findings(source: str, rel: str = "m.py") -> tuple[SastFinding, ...]:
    return analyze_source(source, rel)


def _one(source: str) -> SastFinding:
    findings = _findings(source)
    assert len(findings) == 1, [(f.kind, f.tier, f.callee) for f in findings]
    return findings[0]


# --- direct flow (one per source kind) ------------------------------------------------------


def test_direct_flow_fastapi_param() -> None:
    f = _one(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    os.system(cmd)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.cwe == "CWE-78"
    assert f.source_kind == "http-parameter"
    assert f.flow is not None
    assert f.flow.render() == "r -> os.system (m.py:6)"


def test_direct_flow_argv() -> None:
    f = _one("import os, sys\ndef main():\n    os.system(sys.argv[1])\n")
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "argv"


def test_direct_flow_environment() -> None:
    f = _one("import os\ndef main():\n    os.system(os.environ['CMD'])\n")
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "environment"


def test_direct_flow_environment_getenv() -> None:
    f = _one("import os\ndef main():\n    os.system(os.getenv('CMD'))\n")
    assert f.source_kind == "environment"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_direct_flow_stdin_input() -> None:
    f = _one("import os\ndef main():\n    os.system(input())\n")
    assert f.source_kind == "stdin"
    assert f.tier is SastTier.CONFIRMED_FLOW


# --- cross-function -------------------------------------------------------------------------


def test_cross_function_flow_through_helper_return() -> None:
    f = _one(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def build(x):\n"
        "    return 'run ' + x\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    os.system(build(cmd))\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_cross_function_sink_inside_helper() -> None:
    # The sink lives in the callee; taint enters via the passed argument.
    f = _one(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def sink(c):\n"
        "    os.system(c)\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    sink(cmd)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "r -> sink -> os.system (m.py:5)"


# --- sanitized / partially sanitized --------------------------------------------------------


def test_sanitized_flow_is_not_escalated() -> None:
    # shlex.quote on the value before the sink clears CWE-78 -> no CONFIRMED escalation.
    findings = _findings(
        "import os, shlex\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    safe = shlex.quote(cmd)\n"
        "    os.system(safe)\n"
    )
    assert findings == ()


def test_partial_sanitization_stays_confirmed() -> None:
    # One branch sanitizes, the other does not -> the value is NOT cleared (soundness §4.2).
    f = _one(
        "import os, shlex\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/r')\n"
        "def r(cmd, flag):\n"
        "    if flag:\n"
        "        c = shlex.quote(cmd)\n"
        "    else:\n"
        "        c = cmd\n"
        "    os.system(c)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_sql_sanitizer_does_not_clear_command_injection() -> None:
    # Sanitizers are CWE-scoped: secure_filename clears path traversal, not command injection.
    f = _one(
        "import os\n"
        "from werkzeug.utils import secure_filename\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    os.system(secure_filename(cmd))\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.cwe == "CWE-78"


def test_path_traversal_sanitized_by_secure_filename() -> None:
    findings = _findings(
        "from werkzeug.utils import secure_filename\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/f')\n"
        "def f(name):\n"
        "    open(secure_filename(name))\n"
    )
    assert findings == ()


# --- dynamic-blocked ------------------------------------------------------------------------


def test_dynamic_dispatch_blocks_certainty() -> None:
    # A getattr-dispatched call on the path -> DYNAMIC_UNKNOWN, not CONFIRMED, never dropped.
    f = _one(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/r')\n"
        "def r(name, payload, builders):\n"
        "    cmd = getattr(builders, name)(payload)\n"
        "    os.system(cmd)\n"
    )
    assert f.tier is SastTier.DYNAMIC_UNKNOWN
    assert f.cwe == "CWE-78"


def test_dynamic_never_downgrades_below_possible() -> None:
    # Even through a dynamic hop the tainted value still escalates above POSSIBLE: os.system gets a
    # value built by eval (DYNAMIC_UNKNOWN), while eval itself is a proven CWE-94 sink (CONFIRMED).
    findings = _findings(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/r')\n"
        "def r(blob):\n"
        "    os.system(eval(blob))\n"
    )
    by_cwe = {f.cwe: f.tier for f in findings}
    assert by_cwe["CWE-78"] is SastTier.DYNAMIC_UNKNOWN
    assert by_cwe["CWE-94"] is SastTier.CONFIRMED_FLOW


# --- framework breadth ----------------------------------------------------------------------


def test_flask_request_global_is_a_source() -> None:
    f = _one(
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/r')\n"
        "def r():\n"
        "    os.system(request.args.get('cmd'))\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "flask-request"


def test_celery_task_parameter_is_a_source() -> None:
    f = _one(
        "import os\n"
        "from celery import shared_task\n"
        "@shared_task\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "task-parameter"


def test_flask_verb_decorator_is_an_entry_point() -> None:
    f = _one(
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.post('/r')\n"
        "def r(cmd):\n"
        "    os.system(cmd)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


# --- CWE coverage on confirmed flows --------------------------------------------------------


def test_sqli_confirmed() -> None:
    f = _one(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/u')\n"
        "def u(uid, cursor):\n"
        "    cursor.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )
    assert f.cwe == "CWE-89"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_code_injection_confirmed() -> None:
    f = _one(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/e')\n"
        "def e(expr):\n"
        "    exec(expr)\n"
    )
    assert f.cwe == "CWE-94"
    # exec of a tainted value is the sink itself -> a proven flow, not a blocked one.
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_unsafe_deserialization_confirmed() -> None:
    f = _one(
        "import pickle\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/d')\n"
        "def d(blob):\n"
        "    pickle.loads(blob)\n"
    )
    assert f.cwe == "CWE-502"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_ssrf_confirmed_via_url_keyword() -> None:
    f = _one(
        "import requests\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/p')\n"
        "def p(target):\n"
        "    requests.get(url=target)\n"
    )
    assert f.cwe == "CWE-918"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_path_traversal_confirmed() -> None:
    f = _one(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/f')\n"
        "def f(name):\n"
        "    open('/data/' + name)\n"
    )
    assert f.cwe == "CWE-22"
    assert f.tier is SastTier.CONFIRMED_FLOW


# --- not reachable from an entry point ------------------------------------------------------


def test_not_reachable_yields_no_escalation() -> None:
    # A non-literal sink in a helper never reached from a source -> no CONFIRMED escalation.
    assert _findings("import os\ndef helper(cmd):\n    os.system(cmd)\n") == ()


def test_local_non_source_value_is_not_confirmed() -> None:
    # The argument is non-literal but not source-derived -> stays out of the escalation set.
    assert (
        _findings(
            "import os\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/r')\n"
            "def r():\n"
            "    base = compute()\n"
            "    os.system(base)\n"
        )
        == ()
    )


# --- Task 20.1: container & data-structure taint --------------------------------------------

_ENTRY = "import os\nfrom fastapi import FastAPI\napp = FastAPI()\n"


def _route(body: str, *, imports: str = "") -> str:
    """A FastAPI route whose parameters are taint sources, wrapping ``body`` (4-space indented)."""
    sig = "def r(cmd):\n"
    return f"{_ENTRY}{imports}@app.get('/r')\n{sig}{body}"


def test_container_list_append_to_sink() -> None:
    f = _one(_route("    parts = []\n    parts.append(cmd)\n    os.system(parts[0])\n"))
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.cwe == "CWE-78"


def test_container_list_extend_to_sink() -> None:
    f = _one(
        _ENTRY + "@app.get('/r')\n"
        "def r(args):\n"
        "    cmds = []\n"
        "    cmds.extend(args)\n"
        "    os.system(cmds[0])\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_dict_value_to_sink() -> None:
    f = _one(_route("    d = {}\n    d['k'] = cmd\n    os.system(d['k'])\n"))
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_dict_update_to_sink() -> None:
    f = _one(
        _ENTRY + "@app.get('/r')\n"
        "def r(extra):\n"
        "    cfg = {}\n"
        "    cfg.update(extra)\n"
        "    os.system(cfg['cmd'])\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_set_add_to_sink() -> None:
    f = _one(_route("    s = set()\n    s.add(cmd)\n    for v in s:\n        os.system(v)\n"))
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_comprehension_sink_on_element() -> None:
    # The sink consumes the comprehension loop variable bound to a tainted iterable.
    f = _one(_ENTRY + "@app.get('/r')\ndef r(items):\n    [os.system(x) for x in items]\n")
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_comprehension_result_to_sink() -> None:
    f = _one(
        _ENTRY + "@app.get('/r')\n"
        "def r(names):\n"
        "    cmds = [n for n in names]\n"
        "    os.system(cmds[0])\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_container_tuple_unpack_to_sink() -> None:
    f = _one(_ENTRY + "@app.get('/r')\ndef r(pair):\n    a, b = pair\n    os.system(a)\n")
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_string_join_to_sink() -> None:
    f = _one(_ENTRY + "@app.get('/r')\ndef r(args):\n    os.system(' '.join(args))\n")
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_os_path_join_to_sink() -> None:
    f = _one(_ENTRY + "@app.get('/f')\ndef f(name):\n    open(os.path.join('/data', name))\n")
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.cwe == "CWE-22"


def test_nested_container_to_sink() -> None:
    f = _one(_route("    d = {}\n    d['x'] = [cmd]\n    os.system(d['x'][0])\n"))
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_sanitized_in_container_is_not_escalated() -> None:
    # shlex.quote survives the container round-trip -> CWE-78 stays cleared, no escalation.
    findings = _findings(
        _route(
            "    parts = []\n    parts.append(shlex.quote(cmd))\n    os.system(parts[0])\n",
            imports="import shlex\n",
        )
    )
    assert findings == ()


def test_dynamic_index_is_blocked_not_dropped() -> None:
    # A dynamic value stored in and read from a container keeps its dynamic flag -> DYNAMIC_UNKNOWN,
    # never silently cleared.
    f = _one(
        _ENTRY + "@app.get('/r')\n"
        "def r(name, payload, builders):\n"
        "    params = {}\n"
        "    params['cmd'] = getattr(builders, name)(payload)\n"
        "    os.system(params['cmd'])\n"
    )
    assert f.tier is SastTier.DYNAMIC_UNKNOWN
    assert f.cwe == "CWE-78"


def test_clean_container_yields_no_escalation() -> None:
    # A literal element appended to a container is not tainted -> no escalation (soundness floor).
    assert (
        _findings(
            _ENTRY + "@app.get('/r')\n"
            "def r():\n"
            "    parts = []\n"
            "    parts.append('ls')\n"
            "    os.system(parts[0])\n"
        )
        == ()
    )


# --- object / attribute & class-state taint (Task 20.3) -------------------------------------


def test_constructor_param_taints_field_to_sink() -> None:
    # __init__ stores a tainted param on self.cmd; a later method reads self.cmd into a sink.
    f = _one(
        _ENTRY + "class Svc:\n"
        "    def __init__(self, c):\n"
        "        self.cmd = c\n"
        "    def run(self):\n"
        "        os.system(self.cmd)\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    s = Svc(cmd)\n"
        "    s.run()\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.cwe == "CWE-78"
    assert f.flow is not None
    assert f.flow.render() == "r -> Svc.run -> os.system (m.py:8)"


def test_self_attr_set_then_get_within_method() -> None:
    # attr set -> get -> sink within one method, reached by constructing and calling the instance.
    f = _one(
        _ENTRY + "class Svc:\n"
        "    def handle(self, c):\n"
        "        self.cmd = c\n"
        "        os.system(self.cmd)\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    Svc().handle(cmd)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_dataclass_field_taints_to_sink() -> None:
    # Constructing a dataclass maps the tainted argument onto its first field; reading it sinks.
    f = _one(
        "import os\n"
        "from dataclasses import dataclass\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@dataclass\n"
        "class Cmd:\n"
        "    value: str\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    box = Cmd(cmd)\n"
        "    os.system(box.value)\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_non_constructor_setter_writes_back_to_instance() -> None:
    # configure() sets self.data; a later run() on the same variable reads it into the sink.
    f = _one(
        _ENTRY + "class Svc:\n"
        "    def configure(self, v):\n"
        "        self.data = v\n"
        "    def run(self):\n"
        "        os.system(self.data)\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    s = Svc()\n"
        "    s.configure(cmd)\n"
        "    s.run()\n"
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_setattr_dynamic_attribute_is_blocked_not_dropped() -> None:
    # The attribute name is computed -> the object is tainted dynamically -> DYNAMIC_UNKNOWN, never
    # CONFIRMED and never silently clean.
    f = _one(
        _ENTRY + "class Box:\n"
        "    pass\n"
        "@app.get('/r')\n"
        "def r(cmd):\n"
        "    b = Box()\n"
        "    setattr(b, 'x', cmd)\n"
        "    os.system(b.x)\n"
    )
    assert f.tier is SastTier.DYNAMIC_UNKNOWN


def test_literal_constructed_field_yields_no_escalation() -> None:
    # Soundness floor: a field set from a literal constructor argument is never tainted.
    assert (
        _findings(
            _ENTRY + "class Svc:\n"
            "    def __init__(self, c):\n"
            "        self.cmd = c\n"
            "    def run(self):\n"
            "        os.system(self.cmd)\n"
            "@app.get('/r')\n"
            "def r(cmd):\n"
            "    Svc('ls').run()\n"
        )
        == ()
    )


# --- object / class-state taint across files (Task 20.3 fixture project) --------------------


def _xobject() -> dict[tuple[str, int], SastFinding]:
    return {(f.file, f.line): f for f in analyze_taint(PROJECTS / "taint_object")}


def test_xobject_intra_method_attr_set_get_sink() -> None:
    # Django CBV: self.cmd = request param, then os.system(self.cmd) within the same method.
    f = _xobject()[("views.py", 23)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "http-parameter"


def test_xobject_constructor_taint_across_files_and_methods() -> None:
    # run_view -> Service(raw) (__init__ stores self.cmd) -> svc.execute() sinks self.cmd.
    f = _xobject()[("models.py", 18)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "run_view -> Service.execute -> os.system (models.py:18)"


def test_xobject_dataclass_field() -> None:
    f = _xobject()[("views.py", 35)]
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_xobject_setter_method_writeback() -> None:
    # setter_view -> obj.configure(raw) writes self.data -> obj.run() sinks it.
    f = _xobject()[("models.py", 27)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "setter_view -> Mutable.run -> os.system (models.py:27)"


def test_xobject_dynamic_setattr_is_dynamic_unknown() -> None:
    f = _xobject()[("views.py", 50)]
    assert f.tier is SastTier.DYNAMIC_UNKNOWN


def test_xobject_negatives_stay_possible() -> None:
    # The literal-field and never-tainted-field reads must NOT escalate (no flow is invented).
    by_loc = _xobject()
    assert by_loc[("views.py", 57)].tier is SastTier.POSSIBLE_FLOW
    assert by_loc[("views.py", 63)].tier is SastTier.POSSIBLE_FLOW


def test_xobject_zero_missed_object_flows() -> None:
    # Release-blocking soundness: exactly the genuinely reachable object-state sinks are CONFIRMED.
    by_loc = _xobject()
    confirmed = {loc for loc, f in by_loc.items() if f.tier is SastTier.CONFIRMED_FLOW}
    assert confirmed == {
        ("views.py", 23),
        ("views.py", 35),
        ("models.py", 18),
        ("models.py", 27),
    }


def test_xobject_deterministic() -> None:
    assert analyze_taint(PROJECTS / "taint_object") == analyze_taint(PROJECTS / "taint_object")


# --- merge semantics over a real project (analyze_taint) ------------------------------------


def test_mixed_project_merges_baseline_and_escalations() -> None:
    by_loc = {(f.file, f.line): f for f in analyze_taint(PROJECTS / "taint_mixed")}
    confirmed = by_loc[("app.py", 19)]
    assert confirmed.tier is SastTier.CONFIRMED_FLOW
    assert confirmed.flow is not None
    # Sanitized flow stays SANITIZED; the orphan helper stays POSSIBLE_FLOW (never CONFIRMED).
    assert by_loc[("app.py", 25)].tier is SastTier.SANITIZED
    assert by_loc[("app.py", 31)].tier is SastTier.POSSIBLE_FLOW


def test_cross_file_django_routing() -> None:
    findings = analyze_taint(PROJECTS / "taint_django")
    confirmed = [f for f in findings if f.tier is SastTier.CONFIRMED_FLOW]
    # Both the class-based view method and the function view (routed in urls.py) escalate.
    assert {f.callee for f in confirmed} == {"os.system", "subprocess.run"}
    assert all(f.flow is not None for f in confirmed)


def test_no_confirmed_flow_is_dropped_below_possible() -> None:
    # Soundness: nothing in the mixed project that is a real sink reads as clean/missing.
    findings = analyze_taint(PROJECTS / "taint_mixed")
    assert all(f.tier is not SastTier.SANITIZED or f.callee == "os.system" for f in findings)
    assert len(findings) == 3


# --- cross-module / cross-file taint (Task 20.2) --------------------------------------------


def _xmodule() -> dict[tuple[str, int], SastFinding]:
    return {(f.file, f.line): f for f in analyze_taint(PROJECTS / "taint_xmodule")}


def test_xmodule_direct_flow_into_imported_helper() -> None:
    # A tainted entry-point param flows into a sink in *another* module via ``from helpers import``.
    f = _xmodule()[("helpers.py", 10)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.source_kind == "http-parameter"
    assert f.flow is not None
    assert f.flow.render() == "r_direct -> run_cmd -> os.system (helpers.py:10)"


def test_xmodule_flow_via_reexport() -> None:
    # ``from pkg import reexported_sink`` resolves through pkg/__init__'s ``from .impl import``.
    f = _xmodule()[("pkg/impl.py", 8)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "r_reexport -> reexported_sink -> os.system (pkg/impl.py:8)"


def test_xmodule_flow_via_wrapper_chain() -> None:
    # Two module hops: entry -> helpers.wrap1 -> deeper.wrap2 -> os.system.
    f = _xmodule()[("deeper.py", 8)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "r_wrapper -> wrap1 -> wrap2 -> os.system (deeper.py:8)"


def test_xmodule_sanitized_in_another_module_is_not_confirmed() -> None:
    # safe.sanitize() wraps shlex.quote; the cleared CWE crosses the boundary, so the entry sink
    # stays POSSIBLE_FLOW (never escalated). Soundness: a real partial sanitizer is honored.
    f = _xmodule()[("entry.py", 43)]
    assert f.tier is SastTier.POSSIBLE_FLOW


def test_xmodule_class_method_across_modules() -> None:
    # ``Service().run(tainted)`` — instance method resolved in another module, self skipped.
    f = _xmodule()[("service.py", 9)]
    assert f.tier is SastTier.CONFIRMED_FLOW
    assert f.flow is not None
    assert f.flow.render() == "r_method -> Service.run -> os.system (service.py:9)"


def test_xmodule_not_reachable_stays_possible() -> None:
    # The orphan helper is only called with a literal, never the tainted param -> not CONFIRMED.
    f = _xmodule()[("helpers.py", 20)]
    assert f.tier is SastTier.POSSIBLE_FLOW


def test_xmodule_zero_missed_cross_module_flows() -> None:
    # Release-blocking soundness: every genuinely reachable cross-module sink is CONFIRMED.
    by_loc = _xmodule()
    confirmed = {loc for loc, f in by_loc.items() if f.tier is SastTier.CONFIRMED_FLOW}
    assert confirmed == {
        ("helpers.py", 10),
        ("pkg/impl.py", 8),
        ("deeper.py", 8),
        ("service.py", 9),
    }


def test_xmodule_summaries_order_independent_and_deterministic() -> None:
    # Per-function summaries must not depend on module/discovery order: repeated runs are identical.
    assert analyze_taint(PROJECTS / "taint_xmodule") == analyze_taint(PROJECTS / "taint_xmodule")


# --- robustness: whole-tree, determinism, performance ---------------------------------------


def test_runs_over_repo_without_crashing_and_deterministic() -> None:
    first = analyze_taint(SRC)
    second = analyze_taint(SRC)
    assert first == second  # deterministic
    # The analyzer itself must never raise on real code.
    assert isinstance(first, tuple)


def test_runs_over_fixtures_without_crashing() -> None:
    assert isinstance(analyze_taint(FIXTURES), tuple)


def test_malformed_source_returns_empty() -> None:
    assert analyze_source("def (:\n  bad syntax", "m.py") == ()


def test_performance_budget_under_10s() -> None:
    start = time.perf_counter()
    analyze_taint(SRC)
    elapsed = time.perf_counter() - start
    assert elapsed < 10.0, f"taint pass took {elapsed:.2f}s (budget 10s)"
