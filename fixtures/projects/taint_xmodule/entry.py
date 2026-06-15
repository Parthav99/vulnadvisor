"""Cross-module taint fixture (Task 20.2): entry points whose flows cross file boundaries.

Each route seeds taint from an HTTP parameter and passes it to a callable defined in *another*
module. The taint engine must follow the imported callable into its owner file and escalate the
sink there — proving the differentiator spans the whole project, not one file. The sanitized and
not-reachable routes prove soundness in both directions (a cross-module sanitizer clears; an
untainted cross-module call never becomes CONFIRMED).
"""

import os

from fastapi import FastAPI

from helpers import orphan, run_cmd, wrap1
from pkg import reexported_sink
from safe import sanitize
from service import Service

app = FastAPI()


@app.get("/direct")
def r_direct(cmd):
    # cross-module direct: tainted param -> helpers.run_cmd -> os.system (sink in helpers.py).
    run_cmd(cmd)


@app.get("/reexport")
def r_reexport(cmd):
    # via re-export: pkg/__init__ re-exports pkg.impl.reexported_sink (sink in pkg/impl.py).
    reexported_sink(cmd)


@app.get("/wrapper")
def r_wrapper(cmd):
    # via wrapper chain: helpers.wrap1 -> deeper.wrap2 -> os.system (sink in deeper.py).
    wrap1(cmd)


@app.get("/sanitized")
def r_sanitized(cmd):
    # sanitized in another module: safe.sanitize wraps shlex.quote, so CWE-78 is cleared here.
    os.system(sanitize(cmd))


@app.get("/method")
def r_method(cmd):
    # class-method across modules: Service().run sinks the tainted value (sink in service.py).
    Service().run(cmd)


@app.get("/orphan")
def r_orphan(cmd):
    # not-reachable-across-modules: orphan is called with a literal, never the tainted param, so
    # its sink stays POSSIBLE_FLOW and is never escalated to CONFIRMED.
    orphan("ls -la")
