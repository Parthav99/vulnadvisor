"""A FastAPI app mixing a reachable flow, a sanitized flow, and a sink not reachable from any entry.

Used to test the ``analyze_taint`` merge: the entry-routed sink escalates to CONFIRMED_FLOW, the
sanitized one stays out of the escalation set (baseline SANITIZED), and the helper that is never
called from an entry point keeps its intra-procedural POSSIBLE_FLOW — never CONFIRMED.
"""

import os
import shlex

from fastapi import FastAPI

app = FastAPI()


@app.get("/run")
def run(cmd):
    # CONFIRMED: tainted query parameter reaches os.system with no sanitizer.
    os.system(cmd)


@app.get("/safe")
def safe(cmd):
    # SANITIZED: the dangerous argument is shlex.quote'd before the sink.
    os.system(shlex.quote(cmd))


def orphan_helper(cmd):
    # POSSIBLE_FLOW: a non-literal sink argument, but this helper is never reached from an entry
    # point, so taint cannot tie it to a source. Must NOT become CONFIRMED.
    os.system(cmd)
