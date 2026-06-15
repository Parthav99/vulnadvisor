"""First-party helpers reached cross-module from ``entry.py``."""

import os

from deeper import wrap2


def run_cmd(c):
    # direct cross-module sink: the caller's tainted argument lands here.
    os.system(c)


def wrap1(c):
    # one hop of the wrapper chain; the real sink is one more module away (deeper.wrap2).
    wrap2(c)


def orphan(c):
    # a real sink, but only ever called with a literal -> stays POSSIBLE_FLOW, never CONFIRMED.
    os.system(c)
