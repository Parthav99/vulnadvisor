"""A cross-module sanitizer: returns a shlex-quoted value so the caller's sink is cleared."""

import shlex


def sanitize(c):
    # the return value carries a CWE-78 "cleared" mark across the module boundary.
    return shlex.quote(c)
