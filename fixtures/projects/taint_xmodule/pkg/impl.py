"""Implementation module behind the package re-export; holds the actual sink."""

import os


def reexported_sink(c):
    # reached via ``from pkg import reexported_sink`` (re-export chain through pkg/__init__).
    os.system(c)
