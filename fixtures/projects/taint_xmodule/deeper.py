"""The far end of the cross-module wrapper chain (entry -> helpers.wrap1 -> deeper.wrap2)."""

import os


def wrap2(c):
    # the sink at the end of a two-module wrapper chain.
    os.system(c)
