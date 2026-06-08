"""Module exercising aliases, from-imports, and dynamic imports."""

import importlib
import os
import os.path as osp

import numpy as np
from collections import OrderedDict
from yaml import safe_load


def load(name):
    """Dynamically import a module by name."""
    return importlib.import_module(name)


def boot():
    """Use a few dynamic-execution constructs."""
    mod = __import__("json")
    eval("2 + 2")
    exec("y = 1")
    return mod, osp, np, OrderedDict, safe_load, os
