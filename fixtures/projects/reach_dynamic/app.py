"""Fixture C: imports PyYAML dynamically -> DYNAMIC_UNKNOWN (must not be marked safe)."""

import importlib


def load_parser(name="yaml"):
    return importlib.import_module(name)
