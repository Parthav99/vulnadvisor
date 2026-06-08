"""Imports yaml but never calls the vulnerable symbol -> IMPORTED (not escalated)."""

import yaml

DEFAULT_LOADER = yaml.SafeLoader


def describe():
    return "yaml is imported but load() is never called here"
