"""Reaches yaml via reflection -> DYNAMIC_UNKNOWN (must not be marked not-called)."""

import yaml


def run(func_name, data):
    func = getattr(yaml, func_name)
    return func(data)
