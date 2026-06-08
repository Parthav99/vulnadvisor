"""Fixture A: imports the (vulnerable) PyYAML package -> IMPORTED."""

import yaml


def load(text):
    return yaml.safe_load(text)
