"""Fixture B: declares PyYAML but never imports it -> NOT_IMPORTED (confidently safe)."""

import os


def cwd():
    return os.getcwd()
