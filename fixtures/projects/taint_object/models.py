"""The classes whose instance state carries taint for the Task 20.3 fixture.

Defined in a separate module so resolution is cross-file too: the views construct and call these,
and the engine must analyze each class's ``__init__`` / methods to know which fields a tainted
input reaches.
"""

import os
from dataclasses import dataclass


class Service:
    def __init__(self, cmd):
        # constructor parameter stored on a field; read by execute().
        self.cmd = cmd

    def execute(self):
        os.system(self.cmd)


class Mutable:
    def configure(self, value):
        # a non-constructor setter: writes the field that run() later sinks.
        self.data = value

    def run(self):
        os.system(self.data)


class Holder:
    def __init__(self):
        # no tainted field at construction; cmd is only ever set dynamically (setattr).
        self.cmd = "noop"


@dataclass
class Cmd:
    value: str
