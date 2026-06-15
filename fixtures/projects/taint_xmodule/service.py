"""A class whose method is the sink, invoked cross-module as ``Service().run(tainted)``."""

import os


class Service:
    def run(self, c):
        # instance-method sink reached across modules via an inline construction.
        os.system(c)
