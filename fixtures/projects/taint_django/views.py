"""Django views for the cross-file taint fixture: the route is declared in ``urls.py``.

``ConfigView`` is a class-based view; ``run_report`` is a function view. Neither is decorated, so
the only way the taint engine knows they are entry points is the project-wide URLconf collection —
this fixture proves cross-file rooting (a view defined here, routed in a sibling file).
"""

import os
import subprocess

from django.views import View


class ConfigView(View):
    def post(self, request, target):
        # target is a path parameter -> tainted; shell command injection (CWE-78).
        os.system("backup " + target)


def run_report(request, name):
    # Cross-function flow: the tainted view param reaches the sink through a helper.
    cmd = _make_cmd(name)
    subprocess.run(cmd, shell=True)


def _make_cmd(part):
    return "report --for " + part
