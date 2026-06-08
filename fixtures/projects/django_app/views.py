"""A vulnerable call reached only through a Django view (wired up in urls.py).

``parse_config`` is dispatched by Django's URL resolver, never from module top-level. The Django
plugin reads urls.py, learns ``parse_config`` is a routed view, and roots the call-graph there so
the path is parse_config -> _load -> yaml.load.
"""

import yaml


def parse_config(request):
    return _load(request.body)


def _load(raw):
    return yaml.load(raw)
