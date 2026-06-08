"""A vulnerable call reached only through a FastAPI route handler.

``read_config`` is dispatched by FastAPI on request, never from module top-level. Without framework
awareness the path can't be rooted at the handler; the FastAPI plugin makes ``read_config`` a
call-graph root so the path is read_config -> _load -> yaml.load.
"""

import yaml
from fastapi import FastAPI

app = FastAPI()


@app.post("/config")
def read_config(raw: str):
    return _load(raw)


def _load(raw):
    return yaml.load(raw)
