"""Framework plugins that expose framework-registered callables as call-graph entry points."""

from vulnadvisor.callgraph.frameworks.base import (
    EntryPoint,
    FrameworkPlugin,
    collect_entry_points,
    entry_point_names,
)
from vulnadvisor.callgraph.frameworks.celery import CeleryPlugin
from vulnadvisor.callgraph.frameworks.django import DjangoPlugin
from vulnadvisor.callgraph.frameworks.fastapi import FastAPIPlugin
from vulnadvisor.callgraph.frameworks.flask import FlaskPlugin

# The plugins enabled by default. A scan may pass its own list (e.g. to disable one) for isolation.
# Breadth matters for soundness: a missed entry point is a catastrophic false negative, so we root
# the graph at FastAPI/Flask routes, Django views + signals, and Celery tasks. Over-rooting only
# adds reported paths, never hides one.
DEFAULT_PLUGINS: tuple[FrameworkPlugin, ...] = (
    FastAPIPlugin(),
    FlaskPlugin(),
    DjangoPlugin(),
    CeleryPlugin(),
)

__all__ = [
    "DEFAULT_PLUGINS",
    "CeleryPlugin",
    "DjangoPlugin",
    "EntryPoint",
    "FastAPIPlugin",
    "FlaskPlugin",
    "FrameworkPlugin",
    "collect_entry_points",
    "entry_point_names",
]
