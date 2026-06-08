"""Framework plugins that expose framework-registered callables as call-graph entry points."""

from vulnadvisor.callgraph.frameworks.base import (
    EntryPoint,
    FrameworkPlugin,
    collect_entry_points,
    entry_point_names,
)
from vulnadvisor.callgraph.frameworks.django import DjangoPlugin
from vulnadvisor.callgraph.frameworks.fastapi import FastAPIPlugin

# The plugins enabled by default. A scan may pass its own list (e.g. to disable one) for isolation.
DEFAULT_PLUGINS: tuple[FrameworkPlugin, ...] = (FastAPIPlugin(), DjangoPlugin())

__all__ = [
    "DEFAULT_PLUGINS",
    "DjangoPlugin",
    "EntryPoint",
    "FastAPIPlugin",
    "FrameworkPlugin",
    "collect_entry_points",
    "entry_point_names",
]
