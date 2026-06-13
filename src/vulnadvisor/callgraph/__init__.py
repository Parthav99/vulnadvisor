"""Callgraph: AST import graph, demand-driven call paths, and type-informed resolution."""

from vulnadvisor.callgraph.call_paths import (
    CallGraphResult,
    PackageReflection,
    find_vulnerable_call_paths,
)
from vulnadvisor.callgraph.frameworks import (
    DEFAULT_PLUGINS,
    CeleryPlugin,
    DjangoPlugin,
    EntryPoint,
    FastAPIPlugin,
    FlaskPlugin,
    FrameworkPlugin,
    collect_entry_points,
    entry_point_names,
)
from vulnadvisor.callgraph.import_graph import (
    build_import_graph,
    map_imports_to_distributions,
)
from vulnadvisor.callgraph.type_resolver import (
    NullResolver,
    PyrightResolver,
    TypeResolver,
)

__all__ = [
    "DEFAULT_PLUGINS",
    "CallGraphResult",
    "CeleryPlugin",
    "DjangoPlugin",
    "EntryPoint",
    "FastAPIPlugin",
    "FlaskPlugin",
    "FrameworkPlugin",
    "NullResolver",
    "PackageReflection",
    "PyrightResolver",
    "TypeResolver",
    "build_import_graph",
    "collect_entry_points",
    "entry_point_names",
    "find_vulnerable_call_paths",
    "map_imports_to_distributions",
]
