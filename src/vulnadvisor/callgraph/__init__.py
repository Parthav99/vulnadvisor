"""Callgraph: AST import graph, demand-driven call paths, and type-informed resolution."""

from vulnadvisor.callgraph.call_paths import (
    CallGraphResult,
    PackageReflection,
    find_vulnerable_call_paths,
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
    "CallGraphResult",
    "NullResolver",
    "PackageReflection",
    "PyrightResolver",
    "TypeResolver",
    "build_import_graph",
    "find_vulnerable_call_paths",
    "map_imports_to_distributions",
]
