# File: src/vulnadvisor/callgraph/frameworks/flask.py
"""Flask plugin: view functions registered via route decorators are entry points.

Flask dispatches a function decorated ``@app.route("/x")`` / ``@bp.route(...)`` (or the Flask 2
verb shortcuts ``@app.get`` / ``@app.post`` / ...) when a request arrives — it is never called from
your module top-level. We treat any function carrying such a decorator as a call-graph root so a
vulnerable symbol used in the view (directly or via helpers) is reported on a path rooted at the
route. The request data itself is a module-global (``flask.request``), handled as a taint source by
the SAST engine rather than as a parameter.
"""

import ast

from vulnadvisor.callgraph.frameworks.base import EntryPoint

__all__ = ["FlaskPlugin"]

# Flask routing decorators: the generic ``route`` plus the Flask 2 verb shortcuts. ``add_url_rule``
# is an imperative registration we do not chase here (the function is referenced, not decorated).
_ROUTE_ATTRS = frozenset({"route", "get", "post", "put", "patch", "delete", "head", "options"})


def _is_route_decorator(decorator: ast.expr) -> bool:
    """Whether ``decorator`` is a Flask route registration (``@app.route`` / ``@bp.post`` / ...)."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr in _ROUTE_ATTRS


class FlaskPlugin:
    """Detects Flask view handlers by their route decorators."""

    name = "flask"

    def entry_points(self, tree: ast.Module, rel: str) -> list[EntryPoint]:
        """Return every function in ``tree`` carrying a Flask route decorator."""
        out: list[EntryPoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if any(_is_route_decorator(decorator) for decorator in node.decorator_list):
                out.append(
                    EntryPoint(
                        file=rel,
                        name=node.name,
                        framework=self.name,
                        reason="Flask route handler (@…route)",
                    )
                )
        return out
