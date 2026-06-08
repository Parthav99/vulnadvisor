# File: src/vulnadvisor/callgraph/frameworks/fastapi.py
"""FastAPI plugin: route/websocket handlers registered via decorators are entry points.

FastAPI dispatches a function decorated ``@app.get("/x")`` / ``@router.post(...)`` /
``@app.websocket(...)`` when a request arrives — it is never called from your module top-level. We
treat any function carrying such a decorator as a call-graph root so a vulnerable symbol used in the
handler (directly or via helpers) is reported on a path rooted at the route.
"""

import ast

from vulnadvisor.callgraph.frameworks.base import EntryPoint

__all__ = ["FastAPIPlugin"]

# FastAPI's routing decorators (also covers APIRouter and the generic ``route``/``api_route``).
_ROUTE_METHODS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
        "websocket",
        "route",
        "api_route",
    }
)


def _route_method(decorator: ast.expr) -> str | None:
    """Return the HTTP method if ``decorator`` is a FastAPI route decorator, else ``None``."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute) and target.attr in _ROUTE_METHODS:
        return target.attr
    return None


class FastAPIPlugin:
    """Detects FastAPI route handlers by their routing decorators."""

    name = "fastapi"

    def entry_points(self, tree: ast.Module, rel: str) -> list[EntryPoint]:
        """Return every function in ``tree`` carrying a FastAPI routing decorator."""
        out: list[EntryPoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for decorator in node.decorator_list:
                method = _route_method(decorator)
                if method is not None:
                    out.append(
                        EntryPoint(
                            file=rel,
                            name=node.name,
                            framework=self.name,
                            reason=f"FastAPI route handler (@…{method})",
                        )
                    )
                    break
        return out
