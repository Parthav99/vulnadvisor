# File: src/vulnadvisor/callgraph/frameworks/django.py
"""Django plugin: views wired in a URLconf and ``@receiver`` signal handlers are entry points.

Django dispatches code two ways we can spot statically:

* **URLconf** — ``path("x/", views.my_view)`` / ``re_path(...)`` register a view callable. The view
  is referenced (``views.my_view``, a bare name, or ``MyView.as_view()``), never called there, so we
  treat the referenced function — or, for class-based views, the class — as a call-graph root.
* **Signals** — a function decorated ``@receiver(post_save, ...)`` is invoked by Django's signal
  dispatcher, so it is an entry point too.

For a class-based view we emit the *class* name; the call-path search roots any of that class's
HTTP-verb methods, since Django dispatches them by request method.
"""

import ast

from vulnadvisor.callgraph.frameworks.base import EntryPoint

__all__ = ["DjangoPlugin"]

_URL_FUNCS = frozenset({"path", "re_path", "url"})


def _callable_name(node: ast.expr) -> str | None:
    """Return the simple name a call/decorator targets (``Name`` id or ``Attribute`` attr)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_receiver(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether ``node`` is decorated with Django's ``@receiver(...)`` signal decorator."""
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _callable_name(target) == "receiver":
            return True
    return False


def _is_url_route(call: ast.Call) -> bool:
    """Whether ``call`` is a URLconf ``path``/``re_path``/``url`` with a view in the second arg."""
    return _callable_name(call.func) in _URL_FUNCS and len(call.args) >= 2


def _view_name(view: ast.expr) -> str | None:
    """Resolve a URLconf view reference to the name to root: function name or view-class name."""
    if isinstance(view, ast.Attribute):
        return view.attr  # views.my_view -> my_view
    if isinstance(view, ast.Name):
        return view.id  # my_view
    if isinstance(view, ast.Call):
        func = view.func
        if isinstance(func, ast.Attribute) and func.attr == "as_view":
            return _callable_name(func.value)  # MyView.as_view() -> MyView
    return None


class DjangoPlugin:
    """Detects Django views (via URLconf ``path``/``re_path``) and ``@receiver`` signal handlers."""

    name = "django"

    def entry_points(self, tree: ast.Module, rel: str) -> list[EntryPoint]:
        """Return Django URL-routed views and signal receivers declared in ``tree``."""
        out: list[EntryPoint] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_receiver(node):
                out.append(
                    EntryPoint(
                        file=rel,
                        name=node.name,
                        framework=self.name,
                        reason="Django signal receiver (@receiver)",
                    )
                )
            elif isinstance(node, ast.Call) and _is_url_route(node):
                name = _view_name(node.args[1])
                if name is not None:
                    out.append(
                        EntryPoint(
                            file=rel,
                            name=name,
                            framework=self.name,
                            reason="Django URLconf view (path/re_path)",
                        )
                    )
        return out
