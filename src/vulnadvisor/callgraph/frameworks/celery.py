# File: src/vulnadvisor/callgraph/frameworks/celery.py
"""Celery plugin: functions registered as tasks are entry points.

A Celery worker invokes a function decorated ``@app.task`` / ``@celery.task`` / ``@shared_task``
when a message for that task is consumed — the function is never called from your module top-level.
Its arguments are the (attacker-influenceable) task payload, so we root the call graph at it: a
vulnerable symbol used in the task body (directly or via helpers) is reported on a path rooted at
the task, and the SAST engine treats the task's parameters as taint sources.
"""

import ast

from vulnadvisor.callgraph.frameworks.base import EntryPoint

__all__ = ["CeleryPlugin"]


def _is_task_decorator(decorator: ast.expr) -> bool:
    """Whether ``decorator`` registers a Celery task (``@app.task`` / ``@shared_task`` / ...)."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr in {"task", "shared_task"}
    if isinstance(target, ast.Name):
        return target.id == "shared_task"
    return False


class CeleryPlugin:
    """Detects Celery task handlers by their ``@task`` / ``@shared_task`` decorators."""

    name = "celery"

    def entry_points(self, tree: ast.Module, rel: str) -> list[EntryPoint]:
        """Return every function in ``tree`` registered as a Celery task."""
        out: list[EntryPoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if any(_is_task_decorator(decorator) for decorator in node.decorator_list):
                out.append(
                    EntryPoint(
                        file=rel,
                        name=node.name,
                        framework=self.name,
                        reason="Celery task (@task/@shared_task)",
                    )
                )
        return out
