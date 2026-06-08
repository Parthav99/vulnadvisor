"""Remediation command templating (shared by terminal, JSON, and SARIF output).

Lives here (not in ``cli``) so the machine-output emitters can reuse it without importing the
CLI. The exact minimal-upgrade target arrives in Task 3.2; this is a templated upgrade for now.
"""

from vulnadvisor.model.dependency import Dependency, DependencySource

__all__ = ["fix_command"]


def fix_command(dependency: Dependency) -> str:
    """Return a templated upgrade command appropriate to the dependency's manifest type."""
    name = dependency.raw_name or dependency.name
    if dependency.source is DependencySource.POETRY_LOCK:
        return f"poetry update {name}"
    if dependency.source is DependencySource.PIPFILE_LOCK:
        return f"pipenv update {name}"
    return f"pip install --upgrade {name}"
