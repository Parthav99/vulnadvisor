"""Remediation command templating (shared by terminal, JSON, and SARIF output).

Lives here (not in ``cli``) so the machine-output emitters can reuse it without importing the
CLI. The command upgrades to the resolved minimal safe version and is shaped for the dependency's
manifest type (pip / poetry / pipenv).
"""

from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.safe_fix import SafeFix

__all__ = ["fix_command"]


def fix_command(dependency: Dependency, safe_fix: SafeFix) -> str | None:
    """Return the exact upgrade command to the minimal safe version, or ``None`` if no fix.

    The command pins to ``>=<fixed_version>`` and matches the dependency's manifest type.
    """
    if not safe_fix.has_fix or safe_fix.fixed_version is None:
        return None
    name = dependency.raw_name or dependency.name
    target = f'"{name}>={safe_fix.fixed_version}"'
    if dependency.source is DependencySource.POETRY_LOCK:
        return f"poetry add {target}"
    if dependency.source is DependencySource.PIPFILE_LOCK:
        return f"pipenv install {target}"
    return f"pip install --upgrade {target}"
