"""Resolve the minimal safe-fix version for a vulnerable dependency.

Given an advisory's fixed versions and the installed version, we recommend the **smallest fixed
version greater than the installed one** — the nearest non-vulnerable upgrade. This is pure,
deterministic version math (PEP 440 via ``packaging``); no I/O.

We flag two cases the caller must surface honestly:
* **No fix** — the advisory advertises no fixed version above the installed one.
* **Major jump** — the fix crosses a major version boundary and may be breaking.
"""

from packaging.version import InvalidVersion, Version

from vulnadvisor.model.advisory import Advisory
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.model.safe_fix import SafeFix

__all__ = ["resolve_safe_fix"]


def _parse_version(value: str | None) -> Version | None:
    """Parse a PEP 440 version, returning ``None`` for missing/invalid input."""
    if not value:
        return None
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _fixed_versions(dependency: Dependency, advisory: Advisory) -> list[Version]:
    """Collect the valid fixed versions for ``dependency`` from the advisory's affected ranges."""
    matching = [pkg for pkg in advisory.affected if pkg.name == dependency.name]
    packages = matching or list(advisory.affected)
    versions: list[Version] = []
    for package in packages:
        for affected_range in package.ranges:
            parsed = _parse_version(affected_range.fixed)
            if parsed is not None:
                versions.append(parsed)
    return versions


def resolve_safe_fix(dependency: Dependency, advisory: Advisory) -> SafeFix:
    """Resolve the nearest non-vulnerable upgrade for ``dependency`` per ``advisory``."""
    current = _parse_version(dependency.version)
    fixed = sorted(set(_fixed_versions(dependency, advisory)))
    available = tuple(str(v) for v in fixed)

    if not fixed:
        return SafeFix(
            current_version=dependency.version,
            fixed_version=None,
            has_fix=False,
            is_major_jump=False,
            available_fixes=(),
            note="No fixed version is available yet; monitor the advisory and apply mitigations.",
        )

    if current is not None:
        candidates = [v for v in fixed if v > current]
        recommended = candidates[0] if candidates else None
    else:
        recommended = fixed[0]

    if recommended is None:
        return SafeFix(
            current_version=dependency.version,
            fixed_version=None,
            has_fix=False,
            is_major_jump=False,
            available_fixes=available,
            note="No fixed version above the installed version was found.",
        )

    is_major_jump = current is not None and recommended.major > current.major
    if is_major_jump:
        note = (
            f"Minimal safe upgrade is {recommended}, a major-version jump from "
            f"{current} - may include breaking changes."
        )
    else:
        note = f"Minimal safe upgrade: {recommended}."

    return SafeFix(
        current_version=dependency.version,
        fixed_version=str(recommended),
        has_fix=True,
        is_major_jump=is_major_jump,
        available_fixes=available,
        note=note,
    )
