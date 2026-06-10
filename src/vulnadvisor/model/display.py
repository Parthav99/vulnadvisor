"""Canonical, CVE-first display identity for advisories and findings.

One display rule for every surface (terminal, JSON, SARIF, PR comments, dashboard): show the
lowest-numbered CVE alias when one exists, then a GHSA id, then a PYSEC id, then the raw advisory
id. Display contexts never use ``==`` between package and version (``==`` is reserved for fix
commands).

Both helpers are pure; :func:`select_display_id` is defensive against malformed alias lists
(non-strings and junk identifiers are skipped, never raised on) so it is safe to call on
externally-sourced data.
"""

import re
from collections.abc import Iterable

from vulnadvisor.model.advisory import Advisory
from vulnadvisor.model.score import ScoredFinding

__all__ = ["display_id", "display_title", "select_display_id"]

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
_PYSEC_RE = re.compile(r"^PYSEC-\d{4}-\d+$", re.IGNORECASE)


def select_display_id(advisory_id: str, aliases: Iterable[object]) -> str:
    """Choose the canonical display identifier from a raw advisory id and its aliases.

    Order of preference: lowest-numbered CVE (by year, then number) among the id and aliases,
    then the first GHSA id, then the first PYSEC id, then the raw ``advisory_id``. Non-string or
    malformed alias entries are ignored.
    """
    candidates = [advisory_id, *(a for a in aliases if isinstance(a, str))]
    candidates = [c.strip() for c in candidates if c and c.strip()]

    cves: list[tuple[int, int, str]] = []
    for candidate in candidates:
        match = _CVE_RE.match(candidate)
        if match is not None:
            cves.append((int(match.group(1)), int(match.group(2)), candidate.upper()))
    if cves:
        return min(cves)[2]

    for candidate in candidates:
        if _GHSA_RE.match(candidate):
            return candidate
    for candidate in candidates:
        if _PYSEC_RE.match(candidate):
            return candidate
    return advisory_id


def display_id(advisory: Advisory) -> str:
    """The canonical display identifier for an advisory (CVE-first; see module docstring)."""
    return select_display_id(advisory.id, advisory.aliases)


def display_title(finding: ScoredFinding) -> str:
    """The canonical one-line title for a finding: ``CVE-2020-28493 · jinja2 2.11.2``.

    No ``==`` in display contexts; an unpinned dependency renders as ``(unpinned)``.
    """
    dependency = finding.matched.dependency
    version = dependency.version or "(unpinned)"
    return f"{display_id(finding.matched.advisory)} · {dependency.name} {version}"
