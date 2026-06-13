"""Defensive parsing of a coverage.py JSON report into normalized executed-line data.

``coverage json -o coverage.json`` (line *or* branch mode) writes a top-level object::

    {
      "meta": {...},
      "files": {
        "src/app/db.py": {
          "executed_lines": [1, 2, 5, 42],   # present in BOTH line and branch mode
          "missing_lines": [...],
          "summary": {...},
          "executed_branches": [[1, 2], ...]  # branch mode only; we read executed_lines either way
        },
        ...
      },
      "totals": {...}
    }

We read **only** ``executed_lines`` (always present), so the same code path handles line and branch
coverage. Every value is validated and coerced; malformed input raises :class:`CoverageParseError`
(never an unhandled crash, per the CLAUDE.md defensive-parsing rule), and file paths that resolve
outside the scanned project are silently ignored (coverage of third-party code is not our concern).
"""

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CoverageData", "CoverageParseError", "parse_coverage"]


class CoverageParseError(Exception):
    """The supplied coverage report was not a readable coverage.py JSON document."""


@dataclass(frozen=True)
class CoverageData:
    """Normalized executed-line coverage, keyed by project-relative POSIX path.

    A path is present as a key iff the coverage report included that file (so an empty executed set
    means "the suite ran over this file but executed none of these lines"). Paths are normalized to
    match the project-relative POSIX paths VulnAdvisor uses for import sites, call-path steps, and
    sink locations, so overlay lookups are a direct dict hit.
    """

    executed_lines: dict[str, frozenset[int]]

    def covers_file(self, rel_path: str) -> bool:
        """Whether the coverage report included ``rel_path`` (regardless of what executed)."""
        return rel_path in self.executed_lines

    def executed(self, rel_path: str) -> frozenset[int]:
        """The set of executed line numbers for ``rel_path`` (empty if absent or none ran)."""
        return self.executed_lines.get(rel_path, frozenset())

    @property
    def file_count(self) -> int:
        """Number of project files present in the coverage report."""
        return len(self.executed_lines)


def _coerce_executed_lines(entry: dict[str, object]) -> frozenset[int]:
    """Pull a clean ``frozenset[int]`` from a file entry's ``executed_lines`` (defensive)."""
    raw = entry.get("executed_lines")
    if not isinstance(raw, list):
        return frozenset()
    lines: set[int] = set()
    for value in raw:
        # ``bool`` is an ``int`` subclass — exclude it so ``true``/``false`` never become line 1/0.
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        if value > 0:
            lines.add(value)
    return frozenset(lines)


def _normalize_path(raw_path: str, root: Path) -> str | None:
    """Resolve ``raw_path`` to a project-relative POSIX path, or ``None`` if outside the project.

    Coverage paths may be absolute or relative to where the suite ran (normally the project root).
    Either way we resolve against ``root`` and keep only files that live under it — coverage for a
    site-packages dependency or an unrelated absolute path is not the project's first-party code.
    """
    try:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        relative = resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return relative.as_posix()


def parse_coverage(raw: str | bytes, project_root: Path) -> CoverageData:
    """Parse a coverage.py JSON document into :class:`CoverageData` normalized to ``project_root``.

    Raises :class:`CoverageParseError` on anything that is not a coverage.py JSON report (invalid
    JSON, wrong top-level shape, missing ``files`` object). Individual malformed file entries are
    skipped rather than fatal, and out-of-project paths are ignored.
    """
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise CoverageParseError(f"not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CoverageParseError("expected a JSON object at the top level")
    files = document.get("files")
    if not isinstance(files, dict):
        raise CoverageParseError(
            "missing or malformed 'files' object - is this a `coverage json` report?"
        )

    root = project_root.resolve()
    executed: dict[str, frozenset[int]] = {}
    for raw_path, entry in files.items():
        if not isinstance(raw_path, str) or not isinstance(entry, dict):
            continue
        rel = _normalize_path(raw_path, root)
        if rel is None:
            continue  # outside the scanned project -> ignored
        lines = _coerce_executed_lines(entry)
        # Two coverage paths can normalize to the same project-relative file; union their lines.
        executed[rel] = executed.get(rel, frozenset()) | lines
    return CoverageData(executed_lines=executed)
