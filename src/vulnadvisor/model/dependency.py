"""The normalized dependency model shared across packages."""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class DependencySource(str, Enum):
    """Where a dependency record was discovered."""

    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    POETRY_LOCK = "poetry.lock"
    PIPFILE_LOCK = "Pipfile.lock"
    ENVIRONMENT = "environment"


class Dependency(BaseModel):
    """A single resolved or declared project dependency.

    Attributes:
        name: PEP 503 canonical (lowercased, dash-separated) distribution name. Use this for
            matching and de-duplication.
        version: The exact pinned version when known (``==`` / lockfile entry), else ``None``.
            A ``None`` version means the manifest only gave a range or left it unpinned.
        source: Which manifest (or the live environment) this record came from.
        is_direct: ``True`` when the dependency is explicitly declared by the project, ``False``
            for resolved/transitive lockfile entries and environment-derived records.
        raw_name: The original, un-normalized name as written in the manifest (kept for display
            and for package-to-import resolution in Task 1.2).
        specifier: The raw version constraint string as written (e.g. ``>=2.28,<3.0``, ``^1.4``),
            preserved even when no exact ``version`` could be pinned.
        extras: Declared extras for the dependency (e.g. ``("security",)``).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None = None
    source: DependencySource
    is_direct: bool = False
    raw_name: str | None = None
    specifier: str | None = None
    extras: tuple[str, ...] = ()
