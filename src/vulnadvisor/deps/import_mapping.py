"""Resolve distribution names to the import names a project would actually ``import``.

The install name and the import name frequently differ (``PyYAML`` -> ``yaml``,
``beautifulsoup4`` -> ``bs4``). Missing that mapping would make us miss real vulnerabilities, so
resolution is layered for soundness:

1. **Installed metadata** (highest confidence): the package's own ``top_level.txt`` or, failing
   that, top-level names derived from its ``RECORD``.
2. **Curated table** (medium confidence): a hand-maintained map of well-known tricky names.
3. **Best-guess** (low confidence): canonical name with ``-`` -> ``_``; flagged so downstream
   logic can treat it cautiously rather than trusting it.

Every dependency therefore always resolves to at least one import name plus a confidence flag;
nothing crashes on an unknown package.
"""

from importlib import metadata
from importlib.metadata import Distribution, PackageNotFoundError

from vulnadvisor.deps.parsers import canonicalize_name
from vulnadvisor.model.dependency import Dependency
from vulnadvisor.model.import_mapping import (
    ImportMapping,
    MappingConfidence,
    MappingSource,
)

__all__ = [
    "CURATED_IMPORT_NAMES",
    "resolve_dependency",
    "resolve_import_names",
]

# Curated map of canonical distribution name -> top-level import names. Keys MUST be PEP 503
# canonical (lowercase, dash-separated). Values are real import names (case-sensitive).
CURATED_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "pillow": ("PIL",),
    "python-dateutil": ("dateutil",),
    "opencv-python": ("cv2",),
    "pyjwt": ("jwt",),
    "python-dotenv": ("dotenv",),
    "msgpack": ("msgpack",),
    "mysqlclient": ("MySQLdb",),
    "psycopg2-binary": ("psycopg2",),
    "protobuf": ("google",),
    "grpcio": ("grpc",),
    "setuptools": ("setuptools", "pkg_resources"),
    "websocket-client": ("websocket",),
    "pymysql": ("pymysql",),
    "markupsafe": ("markupsafe",),
}

# Top-level RECORD entries that never represent an importable package/module.
_NON_IMPORT_SUFFIXES = (".dist-info", ".data", ".egg-info")


def _best_guess(canonical: str) -> str:
    """Best-effort import name for an unknown distribution (``-`` -> ``_``)."""
    return canonical.replace("-", "_")


def _names_from_top_level(dist: Distribution) -> tuple[str, ...]:
    """Read import names from ``top_level.txt`` if present."""
    try:
        raw = dist.read_text("top_level.txt")
    except OSError:
        return ()
    if not raw:
        return ()
    names = tuple(line.strip() for line in raw.splitlines() if line.strip())
    return tuple(dict.fromkeys(name for name in names if name.isidentifier()))


def _names_from_record(dist: Distribution) -> tuple[str, ...]:
    """Derive top-level import names from the installed file list (``RECORD``)."""
    files = dist.files
    if not files:
        return ()
    names: set[str] = set()
    for path in files:
        parts = path.parts
        if not parts:
            continue
        first = parts[0]
        if first in {"..", "__pycache__"} or first.endswith(_NON_IMPORT_SUFFIXES):
            continue
        if len(parts) == 1:
            # A top-level single-file module (skip data files and the package marker).
            if first.endswith(".py") and first != "__init__.py":
                module = first[:-3]
                if module.isidentifier():
                    names.add(module)
        elif first.isidentifier():
            # A top-level package directory.
            names.add(first)
    return tuple(sorted(names))


def _names_from_metadata(distribution: str) -> tuple[str, ...]:
    """Resolve import names from installed metadata, or ``()`` if the package is absent."""
    try:
        dist = metadata.distribution(distribution)
    except PackageNotFoundError:
        return ()
    top_level = _names_from_top_level(dist)
    if top_level:
        return top_level
    return _names_from_record(dist)


def resolve_import_names(distribution: str) -> ImportMapping:
    """Resolve a distribution name to its import names with a confidence flag.

    Tries installed metadata first (``HIGH``), then the curated table (``MEDIUM``), then a
    best-guess normalization (``LOW``). Always returns a mapping with at least one import name.
    """
    canonical = canonicalize_name(distribution)

    from_metadata = _names_from_metadata(distribution)
    if from_metadata:
        return ImportMapping(
            distribution=canonical,
            import_names=from_metadata,
            confidence=MappingConfidence.HIGH,
            source=MappingSource.METADATA,
        )

    curated = CURATED_IMPORT_NAMES.get(canonical)
    if curated:
        return ImportMapping(
            distribution=canonical,
            import_names=curated,
            confidence=MappingConfidence.MEDIUM,
            source=MappingSource.CURATED,
        )

    return ImportMapping(
        distribution=canonical,
        import_names=(_best_guess(canonical),),
        confidence=MappingConfidence.LOW,
        source=MappingSource.GUESS,
    )


def resolve_dependency(dependency: Dependency) -> ImportMapping:
    """Resolve a :class:`Dependency` to its import names (prefers the raw manifest name)."""
    return resolve_import_names(dependency.raw_name or dependency.name)
