"""Deps: manifest parsing, dependency resolution, and package-to-import mapping."""

from vulnadvisor.deps.import_mapping import (
    CURATED_IMPORT_NAMES,
    resolve_dependency,
    resolve_import_names,
)
from vulnadvisor.deps.parsers import (
    ManifestParseError,
    canonicalize_name,
    collect_dependencies,
    dependencies_from_environment,
    parse_manifest_file,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)

__all__ = [
    "CURATED_IMPORT_NAMES",
    "ManifestParseError",
    "canonicalize_name",
    "collect_dependencies",
    "dependencies_from_environment",
    "parse_manifest_file",
    "parse_pipfile_lock",
    "parse_poetry_lock",
    "parse_pyproject_toml",
    "parse_requirements_txt",
    "resolve_dependency",
    "resolve_import_names",
]
