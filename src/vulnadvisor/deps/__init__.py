"""Deps: manifest parsing, dependency resolution, and package-to-import mapping."""

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
    "ManifestParseError",
    "canonicalize_name",
    "collect_dependencies",
    "dependencies_from_environment",
    "parse_manifest_file",
    "parse_pipfile_lock",
    "parse_poetry_lock",
    "parse_pyproject_toml",
    "parse_requirements_txt",
]
