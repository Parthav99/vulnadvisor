"""Backfill the symbol dataset by extracting vulnerable symbols for many packages' advisories.

For each package we query OSV for all of its advisories and extract+store the vulnerable symbols.
Re-runs are idempotent: an advisory already in the dataset is skipped unless ``refresh`` is set,
which re-extracts (the refresh path for updated advisories). Per-package outages degrade (the
package is recorded) rather than aborting the whole run.
"""

from collections.abc import Iterable, Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from vulnadvisor.advisories.transport import TransportError
from vulnadvisor.deps.parsers import canonicalize_name
from vulnadvisor.model.advisory import Advisory
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.symbols import SymbolExtraction
from vulnadvisor.store.dataset import SymbolDataset

__all__ = ["TOP_PYPI_PACKAGES", "BackfillReport", "backfill", "top_packages"]

# A small built-in list of widely used PyPI packages, used by ``--top N`` so backfill needs no
# network just to choose targets. Not exhaustive — the user can always pass explicit names.
TOP_PYPI_PACKAGES: tuple[str, ...] = (
    "urllib3",
    "requests",
    "setuptools",
    "certifi",
    "charset-normalizer",
    "idna",
    "pyyaml",
    "packaging",
    "jinja2",
    "click",
    "flask",
    "werkzeug",
    "cryptography",
    "numpy",
    "pandas",
    "pillow",
    "sqlalchemy",
    "django",
    "aiohttp",
    "lxml",
    "scipy",
    "boto3",
    "tornado",
    "paramiko",
    "twisted",
    "scrapy",
    "celery",
    "redis",
    "pyjwt",
    "markdown",
)


class _OSVQuerier(Protocol):
    """Structural type for the OSV query dependency (so tests can inject a fake)."""

    def query(self, dependency: Dependency) -> list[Advisory]:
        """Return advisories affecting ``dependency``."""
        ...


class _SymbolExtractor(Protocol):
    """Structural type for the symbol extractor (so tests can inject a fake)."""

    def extract(self, advisory: Advisory) -> SymbolExtraction:
        """Extract vulnerable symbols for ``advisory``."""
        ...


class BackfillReport(BaseModel):
    """Summary of a backfill run."""

    model_config = ConfigDict(frozen=True)

    packages: int
    advisories_seen: int
    written: int
    skipped: int
    degraded_packages: tuple[str, ...] = ()


def backfill(
    dataset: SymbolDataset,
    package_names: Iterable[str],
    *,
    osv: _OSVQuerier,
    extractor: _SymbolExtractor,
    refresh: bool = False,
) -> BackfillReport:
    """Populate ``dataset`` with extracted symbols for the given packages' advisories."""
    packages = 0
    seen = 0
    written = 0
    skipped = 0
    degraded: list[str] = []

    for raw_name in package_names:
        packages += 1
        canonical = canonicalize_name(raw_name)
        dependency = Dependency(
            name=canonical,
            raw_name=raw_name,
            version=None,
            source=DependencySource.ENVIRONMENT,
        )
        try:
            advisories = osv.query(dependency)
        except TransportError:
            degraded.append(canonical)
            continue

        for advisory in advisories:
            seen += 1
            if not refresh and dataset.has(advisory.id):
                skipped += 1
                continue
            dataset.upsert(extractor.extract(advisory))
            written += 1

    return BackfillReport(
        packages=packages,
        advisories_seen=seen,
        written=written,
        skipped=skipped,
        degraded_packages=tuple(degraded),
    )


def top_packages(count: int) -> Sequence[str]:
    """Return the first ``count`` built-in top PyPI package names."""
    return TOP_PYPI_PACKAGES[: max(0, count)]
