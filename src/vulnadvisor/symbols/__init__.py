"""Symbols: fix-commit-to-vulnerable-symbol extraction (the data moat)."""

from vulnadvisor.symbols.backfill import (
    TOP_PYPI_PACKAGES,
    BackfillReport,
    backfill,
    top_packages,
)
from vulnadvisor.symbols.extractor import (
    SymbolExtractor,
    extract_symbols_from_patch,
    fix_commit_urls,
)

__all__ = [
    "TOP_PYPI_PACKAGES",
    "BackfillReport",
    "SymbolExtractor",
    "backfill",
    "extract_symbols_from_patch",
    "fix_commit_urls",
    "top_packages",
]
