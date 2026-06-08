"""Symbols: fix-commit-to-vulnerable-symbol extraction (the data moat)."""

from vulnadvisor.symbols.extractor import (
    SymbolExtractor,
    extract_symbols_from_patch,
    fix_commit_urls,
)

__all__ = [
    "SymbolExtractor",
    "extract_symbols_from_patch",
    "fix_commit_urls",
]
