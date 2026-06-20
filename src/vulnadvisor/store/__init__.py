"""Store: SQLite caches (advisory TTL cache + per-file analysis/facts caches) and symbol dataset."""

from vulnadvisor.store.analysis_cache import AnalysisCache, default_analysis_cache_path
from vulnadvisor.store.cache import SqliteCache, default_cache_path
from vulnadvisor.store.dataset import SymbolDataset, default_dataset_path
from vulnadvisor.store.file_facts import (
    FileFacts,
    FileFactsCache,
    FunctionTaintSummary,
    default_facts_cache_path,
    facts_cache_key,
)

__all__ = [
    "AnalysisCache",
    "FileFacts",
    "FileFactsCache",
    "FunctionTaintSummary",
    "SqliteCache",
    "SymbolDataset",
    "default_analysis_cache_path",
    "default_cache_path",
    "default_dataset_path",
    "default_facts_cache_path",
    "facts_cache_key",
]
