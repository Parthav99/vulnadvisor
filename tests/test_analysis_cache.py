from pathlib import Path

from vulnadvisor.callgraph import build_import_graph
from vulnadvisor.model.imports import FileAnalysis, ImportGraph
from vulnadvisor.store.analysis_cache import AnalysisCache, cache_key, content_hash


def _make_project(root: Path) -> int:
    """Write a small multi-file project under ``root``; return its analyzable file count."""
    (root / "pkg").mkdir()
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "a.py").write_text("import yaml\n\n\ndef parse(s):\n    return yaml.load(s)\n")
    (root / "pkg" / "b.py").write_text(
        "import requests\n\n\ndef get(u):\n    return requests.get(u)\n"
    )  # noqa: E501
    (root / "main.py").write_text("from pkg import a\n\nprint(a.parse('x: 1'))\n")
    return 4


# --- key + hashing -------------------------------------------------------------------------------


def test_content_hash_is_stable_and_content_sensitive() -> None:
    assert content_hash("import yaml\n") == content_hash("import yaml\n")
    assert content_hash("import yaml\n") != content_hash("import json\n")


def test_cache_key_separates_identical_content_at_different_paths() -> None:
    # Two empty __init__.py files have identical content but must not share a cache entry.
    assert cache_key("a/__init__.py", "") != cache_key("b/__init__.py", "")
    assert cache_key("a.py", "x = 1\n") == cache_key("a.py", "x = 1\n")


def test_file_analysis_round_trips() -> None:
    original = FileAnalysis.model_validate_json(FileAnalysis(imports=()).model_dump_json())
    assert original == FileAnalysis(imports=())


# --- cache behavior (the validation gate) --------------------------------------------------------


def test_unchanged_rerun_is_all_hits_no_reanalysis(tmp_path: Path) -> None:
    count = _make_project(tmp_path)
    cache = AnalysisCache()

    build_import_graph(tmp_path, cache=cache)
    assert cache.hits == 0
    assert cache.misses == count  # cold cache: every file analyzed once

    cache.hits = cache.misses = 0
    build_import_graph(tmp_path, cache=cache)
    assert cache.misses == 0  # warm cache: nothing re-analyzed
    assert cache.hits == count


def test_editing_one_file_invalidates_only_that_slice(tmp_path: Path) -> None:
    count = _make_project(tmp_path)
    cache = AnalysisCache()
    build_import_graph(tmp_path, cache=cache)  # warm the cache

    (tmp_path / "pkg" / "a.py").write_text(
        "import yaml\nimport os\n\n\ndef parse(s):\n    return yaml.load(s)\n"
    )

    cache.hits = cache.misses = 0
    build_import_graph(tmp_path, cache=cache)
    assert cache.misses == 1  # only the edited file is re-analyzed
    assert cache.hits == count - 1


def test_cached_graph_is_identical_to_uncached(tmp_path: Path) -> None:
    _make_project(tmp_path)
    cache = AnalysisCache()

    uncached: ImportGraph = build_import_graph(tmp_path)
    warmed: ImportGraph = build_import_graph(tmp_path, cache=cache)  # cold (populates)
    served: ImportGraph = build_import_graph(tmp_path, cache=cache)  # served from cache

    assert warmed == uncached
    assert served == uncached  # cache is a pure speed optimization, never changes results


def test_edit_then_revert_reuses_original_entry(tmp_path: Path) -> None:
    # Content addressing: reverting a file to a previously seen state hits the old entry.
    _make_project(tmp_path)
    original = (tmp_path / "main.py").read_text(encoding="utf-8")
    cache = AnalysisCache()
    build_import_graph(tmp_path, cache=cache)

    (tmp_path / "main.py").write_text(original + "# touched\n")
    build_import_graph(tmp_path, cache=cache)  # one miss for the edit

    (tmp_path / "main.py").write_text(original)  # revert to known content
    cache.hits = cache.misses = 0
    build_import_graph(tmp_path, cache=cache)
    assert cache.misses == 0  # original content still cached -> all hits


def test_corrupt_entry_falls_back_to_reanalysis(tmp_path: Path) -> None:
    _make_project(tmp_path)
    cache = AnalysisCache()
    build_import_graph(tmp_path, cache=cache)

    # Poison one stored value; the cache must treat it as a miss, never crash.
    cache._conn.execute("UPDATE file_analysis SET value = ? WHERE 1", ("not json",))
    cache._conn.commit()

    cache.hits = cache.misses = 0
    graph = build_import_graph(tmp_path, cache=cache)
    assert cache.misses >= 1  # corrupt entries forced re-analysis
    assert graph == build_import_graph(tmp_path)  # results still correct


def test_cache_persists_across_connections(tmp_path: Path) -> None:
    count = _make_project(tmp_path)
    db = tmp_path / "analysis.sqlite"

    first = AnalysisCache(db)
    build_import_graph(tmp_path, cache=first)
    first.close()

    second = AnalysisCache(db)
    build_import_graph(tmp_path, cache=second)
    assert second.hits == count  # a fresh process reuses the on-disk cache
    assert second.misses == 0
    second.close()
