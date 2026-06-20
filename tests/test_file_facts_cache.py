"""Task 22.1 validation gate: the per-file facts cache and its sound (content+rule) invalidation."""

from pathlib import Path

from vulnadvisor.sast.facts import build_file_facts
from vulnadvisor.sast.model import SastTier, SinkHit
from vulnadvisor.sast.rules import rule_pack_hash
from vulnadvisor.store.file_facts import (
    FileFacts,
    FileFactsCache,
    FunctionTaintSummary,
    default_facts_cache_path,
    facts_cache_key,
)

_YAML_SRC = "import yaml\n\n\ndef parse(s):\n    return yaml.load(s)\n"


def _sink() -> SinkHit:
    return SinkHit(
        cwe="CWE-502",
        kind="unsafe-deserialization",
        title="Unsafe deserialization",
        file="a.py",
        line=5,
        col=11,
        callee="yaml.load",
        tier=SastTier.POSSIBLE_FLOW,
        reason="non-literal argument",
    )


def _facts(rel: str = "a.py") -> FileFacts:
    return FileFacts(
        rel=rel,
        analysis=build_file_facts(rel, _YAML_SRC).analysis,
        sinks=(_sink(),),
        taint_summaries=(
            FunctionTaintSummary(
                module="a", qualname="parse", tainted_params=("s",), taints_return=True
            ),
        ),
    )


# --- key composition -----------------------------------------------------------------------------


def test_key_invalidates_on_content_change() -> None:
    rp = rule_pack_hash()
    assert facts_cache_key("a.py", "x = 1\n", rp) == facts_cache_key("a.py", "x = 1\n", rp)
    assert facts_cache_key("a.py", "x = 1\n", rp) != facts_cache_key("a.py", "x = 2\n", rp)


def test_key_invalidates_on_rule_pack_change() -> None:
    same = facts_cache_key("a.py", "x = 1\n", "rulehash-A")
    changed = facts_cache_key("a.py", "x = 1\n", "rulehash-B")
    assert same != changed  # a rule-pack change must produce a different key (busts the entry)


def test_key_separates_identical_content_at_different_paths() -> None:
    rp = rule_pack_hash()
    assert facts_cache_key("a/__init__.py", "", rp) != facts_cache_key("b/__init__.py", "", rp)


def test_rule_pack_hash_is_deterministic_and_hex_sha256() -> None:
    first = rule_pack_hash()
    assert first == rule_pack_hash()  # pure: identical rules -> identical digest across calls
    assert len(first) == 64 and all(c in "0123456789abcdef" for c in first)


# --- round-trip ----------------------------------------------------------------------------------


def test_file_facts_round_trips_with_all_fact_kinds() -> None:
    facts = _facts()
    restored = FileFacts.model_validate_json(facts.model_dump_json())
    assert restored == facts
    assert restored.sinks and restored.taint_summaries  # sinks + summaries survive serialization


def test_build_file_facts_is_pure_and_finds_sinks() -> None:
    facts = build_file_facts("a.py", _YAML_SRC)
    assert build_file_facts("a.py", _YAML_SRC) == facts  # deterministic
    assert any(s.callee == "yaml.load" for s in facts.sinks)
    assert facts.taint_summaries == ()  # summaries are the 22.2 engine's job, empty here


def test_build_file_facts_does_not_raise_on_syntax_error() -> None:
    facts = build_file_facts("bad.py", "def (:\n")
    assert facts.sinks == ()
    assert facts.analysis.parse_error is not None  # captured, not raised


# --- cache behavior (the validation gate) --------------------------------------------------------


def test_hit_then_miss_keyed_by_content() -> None:
    cache = FileFactsCache()
    rp = rule_pack_hash()
    key = facts_cache_key("a.py", _YAML_SRC, rp)

    assert cache.get(key) is None
    assert cache.misses == 1 and cache.hits == 0

    cache.set(key, _facts())
    got = cache.get(key)
    assert got is not None and got.sinks[0].callee == "yaml.load"
    assert cache.hits == 1

    # An edited file hashes to a new key -> a miss, never a stale hit.
    edited = facts_cache_key("a.py", _YAML_SRC + "x = 2\n", rp)
    assert cache.get(edited) is None


def test_rule_pack_change_misses_old_entry() -> None:
    cache = FileFactsCache()
    old = facts_cache_key("a.py", _YAML_SRC, "rules-v1")
    cache.set(old, _facts())

    # Same file, different rule pack: the key differs, so the old facts are not served.
    new = facts_cache_key("a.py", _YAML_SRC, "rules-v2")
    assert cache.get(new) is None  # rule change forces re-analysis (no hidden finding)


def test_corrupt_row_is_a_miss_not_a_crash() -> None:
    cache = FileFactsCache()
    rp = rule_pack_hash()
    key = facts_cache_key("a.py", _YAML_SRC, rp)
    cache.set(key, _facts())

    cache._conn.execute("UPDATE file_facts SET value = ? WHERE 1", ("not json",))
    cache._conn.commit()

    cache.hits = cache.misses = 0
    assert cache.get(key) is None  # defensive: corrupt entry -> miss, no exception
    assert cache.misses == 1


def test_old_schema_row_is_a_miss() -> None:
    cache = FileFactsCache()
    rp = rule_pack_hash()
    key = facts_cache_key("a.py", _YAML_SRC, rp)
    # A row missing the required ``rel``/``analysis`` fields (an older schema) must not deserialize.
    cache._conn.execute("INSERT INTO file_facts (key, value) VALUES (?, ?)", (key, "{}"))
    cache._conn.commit()
    assert cache.get(key) is None


def test_cache_persists_across_connections(tmp_path: Path) -> None:
    db = tmp_path / "file_facts.sqlite"
    rp = rule_pack_hash()
    key = facts_cache_key("a.py", _YAML_SRC, rp)

    first = FileFactsCache(db)
    first.set(key, _facts())
    first.close()

    second = FileFactsCache(db)
    got = second.get(key)
    assert got is not None and got.sinks[0].callee == "yaml.load"
    assert second.hits == 1
    second.close()


def test_default_facts_cache_path_is_sibling_of_analysis_cache(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VULNADVISOR_CACHE", str(tmp_path))
    path = default_facts_cache_path()
    assert path.name == "file_facts.sqlite"
    assert path.parent == tmp_path
