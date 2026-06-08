from pathlib import Path

from vulnadvisor.model import (
    ExtractionStatus,
    SymbolExtraction,
    SymbolKind,
    VulnerableSymbol,
)
from vulnadvisor.store import SymbolDataset


def _extraction(advisory_id: str) -> SymbolExtraction:
    return SymbolExtraction(
        advisory_id=advisory_id,
        symbols=(
            VulnerableSymbol(
                name="find_python_name",
                qualname="FullConstructor.find_python_name",
                kind=SymbolKind.METHOD,
                file="lib3/yaml/constructor.py",
            ),
        ),
        confidence=0.85,
        provenance=("https://github.com/o/r/commit/abc",),
        status=ExtractionStatus.EXTRACTED,
    )


def test_upsert_and_get_roundtrip() -> None:
    dataset = SymbolDataset()
    extraction = _extraction("GHSA-1")
    dataset.upsert(extraction)
    fetched = dataset.get("GHSA-1")
    assert fetched == extraction
    assert fetched is not None
    assert fetched.symbols[0].qualname == "FullConstructor.find_python_name"


def test_has_and_count() -> None:
    dataset = SymbolDataset()
    assert dataset.count() == 0
    assert dataset.has("GHSA-1") is False
    dataset.upsert(_extraction("GHSA-1"))
    assert dataset.has("GHSA-1") is True
    assert dataset.count() == 1


def test_get_missing_returns_none() -> None:
    assert SymbolDataset().get("nope") is None


def test_upsert_is_idempotent() -> None:
    dataset = SymbolDataset()
    dataset.upsert(_extraction("GHSA-1"))
    dataset.upsert(_extraction("GHSA-1"))  # same id again
    assert dataset.count() == 1


def test_upsert_replaces_payload() -> None:
    dataset = SymbolDataset()
    dataset.upsert(SymbolExtraction(advisory_id="GHSA-1", status=ExtractionStatus.NO_FIX_LINK))
    dataset.upsert(_extraction("GHSA-1"))  # replace with the extracted version
    fetched = dataset.get("GHSA-1")
    assert fetched is not None
    assert fetched.status is ExtractionStatus.EXTRACTED
    assert dataset.count() == 1


def test_advisory_ids_sorted() -> None:
    dataset = SymbolDataset()
    for advisory_id in ("GHSA-c", "GHSA-a", "GHSA-b"):
        dataset.upsert(_extraction(advisory_id))
    assert dataset.advisory_ids() == ["GHSA-a", "GHSA-b", "GHSA-c"]


def test_persists_to_disk(tmp_path: Path) -> None:
    db = tmp_path / "symbols.sqlite"
    dataset = SymbolDataset(db)
    dataset.upsert(_extraction("GHSA-1"))
    dataset.close()

    reopened = SymbolDataset(db)
    assert reopened.count() == 1
    assert reopened.get("GHSA-1") is not None
    reopened.close()
