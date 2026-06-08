from pathlib import Path

from vulnadvisor.advisories import TransportError
from vulnadvisor.model import (
    Advisory,
    Dependency,
    ExtractionStatus,
    SymbolExtraction,
    SymbolKind,
    VulnerableSymbol,
)
from vulnadvisor.store import SymbolDataset
from vulnadvisor.symbols.backfill import TOP_PYPI_PACKAGES, backfill, top_packages


class FakeOSV:
    """Returns canned advisories per package name; can simulate an outage for one package."""

    def __init__(self, by_package: dict[str, list[Advisory]], fail: set[str] | None = None) -> None:
        self.by_package = by_package
        self.fail = fail or set()

    def query(self, dependency: Dependency) -> list[Advisory]:
        if dependency.name in self.fail:
            raise TransportError("osv down")
        return self.by_package.get(dependency.name, [])


class FakeExtractor:
    """Returns a canned EXTRACTED result and counts how many times it ran."""

    def __init__(self) -> None:
        self.calls = 0

    def extract(self, advisory: Advisory) -> SymbolExtraction:
        self.calls += 1
        return SymbolExtraction(
            advisory_id=advisory.id,
            symbols=(
                VulnerableSymbol(
                    name="vuln", qualname="vuln", kind=SymbolKind.FUNCTION, file="m.py"
                ),
            ),
            confidence=0.8,
            provenance=("https://github.com/o/r/commit/abc",),
            status=ExtractionStatus.EXTRACTED,
        )


def _osv() -> FakeOSV:
    return FakeOSV(
        {
            "pyyaml": [Advisory(id="GHSA-yaml-1"), Advisory(id="GHSA-yaml-2")],
            "flask": [Advisory(id="GHSA-flask-1")],
        }
    )


def test_backfill_populates_dataset() -> None:
    dataset = SymbolDataset()
    extractor = FakeExtractor()
    report = backfill(dataset, ["PyYAML", "Flask"], osv=_osv(), extractor=extractor)

    assert report.packages == 2
    assert report.advisories_seen == 3
    assert report.written == 3
    assert report.skipped == 0
    assert dataset.count() == 3
    assert extractor.calls == 3


def test_backfill_is_idempotent() -> None:
    dataset = SymbolDataset()
    backfill(dataset, ["PyYAML", "Flask"], osv=_osv(), extractor=FakeExtractor())

    extractor = FakeExtractor()
    report = backfill(dataset, ["PyYAML", "Flask"], osv=_osv(), extractor=extractor)
    assert report.written == 0
    assert report.skipped == 3
    assert dataset.count() == 3  # unchanged
    assert extractor.calls == 0  # nothing re-extracted


def test_backfill_refresh_re_extracts() -> None:
    dataset = SymbolDataset()
    backfill(dataset, ["PyYAML"], osv=_osv(), extractor=FakeExtractor())

    extractor = FakeExtractor()
    report = backfill(dataset, ["PyYAML"], osv=_osv(), extractor=extractor, refresh=True)
    assert report.written == 2
    assert report.skipped == 0
    assert extractor.calls == 2
    assert dataset.count() == 2  # still idempotent on row count


def test_backfill_handles_outage() -> None:
    dataset = SymbolDataset()
    osv = FakeOSV({"flask": [Advisory(id="GHSA-flask-1")]}, fail={"pyyaml"})
    report = backfill(dataset, ["PyYAML", "Flask"], osv=osv, extractor=FakeExtractor())

    assert "pyyaml" in report.degraded_packages
    assert dataset.count() == 1  # flask still processed
    assert report.written == 1


def test_top_packages_slice() -> None:
    assert list(top_packages(3)) == list(TOP_PYPI_PACKAGES[:3])
    assert list(top_packages(0)) == []


def test_persisted_lookup(tmp_path: Path) -> None:
    db = tmp_path / "symbols.sqlite"
    dataset = SymbolDataset(db)
    backfill(dataset, ["PyYAML"], osv=_osv(), extractor=FakeExtractor())
    dataset.close()

    reopened = SymbolDataset(db)
    assert reopened.has("GHSA-yaml-1")
    assert reopened.get("GHSA-yaml-1") is not None
    reopened.close()
