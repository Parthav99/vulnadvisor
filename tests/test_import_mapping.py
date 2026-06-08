import pytest

from vulnadvisor.deps import (
    CURATED_IMPORT_NAMES,
    resolve_dependency,
    resolve_import_names,
)
from vulnadvisor.model import (
    Dependency,
    DependencySource,
    MappingConfidence,
    MappingSource,
)

# ≥10 tricky real-world distribution -> import-name mappings. Whether resolved from installed
# metadata or the curated table, the expected import name must appear.
TRICKY_MAPPINGS = [
    ("PyYAML", "yaml"),
    ("beautifulsoup4", "bs4"),
    ("scikit-learn", "sklearn"),
    ("Pillow", "PIL"),
    ("python-dateutil", "dateutil"),
    ("opencv-python", "cv2"),
    ("PyJWT", "jwt"),
    ("python-dotenv", "dotenv"),
    ("mysqlclient", "MySQLdb"),
    ("psycopg2-binary", "psycopg2"),
    ("protobuf", "google"),
    ("grpcio", "grpc"),
    ("websocket-client", "websocket"),
]


@pytest.mark.parametrize(("distribution", "expected_import"), TRICKY_MAPPINGS)
def test_tricky_name_mappings(distribution: str, expected_import: str) -> None:
    mapping = resolve_import_names(distribution)
    assert expected_import in mapping.import_names


def test_curated_table_values() -> None:
    # The curated table itself is correct for the documented examples.
    assert CURATED_IMPORT_NAMES["pyyaml"] == ("yaml",)
    assert CURATED_IMPORT_NAMES["beautifulsoup4"] == ("bs4",)
    assert CURATED_IMPORT_NAMES["scikit-learn"] == ("sklearn",)
    assert CURATED_IMPORT_NAMES["pillow"] == ("PIL",)
    assert "pkg_resources" in CURATED_IMPORT_NAMES["setuptools"]


def test_curated_keys_are_canonical() -> None:
    from vulnadvisor.deps import canonicalize_name

    for key in CURATED_IMPORT_NAMES:
        assert key == canonicalize_name(key)


def test_installed_package_uses_metadata_high_confidence() -> None:
    # pydantic is installed; its metadata should drive a HIGH-confidence mapping.
    mapping = resolve_import_names("pydantic")
    assert mapping.confidence is MappingConfidence.HIGH
    assert mapping.source is MappingSource.METADATA
    assert "pydantic" in mapping.import_names


def test_curated_used_when_not_installed() -> None:
    # websocket-client is not installed in our dev env, so the curated table is used.
    mapping = resolve_import_names("websocket-client")
    assert mapping.import_names == ("websocket",)
    assert mapping.confidence is MappingConfidence.MEDIUM
    assert mapping.source is MappingSource.CURATED


def test_unknown_package_degrades_to_low_confidence_guess() -> None:
    mapping = resolve_import_names("totally-not-a-real-pkg-xyz")
    assert mapping.confidence is MappingConfidence.LOW
    assert mapping.source is MappingSource.GUESS
    assert mapping.import_names == ("totally_not_a_real_pkg_xyz",)


def test_resolve_always_returns_at_least_one_name() -> None:
    for distribution in ("definitely-missing-123", "PyYAML", "pydantic"):
        assert len(resolve_import_names(distribution).import_names) >= 1


def test_distribution_field_is_canonical() -> None:
    mapping = resolve_import_names("Scikit_Learn")
    assert mapping.distribution == "scikit-learn"


def test_resolve_dependency_prefers_raw_name() -> None:
    dep = Dependency(
        name="pyyaml",
        raw_name="PyYAML",
        version="6.0.1",
        source=DependencySource.REQUIREMENTS_TXT,
        is_direct=True,
    )
    mapping = resolve_dependency(dep)
    assert "yaml" in mapping.import_names
