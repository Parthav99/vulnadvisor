from pathlib import Path

import pytest

from vulnadvisor.callgraph import build_import_graph, map_imports_to_distributions
from vulnadvisor.model import (
    Dependency,
    DependencySource,
    DynamicImportKind,
    ImportKind,
)

SAMPLE = Path(__file__).resolve().parent.parent / "fixtures" / "projects" / "sample_imports"


def _site_for_root(graph, root: str):  # type: ignore[no-untyped-def]
    for site in graph.import_sites:
        if root in site.imported_roots():
            return site
    return None


def test_first_party_modules_inferred() -> None:
    graph = build_import_graph(SAMPLE)
    assert "myapp" in graph.first_party_modules


def test_absolute_import_roots_collected() -> None:
    graph = build_import_graph(SAMPLE)
    roots = set(graph.import_roots())
    # Third-party / stdlib absolute roots from main.py.
    assert {"os", "numpy", "collections", "yaml", "importlib"} <= roots


def test_alias_is_captured() -> None:
    graph = build_import_graph(SAMPLE)
    numpy_site = _site_for_root(graph, "numpy")
    assert numpy_site is not None
    assert numpy_site.kind is ImportKind.IMPORT
    assert numpy_site.names[0].name == "numpy"
    assert numpy_site.names[0].asname == "np"


def test_dotted_alias_root() -> None:
    graph = build_import_graph(SAMPLE)
    # `import os.path as osp` -> root "os", alias on the dotted name.
    site = next(s for s in graph.import_sites if any(n.asname == "osp" for n in s.names))
    assert site.names[0].name == "os.path"
    assert "os" in site.imported_roots()


def test_from_import_captured() -> None:
    graph = build_import_graph(SAMPLE)
    yaml_site = _site_for_root(graph, "yaml")
    assert yaml_site is not None
    assert yaml_site.kind is ImportKind.FROM
    assert yaml_site.module == "yaml"
    assert any(n.name == "safe_load" for n in yaml_site.names)


def test_relative_imports_detected() -> None:
    graph = build_import_graph(SAMPLE)
    relative = [s for s in graph.import_sites if s.is_relative]
    levels = {(s.module, s.level) for s in relative}
    assert (None, 1) in levels  # from . import other
    assert ("helper", 1) in levels  # from .helper import thing
    assert ("main", 2) in levels  # from ..main import load
    # Relative imports are first-party: they contribute no external root.
    for site in relative:
        assert site.imported_roots() == ()


def test_dynamic_sites_detected() -> None:
    graph = build_import_graph(SAMPLE)
    kinds = {site.kind for site in graph.dynamic_sites}
    assert DynamicImportKind.IMPORTLIB in kinds
    assert DynamicImportKind.DUNDER_IMPORT in kinds
    assert DynamicImportKind.EVAL in kinds
    assert DynamicImportKind.EXEC in kinds
    importlib_site = next(s for s in graph.dynamic_sites if s.kind is DynamicImportKind.IMPORTLIB)
    assert "import_module" in importlib_site.detail
    assert importlib_site.lineno > 0


def test_external_roots_exclude_first_party() -> None:
    graph = build_import_graph(SAMPLE)
    external = set(graph.external_import_roots())
    assert "myapp" not in external
    assert "yaml" in external


@pytest.mark.parametrize(
    ("call", "target_root", "first_party_relative"),
    [
        ('importlib.import_module("redash.x")', "redash", False),
        ('importlib.import_module("redash." + name)', "redash", False),
        ('importlib.import_module(f"redash.{name}")', "redash", False),
        ('importlib.import_module(f"{__name__}.{name}")', None, True),
        ('importlib.import_module("." + name, __package__)', None, True),
        ('__import__("pkg.sub")', "pkg", False),
        # unprovable: bare variable, exec, non-dotted prefix, computed call
        ("importlib.import_module(name)", None, False),
        ('importlib.import_module(f"red{name}")', None, False),
        ("exec(code)", None, False),
        ("eval(expr)", None, False),
    ],
)
def test_dynamic_target_extraction(
    tmp_path: Path, call: str, target_root: str | None, first_party_relative: bool
) -> None:
    (tmp_path / "m.py").write_text(f"import importlib\n\n\ndef f(name, code, expr):\n    {call}\n")
    graph = build_import_graph(tmp_path)
    site = graph.dynamic_sites[0]
    assert site.target_root == target_root
    assert site.first_party_relative is first_party_relative


def test_syntax_error_is_recorded_not_raised(tmp_path: Path) -> None:
    (tmp_path / "good.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    assert any(err.file == "bad.py" for err in graph.parse_errors)
    assert "os" in graph.import_roots()  # the good file is still analyzed


def test_excluded_directories_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "vendored.py").write_text("import secret_internal_thing\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    roots = set(graph.import_roots())
    assert "requests" in roots
    assert "secret_internal_thing" not in roots


def test_map_imports_to_distributions() -> None:
    graph = build_import_graph(SAMPLE)
    deps = [
        Dependency(
            name="pyyaml",
            raw_name="PyYAML",
            version="6.0",
            source=DependencySource.REQUIREMENTS_TXT,
        ),
        Dependency(
            name="numpy",
            raw_name="numpy",
            version="1.26.0",
            source=DependencySource.REQUIREMENTS_TXT,
        ),
    ]
    mapping = map_imports_to_distributions(graph, deps)
    assert "pyyaml" in mapping  # PyYAML -> yaml import
    assert "numpy" in mapping
    # Evidence: each mapped distribution points at real import sites.
    assert all(len(sites) >= 1 for sites in mapping.values())


def test_non_utf8_python_file_does_not_crash_scan(tmp_path: Path) -> None:
    # A .py file with invalid UTF-8 bytes (e.g. a binary/gzip test fixture some repos ship) must
    # be recorded as unreadable, not crash the whole scan (regression: UnicodeDecodeError).
    (tmp_path / "good.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"\x1f\x8b\x08\x00bogus binary content")

    graph = build_import_graph(tmp_path)

    assert "os" in graph.import_roots()  # the readable file is still analyzed
    assert any(err.file == "binary.py" for err in graph.parse_errors)
    # parse_errors present keeps reachability cautious (never a silent "not imported").
    assert graph.parse_errors
