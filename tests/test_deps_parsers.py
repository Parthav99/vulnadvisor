from pathlib import Path

import pytest

from vulnadvisor.deps import (
    ManifestParseError,
    canonicalize_name,
    collect_dependencies,
    dependencies_from_environment,
    parse_manifest_file,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from vulnadvisor.model import Dependency, DependencySource

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"


def _by_name(deps: list[Dependency]) -> dict[str, Dependency]:
    return {dep.name: dep for dep in deps}


# --- canonicalization -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Flask", "flask"),
        ("PyYAML", "pyyaml"),
        ("scikit-learn", "scikit-learn"),
        ("scikit_learn", "scikit-learn"),
        ("ruamel.yaml", "ruamel-yaml"),
        ("Foo__Bar.Baz", "foo-bar-baz"),
    ],
)
def test_canonicalize_name(raw: str, expected: str) -> None:
    assert canonicalize_name(raw) == expected


# --- table-driven: one fixture per manifest format --------------------------------------------


def test_parse_requirements_txt_fixture() -> None:
    content = (FIXTURES / "requirements.txt").read_text(encoding="utf-8")
    deps = parse_requirements_txt(content)
    by_name = _by_name(deps)

    # Flask appears twice (different case, one with a marker) -> de-duplicated to one record.
    assert by_name.keys() == {"flask", "requests", "pyyaml", "urllib3", "django", "example-pkg"}
    assert all(dep.source is DependencySource.REQUIREMENTS_TXT for dep in deps)
    assert all(dep.is_direct for dep in deps)

    assert by_name["flask"].version == "2.3.2"
    assert by_name["pyyaml"].version == "6.0.1"
    # Ranged + unpinned -> no exact version, but the raw specifier is preserved.
    assert by_name["requests"].version is None
    assert by_name["requests"].specifier == ">=2.28,<3.0"
    assert by_name["urllib3"].version is None
    # Extras captured; URL form keeps the name with no version.
    assert by_name["django"].extras == ("argon2",)
    assert by_name["django"].version == "4.2.3"
    assert by_name["example-pkg"].version is None


def test_parse_pyproject_pep621_fixture() -> None:
    content = (FIXTURES / "pyproject_pep621.toml").read_text(encoding="utf-8")
    by_name = _by_name(parse_pyproject_toml(content))

    assert by_name.keys() == {"httpx", "pydantic", "rich", "pytest", "ruff"}
    assert by_name["pydantic"].version == "2.5.0"
    assert by_name["pytest"].version == "8.0.0"  # from optional-dependencies
    assert by_name["httpx"].version is None
    assert by_name["httpx"].specifier == ">=0.24"
    assert all(dep.is_direct for dep in by_name.values())


def test_parse_pyproject_poetry_fixture() -> None:
    content = (FIXTURES / "pyproject_poetry.toml").read_text(encoding="utf-8")
    by_name = _by_name(parse_pyproject_toml(content))

    # `python` is excluded; group deps are included.
    assert by_name.keys() == {"flask", "requests", "click", "pytest"}
    assert by_name["flask"].version == "2.3.2"  # bare version == exact
    assert by_name["requests"].version is None  # caret range
    assert by_name["requests"].specifier == "^2.28"
    assert by_name["click"].version == "8.1.7"  # table form { version = "..." }
    assert by_name["pytest"].version is None


def test_parse_poetry_lock_fixture() -> None:
    content = (FIXTURES / "poetry.lock").read_text(encoding="utf-8")
    by_name = _by_name(parse_poetry_lock(content))

    assert by_name.keys() == {"flask", "requests"}
    assert by_name["flask"].version == "2.3.2"
    assert by_name["requests"].version == "2.31.0"
    assert all(not dep.source.value.endswith(".txt") for dep in by_name.values())
    assert all(dep.is_direct is False for dep in by_name.values())


def test_parse_pipfile_lock_fixture() -> None:
    content = (FIXTURES / "Pipfile.lock").read_text(encoding="utf-8")
    by_name = _by_name(parse_pipfile_lock(content))

    assert by_name.keys() == {"flask", "requests", "pytest"}
    assert by_name["flask"].version == "2.3.2"
    assert by_name["requests"].version == "2.31.0"
    assert by_name["pytest"].version == "8.0.0"  # from develop section
    assert all(dep.is_direct is False for dep in by_name.values())


# --- edge cases: missing / duplicate / pinned-vs-range / malformed ----------------------------


@pytest.mark.parametrize(
    "parser",
    [parse_requirements_txt, parse_pyproject_toml, parse_poetry_lock],
)
def test_empty_content_returns_empty(parser: object) -> None:
    assert parser("") == []  # type: ignore[operator]


def test_pipfile_empty_object_returns_empty() -> None:
    assert parse_pipfile_lock("{}") == []


def test_duplicate_entries_are_deduped() -> None:
    content = "flask==2.3.2\nFlask==2.3.2\nflask==2.3.2  # again\n"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "flask"


def test_pinned_and_range_for_same_name_both_kept() -> None:
    # Different resolved versions are distinct records, not a crash.
    content = "flask==2.3.2\nflask>=1.0\n"
    deps = parse_requirements_txt(content)
    versions = sorted((d.version is None, d.version or "") for d in deps)
    assert versions == [(False, "2.3.2"), (True, "")]


@pytest.mark.parametrize(
    ("parser", "bad"),
    [
        (parse_pyproject_toml, "this is = not valid toml ]["),
        (parse_poetry_lock, "this is = not valid toml ]["),
        (parse_pipfile_lock, "{not json"),
    ],
)
def test_malformed_content_raises_typed_error(parser: object, bad: str) -> None:
    with pytest.raises(ManifestParseError):
        parser(bad)  # type: ignore[operator]


def test_pipfile_with_non_object_top_level_raises() -> None:
    with pytest.raises(ManifestParseError):
        parse_pipfile_lock("[1, 2, 3]")


# --- file dispatch + orchestration ------------------------------------------------------------


def test_parse_manifest_file_dispatch(tmp_path: Path) -> None:
    target = tmp_path / "requirements.txt"
    target.write_text("flask==2.3.2\n", encoding="utf-8")
    deps = parse_manifest_file(target)
    assert _by_name(deps)["flask"].version == "2.3.2"


def test_parse_manifest_file_unsupported_name(tmp_path: Path) -> None:
    target = tmp_path / "setup.cfg"
    target.write_text("", encoding="utf-8")
    with pytest.raises(ManifestParseError):
        parse_manifest_file(target)


def test_collect_dependencies_reads_present_manifests(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nrich\n", encoding="utf-8")
    deps = collect_dependencies(tmp_path)
    assert _by_name(deps).keys() == {"flask", "rich"}


def test_collect_dependencies_falls_back_to_environment(tmp_path: Path) -> None:
    # Empty project dir with no manifest -> use the installed environment.
    deps = collect_dependencies(tmp_path)
    names = {dep.name for dep in deps}
    assert names  # non-empty
    assert "pydantic" in names  # we know this is installed
    assert all(dep.source is DependencySource.ENVIRONMENT for dep in deps)


def test_collect_dependencies_no_fallback_returns_empty(tmp_path: Path) -> None:
    assert collect_dependencies(tmp_path, use_environment_fallback=False) == []


def test_dependencies_from_environment_non_empty() -> None:
    deps = dependencies_from_environment()
    assert any(dep.name == "typer" for dep in deps)
