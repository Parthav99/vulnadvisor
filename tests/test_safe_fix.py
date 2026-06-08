import pytest

from vulnadvisor.engine import resolve_safe_fix
from vulnadvisor.model import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    Dependency,
    DependencySource,
    SafeFix,
)
from vulnadvisor.output.remediation import fix_command


def _dep(name: str, version: str | None, source: DependencySource | None = None) -> Dependency:
    return Dependency(
        name=name,
        raw_name=name,
        version=version,
        source=source or DependencySource.REQUIREMENTS_TXT,
    )


def _advisory(name: str, *ranges: AffectedRange) -> Advisory:
    return Advisory(
        id="GHSA-test",
        affected=(AffectedPackage(name=name, ranges=ranges),),
    )


def test_fix_available_minimal_upgrade() -> None:
    dep = _dep("jinja2", "2.10")
    advisory = _advisory("jinja2", AffectedRange(introduced="0", fixed="2.10.1"))
    fix = resolve_safe_fix(dep, advisory)
    assert fix.has_fix is True
    assert fix.fixed_version == "2.10.1"
    assert fix.is_major_jump is False
    assert fix.available_fixes == ("2.10.1",)


def test_picks_smallest_fix_greater_than_current() -> None:
    # Multiple branches fixed; current is 2.1, nearest non-vulnerable is 2.3 (not 1.5).
    dep = _dep("pkg", "2.1")
    advisory = _advisory(
        "pkg",
        AffectedRange(introduced="1.0", fixed="1.5"),
        AffectedRange(introduced="2.0", fixed="2.3"),
    )
    fix = resolve_safe_fix(dep, advisory)
    assert fix.fixed_version == "2.3"
    assert fix.available_fixes == ("1.5", "2.3")


def test_no_fix_when_only_last_affected() -> None:
    dep = _dep("pkg", "3.5")
    advisory = _advisory("pkg", AffectedRange(introduced="0", last_affected="3.9"))
    fix = resolve_safe_fix(dep, advisory)
    assert fix.has_fix is False
    assert fix.fixed_version is None
    assert "No fixed version" in fix.note


def test_no_fix_above_current_version() -> None:
    # Only a fix below the installed version exists -> nothing newer to recommend.
    dep = _dep("pkg", "5.0")
    advisory = _advisory("pkg", AffectedRange(introduced="0", fixed="1.5"))
    fix = resolve_safe_fix(dep, advisory)
    assert fix.has_fix is False
    assert fix.available_fixes == ("1.5",)


def test_major_version_jump_is_flagged() -> None:
    dep = _dep("pkg", "1.4")
    advisory = _advisory("pkg", AffectedRange(introduced="0", fixed="2.0"))
    fix = resolve_safe_fix(dep, advisory)
    assert fix.has_fix is True
    assert fix.fixed_version == "2.0"
    assert fix.is_major_jump is True
    assert "major-version jump" in fix.note


def test_unpinned_current_recommends_lowest_fix() -> None:
    dep = _dep("pkg", None)
    advisory = _advisory(
        "pkg",
        AffectedRange(introduced="0", fixed="1.5"),
        AffectedRange(introduced="2.0", fixed="2.3"),
    )
    fix = resolve_safe_fix(dep, advisory)
    assert fix.fixed_version == "1.5"
    assert fix.has_fix is True


def test_invalid_versions_are_skipped() -> None:
    dep = _dep("pkg", "1.0")
    advisory = _advisory(
        "pkg",
        AffectedRange(introduced="0", fixed="not-a-version"),
        AffectedRange(introduced="0", fixed="1.4"),
    )
    fix = resolve_safe_fix(dep, advisory)
    assert fix.fixed_version == "1.4"


def test_no_affected_data_means_no_fix() -> None:
    fix = resolve_safe_fix(_dep("pkg", "1.0"), Advisory(id="GHSA-x"))
    assert fix.has_fix is False
    assert fix.available_fixes == ()


# --- command templating per manifest type -----------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (DependencySource.REQUIREMENTS_TXT, 'pip install --upgrade "Flask>=0.12.3"'),
        (DependencySource.PYPROJECT_TOML, 'pip install --upgrade "Flask>=0.12.3"'),
        (DependencySource.POETRY_LOCK, 'poetry add "Flask>=0.12.3"'),
        (DependencySource.PIPFILE_LOCK, 'pipenv install "Flask>=0.12.3"'),
    ],
)
def test_fix_command_per_manifest(source: DependencySource, expected: str) -> None:
    dep = Dependency(name="flask", raw_name="Flask", version="0.12", source=source)
    advisory = _advisory("flask", AffectedRange(introduced="0", fixed="0.12.3"))
    assert fix_command(dep, resolve_safe_fix(dep, advisory)) == expected


def test_fix_command_none_when_no_fix() -> None:
    dep = Dependency(
        name="flask",
        raw_name="Flask",
        version="0.12",
        source=DependencySource.REQUIREMENTS_TXT,
    )
    no_fix = SafeFix(
        current_version="0.12",
        fixed_version=None,
        has_fix=False,
        is_major_jump=False,
        available_fixes=(),
        note="none",
    )
    assert fix_command(dep, no_fix) is None
