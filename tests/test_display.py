"""Canonical CVE-first display identity (Task 12.1) — one rule for every surface."""

import pytest

from vulnadvisor.model import (
    Advisory,
    Dependency,
    DependencySource,
    MatchedAdvisory,
    PriorityBand,
    Score,
    ScoredFinding,
    display_id,
    display_title,
    select_display_id,
)

# --- select_display_id (the pure selection rule) ------------------------------------------------


@pytest.mark.parametrize(
    ("advisory_id", "aliases", "expected"),
    [
        # CVE present among aliases beats every other id kind.
        ("GHSA-462w-v97r-4m45", ["CVE-2019-10906"], "CVE-2019-10906"),
        ("PYSEC-2026-52", ["GHSA-462w-v97r-4m45", "CVE-2020-28493"], "CVE-2020-28493"),
        # The id itself can be the CVE.
        ("CVE-2024-3094", [], "CVE-2024-3094"),
        # Multiple CVEs: lowest-numbered wins — by year first, then number (numeric, not lexical).
        ("GHSA-462w-v97r-4m45", ["CVE-2021-44228", "CVE-2020-28493"], "CVE-2020-28493"),
        ("GHSA-462w-v97r-4m45", ["CVE-2020-28493", "CVE-2020-1747"], "CVE-2020-1747"),
        ("GHSA-462w-v97r-4m45", ["CVE-2020-9999", "CVE-2020-28493"], "CVE-2020-9999"),
        # Casing and surrounding whitespace are normalized for CVEs.
        ("GHSA-462w-v97r-4m45", ["cve-2020-28493"], "CVE-2020-28493"),
        ("GHSA-462w-v97r-4m45", [" CVE-2020-28493 "], "CVE-2020-28493"),
        # GHSA-only: a GHSA beats a PYSEC, wherever each appears.
        ("PYSEC-2026-52", ["GHSA-462w-v97r-4m45"], "GHSA-462w-v97r-4m45"),
        ("GHSA-462w-v97r-4m45", [], "GHSA-462w-v97r-4m45"),
        # PYSEC-only.
        ("PYSEC-2026-52", [], "PYSEC-2026-52"),
        ("OSV-MAL-0001", ["PYSEC-2026-52"], "PYSEC-2026-52"),
        # No aliases, unrecognized id kind: the raw id is the display id.
        ("OSV-MAL-0001", [], "OSV-MAL-0001"),
        # Malformed alias entries are skipped, never crash: non-strings, empties, junk CVEs,
        # truncated GHSA segments.
        ("PYSEC-2026-52", [None, 5, "", "CVE-bogus", "CVE-20-1", "GHSA-xx-yy-zz"], "PYSEC-2026-52"),
        ("OSV-MAL-0001", [None, {}, ["CVE-2020-1"], "  "], "OSV-MAL-0001"),
        # A malformed alias never hides a valid one later in the list.
        ("GHSA-462w-v97r-4m45", ["CVE-bogus", "CVE-2020-28493"], "CVE-2020-28493"),
    ],
)
def test_select_display_id(advisory_id: str, aliases: list[object], expected: str) -> None:
    assert select_display_id(advisory_id, aliases) == expected


# --- display_id / display_title (model-level wrappers) -------------------------------------------


def _finding(
    *,
    advisory_id: str = "PYSEC-2026-52",
    aliases: tuple[str, ...] = ("CVE-2020-28493",),
    name: str = "jinja2",
    version: str | None = "2.11.2",
) -> ScoredFinding:
    matched = MatchedAdvisory(
        dependency=Dependency(
            name=name,
            raw_name=name,
            version=version,
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(id=advisory_id, aliases=aliases),
    )
    score = Score(
        value=80.0,
        band=PriorityBand.HIGH,
        verdict="Fix this sprint",
        cvss_base=None,
        cvss_used=5.0,
        cvss_known=False,
        epss_probability=None,
        in_kev=False,
        rationale="test",
    )
    return ScoredFinding(matched=matched, score=score)


def test_display_id_prefers_cve_alias() -> None:
    finding = _finding()
    assert display_id(finding.matched.advisory) == "CVE-2020-28493"


def test_display_title_format() -> None:
    # The exact canonical format: id, middle-dot separator, package, space, version. Never "==".
    assert display_title(_finding()) == "CVE-2020-28493 · jinja2 2.11.2"


def test_display_title_unpinned() -> None:
    assert display_title(_finding(version=None)) == "CVE-2020-28493 · jinja2 (unpinned)"


def test_display_title_falls_back_to_raw_id() -> None:
    finding = _finding(advisory_id="OSV-MAL-0001", aliases=())
    assert display_title(finding) == "OSV-MAL-0001 · jinja2 2.11.2"


def test_display_title_never_contains_equals_pin() -> None:
    # The regression this task kills: "django==4.2.29PYSEC-2026-52"-style smashed display strings.
    title = display_title(
        _finding(name="django", version="4.2.29", advisory_id="PYSEC-2026-52", aliases=())
    )
    assert "==" not in title
    assert title == "PYSEC-2026-52 · django 4.2.29"
