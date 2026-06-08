from pathlib import Path

from vulnadvisor.cli.render import (
    badge_for_band,
    fix_command,
    render_to_string,
)
from vulnadvisor.engine.scoring import score_match
from vulnadvisor.model import (
    Advisory,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
    PriorityBand,
    ScoredFinding,
)

SNAP = Path(__file__).resolve().parent.parent / "fixtures" / "snapshots"


def _sample_findings() -> list[ScoredFinding]:
    jinja = MatchedAdvisory(
        dependency=Dependency(
            name="jinja2",
            raw_name="Jinja2",
            version="2.10",
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id="GHSA-462w-v97r-4m45",
            aliases=("CVE-2019-10906",),
            summary="Jinja2 sandbox escape via str.format_map.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        ),
        epss=EpssScore(cve="CVE-2019-10906", probability=0.945, percentile=0.991),
        in_kev=True,
    )
    flask = MatchedAdvisory(
        dependency=Dependency(
            name="flask",
            raw_name="Flask",
            version="0.12",
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id="GHSA-flask-dos0",
            aliases=("CVE-2018-1000656",),
            summary="Flask denial of service via crafted JSON.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        ),
        epss=EpssScore(cve="CVE-2018-1000656", probability=0.02, percentile=0.40),
        in_kev=False,
    )
    # Already in descending-priority order (jinja2 CRITICAL, flask LOW).
    return [score_match(jinja), score_match(flask)]


def test_render_contains_three_cards_and_badges() -> None:
    out = render_to_string(_sample_findings())
    assert "2 finding(s), highest priority first" in out
    assert "A - Attack summary" in out
    assert "B - Risk" in out
    assert "C - Action" in out
    assert "Badge: RED" in out
    assert "Badge: GREEN" in out
    assert "Fix now" in out
    assert "Monitor" in out
    assert "Fix: pip install --upgrade Jinja2" in out


def test_render_degraded_notice() -> None:
    out = render_to_string([], ("OSV", "EPSS"))
    assert "Degraded sources: OSV, EPSS" in out
    assert "No matching advisories found." in out


def test_badge_helper() -> None:
    assert badge_for_band(PriorityBand.CRITICAL) == "RED"
    assert badge_for_band(PriorityBand.HIGH) == "RED"
    assert badge_for_band(PriorityBand.MEDIUM) == "YELLOW"
    assert badge_for_band(PriorityBand.LOW) == "GREEN"
    assert badge_for_band(PriorityBand.INFO) == "GREEN"


def test_fix_command_per_source() -> None:
    def dep(source: DependencySource) -> Dependency:
        return Dependency(name="flask", raw_name="Flask", version="0.12", source=source)

    assert fix_command(dep(DependencySource.REQUIREMENTS_TXT)) == "pip install --upgrade Flask"
    assert fix_command(dep(DependencySource.POETRY_LOCK)) == "poetry update Flask"
    assert fix_command(dep(DependencySource.PIPFILE_LOCK)) == "pipenv update Flask"


def test_render_snapshot() -> None:
    out = render_to_string(_sample_findings(), width=100)
    SNAP.mkdir(parents=True, exist_ok=True)
    expected = SNAP / "cards.txt"
    if not expected.exists():
        expected.write_text(out, encoding="utf-8")
    assert out == expected.read_text(encoding="utf-8")
