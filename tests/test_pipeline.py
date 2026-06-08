from collections.abc import Callable
from pathlib import Path

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.cli.pipeline import scan_project


def test_scan_project_returns_ranked_findings(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    report = scan_project(tmp_path, fake_matcher())

    assert report.degraded_sources == ()
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.matched.dependency.name == "jinja2"
    assert finding.matched.in_kev is True
    assert finding.score.band.value == "critical"


def test_scan_project_flags_degraded_on_outage(
    tmp_path: Path, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    report = scan_project(tmp_path, fake_matcher({"OSV"}))

    assert "OSV" in report.degraded_sources
    assert report.findings == []
