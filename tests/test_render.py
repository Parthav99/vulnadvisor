from pathlib import Path

from vulnadvisor.cli.render import (
    badge_for_band,
    render_to_string,
)
from vulnadvisor.model import (
    PriorityBand,
    ScoredFinding,
)

SNAP = Path(__file__).resolve().parent.parent / "fixtures" / "snapshots"


def test_render_contains_three_cards_and_badges(
    sample_findings: list[ScoredFinding],
) -> None:
    out = render_to_string(sample_findings)
    assert "2 finding(s), highest priority first" in out
    assert "A - Attack summary" in out
    assert "B - Risk" in out
    assert "C - Action" in out
    assert "Badge: RED" in out
    assert "Badge: GREEN" in out
    assert "Fix now" in out
    assert "Monitor" in out
    assert 'Fix: pip install --upgrade "Jinja2>=2.10.1"' in out
    assert "Minimal safe upgrade: 2.10.1." in out


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


def test_render_snapshot(sample_findings: list[ScoredFinding]) -> None:
    out = render_to_string(sample_findings, width=100)
    SNAP.mkdir(parents=True, exist_ok=True)
    expected = SNAP / "cards.txt"
    if not expected.exists():
        expected.write_text(out, encoding="utf-8")
    assert out == expected.read_text(encoding="utf-8")
