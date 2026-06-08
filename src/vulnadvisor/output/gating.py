"""``--fail-on`` threshold parsing and the CI exit-code decision.

``--fail-on`` accepts either a band name (``critical``/``high``/``medium``/``low``/``info``) or a
numeric score (0-100). A scan exits non-zero when **any** finding meets or exceeds the threshold.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from vulnadvisor.model.score import PriorityBand, ScoredFinding

__all__ = ["EXIT_FINDINGS", "EXIT_OK", "FailOn", "parse_fail_on", "should_fail"]

EXIT_OK = 0
EXIT_FINDINGS = 1

# Band order from least to most severe; index gives a comparable rank.
_BAND_ORDER: tuple[PriorityBand, ...] = (
    PriorityBand.INFO,
    PriorityBand.LOW,
    PriorityBand.MEDIUM,
    PriorityBand.HIGH,
    PriorityBand.CRITICAL,
)
_BAND_BY_NAME = {band.value: band for band in PriorityBand}


@dataclass(frozen=True)
class FailOn:
    """A parsed ``--fail-on`` threshold: exactly one of ``band`` or ``score`` is set."""

    band: PriorityBand | None = None
    score: float | None = None


def parse_fail_on(value: str) -> FailOn:
    """Parse a ``--fail-on`` value into a :class:`FailOn`.

    Raises:
        ValueError: if ``value`` is neither a known band name nor a number in 0-100.
    """
    text = value.strip().lower()
    if text in _BAND_BY_NAME:
        return FailOn(band=_BAND_BY_NAME[text])
    try:
        number = float(text)
    except ValueError:
        raise ValueError(
            f"invalid --fail-on '{value}': expected a band "
            f"({', '.join(_BAND_BY_NAME)}) or a number 0-100"
        ) from None
    if not 0.0 <= number <= 100.0:
        raise ValueError(f"invalid --fail-on '{value}': score must be between 0 and 100")
    return FailOn(score=number)


def _band_rank(band: PriorityBand) -> int:
    """Return the comparable rank of a band (higher = more severe)."""
    return _BAND_ORDER.index(band)


def should_fail(findings: Sequence[ScoredFinding], fail_on: FailOn) -> bool:
    """Return ``True`` when any finding meets or exceeds the ``fail_on`` threshold."""
    if fail_on.score is not None:
        return any(finding.score.value >= fail_on.score for finding in findings)
    if fail_on.band is not None:
        threshold = _band_rank(fail_on.band)
        return any(_band_rank(finding.score.band) >= threshold for finding in findings)
    return False
