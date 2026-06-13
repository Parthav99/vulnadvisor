"""Models for the deterministic priority score and the verdict it drives."""

from enum import Enum

from pydantic import BaseModel, ConfigDict

from vulnadvisor.model.advisory import MatchedAdvisory
from vulnadvisor.model.reachability import Reachability
from vulnadvisor.model.runtime import RuntimeEvidence


class PriorityBand(str, Enum):
    """Coarse priority band a numeric score falls into, driving the verdict label."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Score(BaseModel):
    """A deterministic priority score for one finding, with the inputs that produced it.

    Attributes:
        value: Priority on a 0-100 scale (higher = more urgent).
        band: The :class:`PriorityBand` ``value`` falls into.
        verdict: Human-facing action label for the band (e.g. "Fix this sprint").
        cvss_base: The computed CVSS base score, or ``None`` when unknown.
        cvss_used: The severity actually fed into the formula (the default when unknown).
        cvss_known: Whether ``cvss_base`` was known (``False`` means a default was assumed).
        epss_probability: EPSS exploit probability used, or ``None`` when unknown.
        in_kev: Whether the vulnerability is in the CISA KEV catalog.
        rationale: Plain-text explanation of the signals behind the score.
    """

    model_config = ConfigDict(frozen=True)

    value: float
    band: PriorityBand
    verdict: str
    cvss_base: float | None
    cvss_used: float
    cvss_known: bool
    epss_probability: float | None
    in_kev: bool
    rationale: str


class ScoredFinding(BaseModel):
    """A matched advisory paired with its deterministic score and reachability tier.

    ``runtime`` is an optional dynamic-coverage annotation (Task 16.6): runtime evidence that the
    finding's code did (or did not) execute under a test suite. It is set only by the coverage
    overlay and never changes ``score`` or ``reachability.tier`` — escalation-only, advisory at
    most (see :class:`~vulnadvisor.model.runtime.RuntimeEvidence`).
    """

    model_config = ConfigDict(frozen=True)

    matched: MatchedAdvisory
    score: Score
    reachability: Reachability | None = None
    runtime: RuntimeEvidence | None = None
