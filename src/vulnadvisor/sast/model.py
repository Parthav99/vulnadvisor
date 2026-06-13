"""Models for the SAST engine — confidence tiers and located sink hits (docs/sast-design.md §4).

These are deliberately separate from the SCA reachability models: a first-party finding is about a
*flow* from a source to a sink, not about whether a dependency is imported, so it carries its own
tier vocabulary. Task 16.2 produces the intra-procedural :class:`SinkHit`s; Task 16.3 proves the
source->sink flow and refines the tier.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict

from vulnadvisor.model.callpath import CallPath
from vulnadvisor.model.score import Score


class SastTier(str, Enum):
    """Confidence tier for a first-party (SAST) finding.

    Ordered most-concerning to least (the concern order used for ranking/aggregation):

    * ``CONFIRMED_FLOW`` — a source->sink taint path is proven with no recognized sanitizer on it
      (or, for hardcoded secrets, the secret literal is present in source).
    * ``DYNAMIC_UNKNOWN`` — a dynamic construct on the path blocks certainty; never silently safe.
    * ``POSSIBLE_FLOW`` — the sink is reached with a non-literal argument, but a full source->sink
      taint path is not (yet) proven.
    * ``SANITIZED`` — every path to the sink applies a recognized sanitizer for its CWE, or the
      dangerous argument is a literal constant with no external input. Reported for visibility,
      deprioritized hard, never dropped.
    """

    CONFIRMED_FLOW = "confirmed-flow"
    DYNAMIC_UNKNOWN = "dynamic-unknown"
    POSSIBLE_FLOW = "possible-flow"
    SANITIZED = "sanitized"


class SinkHit(BaseModel):
    """A located sink call (or secret literal) and its intra-procedural taint classification.

    Task 16.2 fills this from a single file with no cross-function knowledge, so ``tier`` is a
    *local* guess: ``SANITIZED`` when the dangerous argument is a literal/recognized-sanitized
    value, ``POSSIBLE_FLOW`` when it is non-literal (pending the taint proof in Task 16.3), or
    ``CONFIRMED_FLOW`` for a hardcoded-secret literal (where the literal itself is the
    vulnerability, so no flow is needed).

    Attributes:
        cwe: The CWE identifier (e.g. ``"CWE-89"``).
        kind: Stable machine id for the sink kind (e.g. ``"sql-injection"``).
        title: Human-readable sink title.
        file: Project-relative POSIX path of the source file.
        line: 1-based line of the sink call / secret literal.
        col: 0-based column offset.
        callee: The resolved callee display (e.g. ``"yaml.load"``) or ``"<string literal>"`` /
            the secret-named target for hardcoded secrets.
        tier: The intra-procedural :class:`SastTier` guess.
        reason: Plain-text explanation of why this tier was assigned.
    """

    model_config = ConfigDict(frozen=True)

    cwe: str
    kind: str
    title: str
    file: str
    line: int
    col: int
    callee: str
    tier: SastTier
    reason: str


# Concern ordering (most -> least), per docs/sast-design.md §4: a CONFIRMED flow outranks a dynamic
# block, which outranks an unproven-source sink, which outranks a sanitized one. Used to pick the
# highest-concern tier when the taint engine (16.3) escalates an intra-procedural baseline hit.
_TIER_CONCERN: dict[SastTier, int] = {
    SastTier.CONFIRMED_FLOW: 3,
    SastTier.DYNAMIC_UNKNOWN: 2,
    SastTier.POSSIBLE_FLOW: 1,
    SastTier.SANITIZED: 0,
}


def tier_concern(tier: SastTier) -> int:
    """Return the concern rank of ``tier`` (higher == more alarming) for ranking/escalation."""
    return _TIER_CONCERN[tier]


class SastFinding(BaseModel):
    """A first-party finding with its proven (or refined) confidence tier and evidence path.

    Task 16.3 produces these by taking the intra-procedural :class:`SinkHit`s from Task 16.2 as a
    floor and *escalating* the ones it can tie to a real taint source: a sink reached by a value
    that flows from a recognized source (a framework entry-point parameter, ``stdin``/``argv``/the
    environment, or a Flask request global) with no sanitizer on the path becomes
    ``CONFIRMED_FLOW`` and carries the source->sink :class:`~vulnadvisor.model.callpath.CallPath` as
    evidence; a path crossing a dynamic construct becomes ``DYNAMIC_UNKNOWN``. Sinks the engine
    cannot tie to a source keep their intra-procedural tier and have ``flow is None``.

    Attributes:
        cwe / kind / title / file / line / col / callee / tier / reason: as :class:`SinkHit`.
        source_kind: The taint source kind for an escalated finding (e.g. ``"http-parameter"``,
            ``"argv"``, ``"environment"``, ``"flask-request"``), or ``None`` when not flow-proven.
        flow: The source->sink call path (same shape as SCA reachability evidence), or ``None``.
    """

    model_config = ConfigDict(frozen=True)

    cwe: str
    kind: str
    title: str
    file: str
    line: int
    col: int
    callee: str
    tier: SastTier
    reason: str
    source_kind: str | None = None
    flow: CallPath | None = None

    @classmethod
    def from_sink_hit(cls, hit: SinkHit) -> "SastFinding":
        """Lift an intra-procedural :class:`SinkHit` into a finding with no proven flow."""
        return cls(
            cwe=hit.cwe,
            kind=hit.kind,
            title=hit.title,
            file=hit.file,
            line=hit.line,
            col=hit.col,
            callee=hit.callee,
            tier=hit.tier,
            reason=hit.reason,
        )


class ScoredSastFinding(BaseModel):
    """A first-party :class:`SastFinding` paired with its deterministic priority score.

    The SAST analogue of :class:`~vulnadvisor.model.score.ScoredFinding`: the engine assigns the
    priority (CWE base severity discounted by the confidence tier — see
    :mod:`vulnadvisor.engine.sast_scoring`), reproducibly and without the LLM. Findings of both
    kinds are ranked together into the one ranked list the CLI, JSON, and SARIF emit (Task 16.4).
    """

    model_config = ConfigDict(frozen=True)

    finding: SastFinding
    score: Score
