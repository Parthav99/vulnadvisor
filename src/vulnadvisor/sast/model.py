"""Models for the SAST engine — confidence tiers and located sink hits (docs/sast-design.md §4).

These are deliberately separate from the SCA reachability models: a first-party finding is about a
*flow* from a source to a sink, not about whether a dependency is imported, so it carries its own
tier vocabulary. Task 16.2 produces the intra-procedural :class:`SinkHit`s; Task 16.3 proves the
source->sink flow and refines the tier.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict


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
