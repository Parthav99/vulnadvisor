"""Model for the dynamic-coverage overlay: runtime evidence that annotates a static finding.

Task 16.6 marries the static reachability/taint structure with *runtime truth* from a
coverage.py JSON report. The overlay never changes a finding's confidence tier or its
deterministic score — soundness and reproducibility hold (tests are not production). It only
attaches a :class:`RuntimeEvidence` annotation, displayed *alongside* the tier:

* ``RUNTIME_CONFIRMED`` — coverage proves a line tied to the finding (an import site, a call-path
  step, or a sink/flow location) executed. This shrinks the ambiguous tiers with proof rather than
  optimism; it is escalation-only (KEV-style), so it can only raise concern, never lower it.
* ``NOT_OBSERVED`` — the suite ran over the finding's files but none of its lines executed. This is
  *advisory only* and **must never downgrade a tier**: a value not exercised by the test suite is
  not proven safe in production.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class RuntimeStatus(str, Enum):
    """Whether runtime coverage confirmed, or merely failed to observe, a finding's code.

    * ``RUNTIME_CONFIRMED`` — at least one line tied to the finding executed under the suite.
    * ``NOT_OBSERVED`` — the finding's files were covered, but none of its lines ran (advisory).
    """

    RUNTIME_CONFIRMED = "runtime-confirmed"
    NOT_OBSERVED = "not-observed"


class ObservedLine(BaseModel):
    """A first-party ``file:line`` that the coverage report proves executed."""

    model_config = ConfigDict(frozen=True)

    file: str
    line: int


class RuntimeEvidence(BaseModel):
    """The coverage overlay's verdict for one finding, with the executed lines behind it.

    Attributes:
        status: ``RUNTIME_CONFIRMED`` (lines executed) or ``NOT_OBSERVED`` (covered, none ran).
        reason: Plain-text explanation of what coverage did and did not show.
        observed: The executed ``file:line`` evidence (empty for ``NOT_OBSERVED``).
    """

    model_config = ConfigDict(frozen=True)

    status: RuntimeStatus
    reason: str
    observed: tuple[ObservedLine, ...] = ()

    @property
    def is_confirmed(self) -> bool:
        """Whether runtime coverage confirmed the finding's code executed."""
        return self.status is RuntimeStatus.RUNTIME_CONFIRMED
