# File: src/vulnadvisor/model/fix.py
"""Models for ``vulnadvisor fix`` — the validated, machine-proven patch (Task 17.1).

A fix is only a fix if the machine can prove it. The LLM proposes a :class:`FixSuggestion`
(a unified diff plus a rationale and a self-reported confidence); the deterministic validation
loop then *proves* it by applying the patch to a throwaway copy of the project and running a
fixed sequence of checks (:class:`ValidationStep`), recorded in a :class:`ValidationReport`. A
patch is only ever surfaced to the user when every step passes — never an unvalidated patch.

These models are pure and frozen so the loop's bookkeeping (:class:`FixAttempt`,
:class:`FixResult`) is reproducible and trivially testable.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict

__all__ = [
    "FixAttempt",
    "FixConfidence",
    "FixOutcome",
    "FixProvenance",
    "FixResult",
    "FixSuggestion",
    "StepStatus",
    "ValidationReport",
    "ValidationStep",
]


class FixConfidence(str, Enum):
    """The model's self-reported confidence in a proposed patch (never affects validation)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FixProvenance(str, Enum):
    """Where a patch came from — a deterministic quick-fix rewrite or the language model.

    Both kinds clear the *same* validation loop before they are ever emitted (Task 19.3); this only
    records *how* the candidate was produced so the dashboard can badge a high-confidence
    deterministic rewrite distinctly from a model-authored one (Task 19.4). It never affects
    validation or the deterministic verdict.
    """

    DETERMINISTIC = "deterministic"
    MODEL = "model"


class FixSuggestion(BaseModel):
    """One candidate patch from the model: a unified diff plus prose, strictly validated.

    Attributes:
        diff: A unified diff (``--- a/<path>`` / ``+++ b/<path>`` hunks) relative to the project
            root, applied with ``git apply -p1``.
        rationale: Plain-English explanation of what the patch changes and why it is safe.
        confidence: The model's self-reported confidence — advisory only; the validation loop, not
            this value, decides whether a patch is emitted.
        provenance: How the candidate was produced — a deterministic quick-fix or the model
            (Task 19.3). Advisory only; both kinds pass the same validator before being emitted.
    """

    model_config = ConfigDict(frozen=True)

    diff: str
    rationale: str
    confidence: FixConfidence = FixConfidence.MEDIUM
    provenance: FixProvenance = FixProvenance.MODEL


class StepStatus(str, Enum):
    """Outcome of a single validation step."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"  # the step did not apply (tool absent, or not configured for the project)


class ValidationStep(BaseModel):
    """The result of one validation stage (apply / syntax / ruff / mypy / tests / rescan).

    Attributes:
        name: Stable step id (e.g. ``"apply"``, ``"rescan"``).
        status: Whether the step passed, failed, or was skipped.
        detail: Diagnostic text (tool stderr, a re-scan explanation, or why it was skipped).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    status: StepStatus
    detail: str = ""


class ValidationReport(BaseModel):
    """The full outcome of validating one :class:`FixSuggestion` against a copy of the project.

    ``ok`` is true only when no step failed. The steps are recorded in execution order; the loop
    stops at the first failure, so a failed report ends on the step that failed.
    """

    model_config = ConfigDict(frozen=True)

    ok: bool
    steps: tuple[ValidationStep, ...]

    def first_failure(self) -> ValidationStep | None:
        """Return the first failed step, or ``None`` when every step passed."""
        for step in self.steps:
            if step.status is StepStatus.FAILED:
                return step
        return None

    def failure_feedback(self) -> str:
        """A compact description of the failure, suitable to feed back to the model for a retry."""
        failure = self.first_failure()
        if failure is None:
            return ""
        detail = failure.detail.strip()
        if detail:
            return f"the '{failure.name}' check failed: {detail}"
        return f"the '{failure.name}' check failed"


class FixAttempt(BaseModel):
    """One iteration of the fix loop: what the model returned and how validation went.

    ``suggestion`` is ``None`` when the model's response could not be parsed into a patch (a parse
    failure is still a recorded attempt). ``report`` is ``None`` when there was nothing to validate
    (no parseable suggestion, or the model call itself failed — see ``note``).
    """

    model_config = ConfigDict(frozen=True)

    suggestion: FixSuggestion | None = None
    report: ValidationReport | None = None
    note: str = ""


class FixOutcome(str, Enum):
    """The terminal outcome of a fix run."""

    VALIDATED = "validated"  # a patch passed the full validation loop
    NO_SAFE_FIX = "no-safe-fix"  # no candidate passed within the attempt budget


class FixResult(BaseModel):
    """The result of running the fix loop for one finding.

    ``suggestion`` is the validated patch when ``outcome`` is ``VALIDATED``, else ``None`` (no
    unvalidated patch is ever returned). ``attempts`` records every iteration for transparency.
    """

    model_config = ConfigDict(frozen=True)

    outcome: FixOutcome
    suggestion: FixSuggestion | None
    attempts: tuple[FixAttempt, ...]
