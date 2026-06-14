# File: src/vulnadvisor/model/suggestion.py
"""Models for ``vulnadvisor fix --suggest-json`` — validated fixes shipped to the PR agent (17.2).

Task 17.1 proves a single patch interactively; Task 17.2 runs that same machine-validated loop in
CI over *every* fixable first-party finding and emits a small JSON document the platform's GitHub
App turns into in-line ``suggestion`` review comments. Only validated patches appear here — the
soundness rule from 17.1 carries over verbatim: an unvalidated patch is never emitted, so it can
never be suggested for one-click commit.

These models are pure and frozen. The document is intentionally self-contained (it carries the
engine facts needed to render the 3-card story PR-side) so the platform never re-runs the engine.
"""

from pydantic import BaseModel, ConfigDict

from vulnadvisor.model.fix import FixConfidence

__all__ = ["SUGGESTION_SCHEMA_VERSION", "SuggestionReport", "ValidatedFix"]

# Bumped only on a breaking change to the document shape; the platform parser accepts this set.
SUGGESTION_SCHEMA_VERSION = "1.0"


class ValidatedFix(BaseModel):
    """One machine-validated patch for a first-party (SAST) finding, ready to suggest on a PR.

    Carries both the patch (``diff`` — a unified diff the platform splits into ``suggestion``
    blocks) and the engine facts the PR comment needs to tell the attack story without re-scanning:
    the CWE/kind/title, the confidence ``tier``, and the rendered source->sink ``flow``.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    file: str
    line: int
    cwe: str
    kind: str
    title: str
    tier: str
    flow: str
    rationale: str
    confidence: FixConfidence
    diff: str


class SuggestionReport(BaseModel):
    """The full set of validated fixes from one ``fix --suggest-json`` run, uploaded with the scan.

    ``schema_version`` lets the platform reject a shape it does not understand rather than guessing.
    A run that found no safe fix produces an empty ``fixes`` list (still a valid, uploadable doc).
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str = SUGGESTION_SCHEMA_VERSION
    tool_version: str
    fixes: tuple[ValidatedFix, ...] = ()
