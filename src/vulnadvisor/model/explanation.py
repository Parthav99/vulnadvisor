"""The plain-English explanation of a finding (Card A "attack story").

This is *only* narrative: it carries no score and cannot influence priority — the engine computes
priority deterministically and the LLM merely explains the result. ``source`` records whether the
text came from the language model or the deterministic template fallback, so the UI can be honest
about its provenance.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class ExplanationSource(str, Enum):
    """Where an :class:`Explanation` came from."""

    LLM = "llm"
    TEMPLATE = "template"


class Explanation(BaseModel):
    """A human-readable attack story plus a one-line verdict rationale for one finding."""

    model_config = ConfigDict(frozen=True)

    attack_story: str
    verdict_rationale: str
    source: ExplanationSource
