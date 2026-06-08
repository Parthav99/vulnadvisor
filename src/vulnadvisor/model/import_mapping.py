"""Model describing how a distribution name resolves to importable module names."""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class MappingConfidence(str, Enum):
    """How trustworthy a distribution-to-import-name mapping is.

    ``HIGH`` comes from the installed package's own metadata; ``MEDIUM`` from our curated table
    of known-tricky names; ``LOW`` is a best-guess normalization that may be wrong.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MappingSource(str, Enum):
    """Which resolution strategy produced a mapping."""

    METADATA = "metadata"
    CURATED = "curated"
    GUESS = "guess"


class ImportMapping(BaseModel):
    """The set of top-level import names a distribution provides.

    Attributes:
        distribution: PEP 503 canonical distribution name that was resolved.
        import_names: Top-level importable names (e.g. ``("yaml",)`` for ``PyYAML``). May contain
            more than one. Empty only if resolution produced nothing usable (should not happen:
            the resolver always falls back to a best guess).
        confidence: How much to trust this mapping (drives soundness escalation downstream).
        source: Which strategy produced the mapping.
    """

    model_config = ConfigDict(frozen=True)

    distribution: str
    import_names: tuple[str, ...]
    confidence: MappingConfidence
    source: MappingSource
