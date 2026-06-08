"""Model for the reachability tier of a finding (per instructions.md confidence tiers)."""

from enum import Enum

from pydantic import BaseModel, ConfigDict

from vulnadvisor.model.imports import DynamicImportSite, ImportSite


class ReachabilityTier(str, Enum):
    """Confidence tier for whether a vulnerable package is reachable from the user's code.

    Ordered most-concerning to least:

    * ``IMPORTED_AND_CALLED`` — a concrete call path exists (function-level, Task 6).
    * ``IMPORTED`` — the package is imported; no confirmed call yet.
    * ``DYNAMIC_UNKNOWN`` — dynamic import/exec, unreadable files, or an uncertain import-name
      mapping mean usage cannot be ruled out. Never treat as safe.
    * ``NOT_IMPORTED`` — the package is never imported. The only confidently-safe tier.
    """

    IMPORTED_AND_CALLED = "imported-and-called"
    IMPORTED = "imported"
    DYNAMIC_UNKNOWN = "dynamic-unknown"
    NOT_IMPORTED = "not-imported"


class Reachability(BaseModel):
    """The reachability verdict for one finding, with the evidence behind it.

    Attributes:
        tier: The assigned :class:`ReachabilityTier`.
        reason: Plain-text explanation (includes a file:line for imported packages).
        evidence: Import sites proving the package is imported (for IMPORTED tiers).
        dynamic_evidence: Dynamic-import/exec sites that block certainty (for DYNAMIC_UNKNOWN).
    """

    model_config = ConfigDict(frozen=True)

    tier: ReachabilityTier
    reason: str
    evidence: tuple[ImportSite, ...] = ()
    dynamic_evidence: tuple[DynamicImportSite, ...] = ()

    @property
    def is_confidently_safe(self) -> bool:
        """Whether this finding is in the only confidently-safe tier (NOT_IMPORTED)."""
        return self.tier is ReachabilityTier.NOT_IMPORTED
