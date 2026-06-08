"""Model: pydantic models shared across packages."""

from vulnadvisor.model.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EpssScore,
    MatchedAdvisory,
    MatchResult,
)
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.import_mapping import (
    ImportMapping,
    MappingConfidence,
    MappingSource,
)
from vulnadvisor.model.imports import (
    DynamicImportKind,
    DynamicImportSite,
    ImportedName,
    ImportGraph,
    ImportKind,
    ImportParseError,
    ImportSite,
)
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.model.safe_fix import SafeFix
from vulnadvisor.model.score import PriorityBand, Score, ScoredFinding

__all__ = [
    "Advisory",
    "AffectedPackage",
    "AffectedRange",
    "Dependency",
    "DependencySource",
    "DynamicImportKind",
    "DynamicImportSite",
    "EpssScore",
    "ImportGraph",
    "ImportKind",
    "ImportMapping",
    "ImportParseError",
    "ImportSite",
    "ImportedName",
    "MappingConfidence",
    "MappingSource",
    "MatchResult",
    "MatchedAdvisory",
    "PriorityBand",
    "Reachability",
    "ReachabilityTier",
    "SafeFix",
    "Score",
    "ScoredFinding",
]
