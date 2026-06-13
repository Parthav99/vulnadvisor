"""Model: pydantic models shared across packages."""

from vulnadvisor.model.advisory import (
    Advisory,
    AdvisoryReference,
    AffectedPackage,
    AffectedRange,
    EpssScore,
    MatchedAdvisory,
    MatchResult,
)
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.display import display_id, display_title, select_display_id
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
from vulnadvisor.model.runtime import ObservedLine, RuntimeEvidence, RuntimeStatus
from vulnadvisor.model.safe_fix import SafeFix
from vulnadvisor.model.score import PriorityBand, Score, ScoredFinding
from vulnadvisor.model.symbols import (
    ExtractionStatus,
    SymbolExtraction,
    SymbolKind,
    VulnerableSymbol,
)

__all__ = [
    "Advisory",
    "AdvisoryReference",
    "AffectedPackage",
    "AffectedRange",
    "CallPath",
    "CallStep",
    "Dependency",
    "DependencySource",
    "DynamicImportKind",
    "DynamicImportSite",
    "EpssScore",
    "ExtractionStatus",
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
    "ObservedLine",
    "PriorityBand",
    "Reachability",
    "ReachabilityTier",
    "RuntimeEvidence",
    "RuntimeStatus",
    "SafeFix",
    "Score",
    "ScoredFinding",
    "SymbolExtraction",
    "SymbolKind",
    "VulnerableSymbol",
    "display_id",
    "display_title",
    "select_display_id",
]
