"""Model: pydantic models shared across packages."""

from vulnadvisor.model.advisory import (
    Advisory,
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
from vulnadvisor.model.score import PriorityBand, Score, ScoredFinding

__all__ = [
    "Advisory",
    "Dependency",
    "DependencySource",
    "EpssScore",
    "ImportMapping",
    "MappingConfidence",
    "MappingSource",
    "MatchResult",
    "MatchedAdvisory",
    "PriorityBand",
    "Score",
    "ScoredFinding",
]
