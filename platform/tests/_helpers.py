"""Shared test helper: build a real ``vulnadvisor`` JSON report from the actual engine.

Using ``build_report`` over real ``score_match`` findings means the platform tests exercise the
exact JSON the CLI emits, proving the two never diverge.
"""

from typing import Any

from vulnadvisor.engine.scoring import score_match
from vulnadvisor.model import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
)
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.output.json_report import build_report


def scored(name: str, advisory_id: str, *, version: str = "1.0", tier: str | None = None) -> Any:
    """A real ScoredFinding for ``name``/``advisory_id``; optional reachability ``tier``."""
    matched = MatchedAdvisory(
        dependency=Dependency(
            name=name,
            raw_name=name,
            version=version,
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id=advisory_id,
            aliases=(f"CVE-2024-{abs(hash(advisory_id)) % 9999:04d}",),
            summary=f"{name} vulnerability",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected=(
                AffectedPackage(name=name, ranges=(AffectedRange(introduced="0", fixed="99"),)),
            ),
        ),
        epss=EpssScore(cve="CVE-2024-0001", probability=0.5, percentile=0.9),
        in_kev=True,
    )
    reachability = (
        Reachability(tier=ReachabilityTier(tier), reason="test") if tier is not None else None
    )
    return score_match(matched, reachability)


def build_report_doc(specs: list[tuple[str, str]]) -> dict[str, Any]:
    """A real engine JSON report for the given ``(package, advisory_id)`` findings."""
    findings = [scored(name, advisory_id) for name, advisory_id in specs]
    return build_report(findings, [], tool_version="1.0.3")


def build_report_with_tiers(specs: list[tuple[str, str, str]]) -> dict[str, Any]:
    """A real report for ``(package, advisory_id, tier)`` findings (for trend categorization)."""
    findings = [scored(name, advisory_id, tier=tier) for name, advisory_id, tier in specs]
    return build_report(findings, [], tool_version="1.0.3")
