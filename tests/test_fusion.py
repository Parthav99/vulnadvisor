"""Task 21.3 — reachability overlay + dedup/fusion of external findings (fusion-design §4–§5).

These exercise the soundness core: an external finding our taint engine corroborates inherits our
tier + evidence and merges (both provenances kept); one we cannot overlay escalates to
``DYNAMIC_UNKNOWN`` and is never dropped, never ``SANITIZED``; the merged list is deterministic and
loses no external finding (the §4.1 release-blocking invariant).
"""

import pytest

from vulnadvisor.engine.sast_scoring import order_unified, score_sast_findings
from vulnadvisor.model.callpath import CallPath, CallStep
from vulnadvisor.sast.external.fusion import (
    external_findings_represented,
    fuse_findings,
    merge_provenance,
)
from vulnadvisor.sast.external.semgrep import SEMGREP_TOOL
from vulnadvisor.sast.model import NATIVE_PROVENANCE, SastFinding, SastTier


def _native(
    *,
    cwe: str = "CWE-89",
    kind: str = "sql-injection",
    file: str = "app.py",
    line: int = 10,
    col: int = 4,
    tier: SastTier = SastTier.CONFIRMED_FLOW,
    with_flow: bool = True,
) -> SastFinding:
    """A native finding, optionally carrying a source->sink path (the richer evidence)."""
    flow = (
        CallPath(
            steps=(
                CallStep(qualname="handler"),
                CallStep(qualname="db.run", file=file, line=line),
            )
        )
        if with_flow
        else None
    )
    return SastFinding(
        cwe=cwe,
        kind=kind,
        title="SQL injection",
        file=file,
        line=line,
        col=col,
        callee="cursor.execute",
        tier=tier,
        reason="native",
        source_kind="http-parameter" if with_flow else None,
        flow=flow,
    )


def _external(
    *,
    cwe: str = "CWE-89",
    kind: str = "sql-injection",
    file: str = "app.py",
    line: int = 10,
    col: int = 4,
    tool: str = SEMGREP_TOOL,
) -> SastFinding:
    """A pre-overlay external finding (``DYNAMIC_UNKNOWN`` floor, no flow), as ``normalize``s."""
    return SastFinding(
        cwe=cwe,
        kind=kind,
        title="SQL injection",
        file=file,
        line=line,
        col=col,
        callee="python.lang.security.sqli",
        tier=SastTier.DYNAMIC_UNKNOWN,
        reason="Located by Semgrep OSS; overlay pending.",
        provenance=(tool,),
    )


# --- overlay: agreement → CONFIRMED-FLOW with our path, both provenances --------------------------


def test_external_corroborating_native_inherits_confirmed_flow_and_path() -> None:
    native = _native(tier=SastTier.CONFIRMED_FLOW, with_flow=True)
    merged = fuse_findings([native], [_external()])

    assert len(merged) == 1
    (record,) = merged
    assert record.tier is SastTier.CONFIRMED_FLOW
    assert record.flow is not None  # our source->sink evidence survives the merge
    assert record.provenance == (NATIVE_PROVENANCE, SEMGREP_TOOL)


@pytest.mark.parametrize(
    "native_tier",
    [SastTier.POSSIBLE_FLOW, SastTier.SANITIZED, SastTier.DYNAMIC_UNKNOWN],
)
def test_native_tier_governs_over_external_floor(native_tier: SastTier) -> None:
    # The external arrives at the DYNAMIC_UNKNOWN floor; corroboration must NOT inflate a
    # POSSIBLE_FLOW/SANITIZED sink to the floor — our engine's determination governs (§4).
    native = _native(tier=native_tier, with_flow=False)
    merged = fuse_findings([native], [_external()])

    assert len(merged) == 1
    assert merged[0].tier is native_tier
    assert merged[0].provenance == (NATIVE_PROVENANCE, SEMGREP_TOOL)


# --- overlay: can't locate / disagree → escalate, never drop, never sanitize ----------------------


def test_unoverlayable_external_escalates_and_survives() -> None:
    # Semgrep flags a CWE our native engine produced no finding for: we cannot overlay it.
    external = _external(cwe="CWE-1004", kind="external-finding", line=42)
    merged = fuse_findings([_native()], [external])

    assert len(merged) == 2  # native + the un-overlayable external, both kept
    escalated = next(f for f in merged if SEMGREP_TOOL in f.provenance and f.line == 42)
    assert escalated.tier is SastTier.DYNAMIC_UNKNOWN
    assert escalated.tier is not SastTier.SANITIZED
    assert "could not overlay" in escalated.reason


def test_external_without_cwe_escalates_separately() -> None:
    external = _external(cwe="", kind="external-finding", line=5)
    merged = fuse_findings([_native()], [external])

    assert len(merged) == 2
    escalated = next(f for f in merged if SEMGREP_TOOL in f.provenance)
    assert escalated.tier is SastTier.DYNAMIC_UNKNOWN
    assert "no resolvable CWE" in escalated.reason


def test_different_cwe_same_line_does_not_merge() -> None:
    # Two genuinely different weaknesses on one line stay two records (§5: CWE is part of the key).
    native = _native(cwe="CWE-78", kind="command-injection", line=10)
    external = _external(cwe="CWE-89", line=10)
    merged = fuse_findings([native], [external])

    assert len(merged) == 2
    assert {f.cwe for f in merged} == {"CWE-78", "CWE-89"}


# --- dedup / ±1 tolerance -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ext_line", "expect_merge"),
    [(9, True), (10, True), (11, True), (12, False)],
)
def test_line_tolerance_is_plus_or_minus_one(ext_line: int, expect_merge: bool) -> None:
    native = _native(line=10)
    merged = fuse_findings([native], [_external(line=ext_line)])

    if expect_merge:
        assert len(merged) == 1
        assert merged[0].provenance == (NATIVE_PROVENANCE, SEMGREP_TOOL)
    else:
        assert len(merged) == 2


def test_two_same_tool_externals_on_adjacent_lines_stay_distinct() -> None:
    # ±1 absorbs cross-tool drift, NOT same-tool findings — collapsing them would drop a finding.
    merged = fuse_findings([], [_external(line=10), _external(line=11)])
    assert len(merged) == 2
    assert all(f.tier is SastTier.DYNAMIC_UNKNOWN for f in merged)


def test_native_findings_are_never_merged_with_each_other() -> None:
    # Two distinct native sinks of the same CWE on adjacent lines must both survive.
    a = _native(line=10, with_flow=True)
    b = _native(line=11, with_flow=True)
    merged = fuse_findings([a, b], [])
    assert len(merged) == 2


# --- soundness invariant: no external finding silently lost (§4.1, release-blocking) --------------


def test_no_external_finding_is_silently_lost() -> None:
    native = [_native(line=10), _native(cwe="CWE-78", kind="command-injection", line=20)]
    external = [
        _external(line=10),  # corroborates native[0]
        _external(cwe="CWE-1004", kind="external-finding", line=30),  # un-overlayable
        _external(cwe="", kind="external-finding", line=40),  # no CWE
    ]
    merged = fuse_findings(native, external)
    assert external_findings_represented(external, merged)


def test_representation_fails_when_an_external_is_dropped() -> None:
    external = [_external(line=10)]
    # A merged list missing the external (only the bare native) must read as "not represented".
    assert not external_findings_represented(external, [_native(line=10)])


# --- provenance + determinism ---------------------------------------------------------------------


def test_merge_provenance_puts_vulnadvisor_first_and_dedupes() -> None:
    assert merge_provenance((SEMGREP_TOOL,), (NATIVE_PROVENANCE,)) == (
        NATIVE_PROVENANCE,
        SEMGREP_TOOL,
    )
    assert merge_provenance((NATIVE_PROVENANCE,), (NATIVE_PROVENANCE,)) == (NATIVE_PROVENANCE,)


def test_fusion_and_ordering_are_deterministic() -> None:
    native = [_native(line=10), _native(cwe="CWE-78", kind="command-injection", line=20)]
    external = [_external(line=11), _external(cwe="CWE-94", kind="external-finding", line=5)]

    first = fuse_findings(native, external)
    # Same inputs in a different order produce the identical merged set and ordering.
    second = fuse_findings(list(reversed(native)), list(reversed(external)))
    assert set(first) == set(second)

    order_a = [f.finding for f in order_unified(score_sast_findings(first))]
    order_b = [f.finding for f in order_unified(score_sast_findings(second))]
    assert order_a == order_b
