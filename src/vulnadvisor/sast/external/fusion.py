"""Reachability overlay + dedup/merge of external findings into our list (Task 21.3).

This is the soundness core of fusion (``docs/fusion-design.md`` §4–§5). An external scanner (Task
21.2's :class:`~vulnadvisor.sast.external.semgrep.SemgrepAdapter`) hands us a flat list of
pattern matches, each at the soundness floor (``DYNAMIC_UNKNOWN``, ``flow is None``). Here we:

1. **Overlay** each external finding with what our own taint engine independently proved about the
   same location: if a native finding sits at the same ``(file, line±1, cwe)``, the external finding
   *corroborates* it and we merge the two — the survivor carries our richer evidence (the
   ``CONFIRMED_FLOW`` tier and source->sink path when we have one) and **both** provenances. An
   external finding we **cannot** locate or overlay never disappears and never reads as safe: it
   escalates to ``DYNAMIC_UNKNOWN`` (the soundness floor, §4 last row) and stays in the list.
2. **Dedup/merge** by ``(file, normalized_line, cwe)`` with ±1 line tolerance (§5 / §12.1) so the
   same call flagged by two tools becomes **one** record, the richer-evidence one displayed, with
   every provenance preserved (corroboration is a feature we show, not a duplicate we hide).

The release-blocking invariant (§4.1): **no external finding is silently lost.** Every external
finding is represented in the merged list — either as the survivor of a merge whose provenance now
includes its tool, or as its own escalated record. :func:`external_findings_represented` asserts
this and is exercised by the gate.

Everything here is pure and deterministic: given the same inputs the merged list (and, after the
existing :func:`~vulnadvisor.engine.sast_scoring.order_unified`, the ordering) is byte-for-byte
reproducible — no clock, no set-iteration order leaking out.
"""

from collections.abc import Sequence

from vulnadvisor.sast.model import (
    NATIVE_PROVENANCE,
    SastFinding,
    SastTier,
    tier_concern,
)

__all__ = [
    "LINE_TOLERANCE",
    "external_findings_represented",
    "fuse_findings",
    "merge_provenance",
]

#: Line-attribution drift tolerated when matching the same call across tools (fusion-design §12.1).
#: A near-miss merges rather than showing a duplicate; conservative.
LINE_TOLERANCE = 1


def fuse_findings(
    native: Sequence[SastFinding],
    external: Sequence[SastFinding],
) -> tuple[SastFinding, ...]:
    """Overlay ``external`` findings onto ``native`` and return one merged, de-duplicated list.

    Native findings (from :func:`vulnadvisor.sast.taint.analyze_taint`) already carry their proven
    tier and evidence; external findings (from an adapter's ``normalize``) arrive at the
    ``DYNAMIC_UNKNOWN`` floor. For each external finding we look for a native — or already-merged —
    record at the same ``(file, line±1, cwe)``: a match merges (the richer record wins, both
    provenances kept); no match escalates the external finding to ``DYNAMIC_UNKNOWN`` and keeps it.

    The result is **unordered** by design — ranking is the engine's job
    (:func:`vulnadvisor.engine.sast_scoring.order_unified` after scoring), so this stays a pure
    merge with no priority logic. Inputs are processed in a deterministic order so output is stable.
    """
    # Process in a stable order so a later external can merge into an earlier one deterministically
    # (two tools flagging the same line, or two findings within tolerance, collapse predictably).
    merged: list[SastFinding] = sorted(native, key=_record_order)
    for ext in sorted(external, key=_record_order):
        idx = _best_match(merged, ext)
        if idx is None:
            merged.append(_escalate_unoverlayable(ext))
        else:
            merged[idx] = _merge(merged[idx], ext)
    return tuple(merged)


def _record_order(finding: SastFinding) -> tuple[str, int, int, str, str]:
    """A total, stable order over findings (independent of provenance, for reproducible merging)."""
    return (finding.file, finding.line, finding.col, finding.cwe, finding.kind)


def _same_location(a: SastFinding, b: SastFinding) -> bool:
    """Whether two findings sit at the same merge key: same file + CWE, line within ±1 (§5).

    The CWE is part of the key (§5): two genuinely different weaknesses on one line stay two
    records.
    """
    return a.file == b.file and a.cwe == b.cwe and abs(a.line - b.line) <= LINE_TOLERANCE


def _matches(a: SastFinding, b: SastFinding) -> bool:
    """Whether two findings may be *merged*: same location (§5) **and** a real CWE to corroborate.

    An external finding with no resolvable CWE (``""``) never merges — it cannot be corroborated and
    will escalate to the ``DYNAMIC_UNKNOWN`` floor as its own record, exactly as §4 requires.
    """
    return bool(a.cwe) and _same_location(a, b)


def _best_match(merged: Sequence[SastFinding], ext: SastFinding) -> int | None:
    """Index of the best record in ``merged`` to corroborate ``ext``, or ``None`` for no merge.

    A candidate qualifies when it is the same issue (``_matches``) **and does not already carry
    ``ext``'s tool** — the ±1 tolerance exists to absorb *cross-tool* line drift for one call, so
    two findings from the **same** tool on adjacent lines are genuinely distinct and must stay apart
    (collapsing them would silently drop a finding). Among qualifiers, the closest line wins; ties
    break to the lowest index (``merged`` is kept in stable order), so the choice is deterministic.
    """
    ext_tool = ext.provenance[0] if ext.provenance else ""
    best_idx: int | None = None
    best_delta = LINE_TOLERANCE + 1
    for idx, candidate in enumerate(merged):
        if ext_tool in candidate.provenance or not _matches(candidate, ext):
            continue
        delta = abs(candidate.line - ext.line)
        if delta < best_delta:
            best_idx, best_delta = idx, delta
    return best_idx


def _merge(a: SastFinding, b: SastFinding) -> SastFinding:
    """Merge two corroborating findings into one: the richer-evidence record, with both provenances.

    Survivor selection (§5): a record with a source->sink ``flow`` beats one without; among equals,
    the higher ``tier_concern`` wins; ties go to the native record (our evidence is the one we can
    show), then to a stable id. The survivor keeps its tier, flow, CWE, and reason; only its
    ``provenance`` grows to record that the other tool flagged it too.
    """
    survivor, other = (a, b) if _richer(a, b) else (b, a)
    return survivor.model_copy(
        update={"provenance": merge_provenance(survivor.provenance, other.provenance)}
    )


def _richer(a: SastFinding, b: SastFinding) -> bool:
    """Whether ``a`` is the record to keep over ``b`` (the displayed survivor of a merge).

    A **native** record always wins over a pre-overlay external one: the external's tier is just the
    ``DYNAMIC_UNKNOWN`` floor, not an independent determination, so corroboration adopts *our*
    engine's tier and evidence (the overlay contract, §4) rather than letting the floor inflate a
    ``POSSIBLE_FLOW``/``SANITIZED`` sink. Only when both sides are native (never happens via
    :func:`fuse_findings`) or both external do we compare evidence: a source->sink ``flow`` beats
    none, then higher ``tier_concern``, then a stable id.
    """
    a_native = NATIVE_PROVENANCE in a.provenance
    b_native = NATIVE_PROVENANCE in b.provenance
    if a_native != b_native:
        return a_native
    if (a.flow is not None) != (b.flow is not None):
        return a.flow is not None
    a_concern, b_concern = tier_concern(a.tier), tier_concern(b.tier)
    if a_concern != b_concern:
        return a_concern > b_concern
    return _record_order(a) <= _record_order(b)


def merge_provenance(first: Sequence[str], second: Sequence[str]) -> tuple[str, ...]:
    """Union two provenance lists, deterministically, with ``vulnadvisor`` first (display order).

    Our own engine is always named first when it corroborated the finding ("found by both, ranked by
    VulnAdvisor"); the remaining tools follow in sorted order. Duplicates are dropped.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for tool in (*first, *second):
        if tool not in seen:
            seen.add(tool)
            ordered.append(tool)
    ordered.sort(key=lambda tool: (tool != NATIVE_PROVENANCE, tool))
    return tuple(ordered)


def _escalate_unoverlayable(ext: SastFinding) -> SastFinding:
    """Stamp an external finding we could not overlay as the ``DYNAMIC_UNKNOWN`` soundness floor.

    Per §4 (last row) such a finding is **never** dropped and **never** ``SANITIZED`` — it stays in
    the list naming the gap, so a reachability we could not prove never reads as safety.
    """
    return ext.model_copy(
        update={
            "tier": SastTier.DYNAMIC_UNKNOWN,
            "reason": _unoverlayable_reason(ext),
        }
    )


def _unoverlayable_reason(ext: SastFinding) -> str:
    """Honest reason for an external finding our reachability engine could not place."""
    tools = " / ".join(ext.provenance) or "an external tool"
    if not ext.cwe:
        gap = "no resolvable CWE to corroborate"
    elif ext.flow is not None:  # defensive: should not happen for a pre-overlay external record
        gap = "kept as reported"
    else:
        gap = "VulnAdvisor could not overlay reachability at this location"
    return f"Located by {tools}; {gap} — escalated to DYNAMIC-UNKNOWN (kept, never silently safe)."


def external_findings_represented(
    external: Sequence[SastFinding],
    merged: Sequence[SastFinding],
) -> bool:
    """Whether every external finding is accounted for in ``merged`` (the §4.1 no-loss invariant).

    Release-blocking: a fused list must lose no external finding. An external finding counts as
    represented when ``merged`` contains a record at the same ``(file, line±1, cwe)`` whose
    provenance includes the external tool — i.e. it survives either as its own escalated record or
    as the survivor of a merge that recorded its tool.
    """
    for ext in external:
        tool = ext.provenance[0] if ext.provenance else ""
        if not any(_same_location(record, ext) and tool in record.provenance for record in merged):
            return False
    return True
