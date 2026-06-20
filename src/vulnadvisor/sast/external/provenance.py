"""Render a finding's ``provenance`` tuple as the honest "who found this, who ranked it" string.

The fusion story (``docs/fusion-design.md`` §6) is told in one fixed, honest line: a finding an
external scanner located but *our* reachability engine tiered reads **"Found by Semgrep OSS ·
ranked by VulnAdvisor reachability"**. The *ranking* is always attributed to VulnAdvisor because the
tier and the priority are our deterministic engine's output, even when the *detection* came from
another tool. A native-only finding carries no such line (we found and ranked it — the default), so
:func:`provenance_line` returns ``None`` for it and the renderers simply omit the line.

Pure and deterministic: a stable tool→label map, no I/O, no clock. Surfaced by the 3-card terminal
output, the JSON/SARIF reports, and the dashboard (Task 21.4).
"""

from collections.abc import Sequence

from vulnadvisor.sast.model import NATIVE_PROVENANCE

__all__ = [
    "TOOL_LABELS",
    "external_tools",
    "provenance_labels",
    "provenance_line",
]

#: Human-readable label per stable provenance id. An id with no entry renders verbatim (so a future
#: adapter is legible before it is added here), never a crash.
TOOL_LABELS: dict[str, str] = {
    NATIVE_PROVENANCE: "VulnAdvisor",
    "semgrep-oss": "Semgrep OSS",
}

#: How the ranking is always attributed, regardless of who detected the finding (§6).
_RANKED_BY = "ranked by VulnAdvisor reachability"


def label_for(tool: str) -> str:
    """Map a provenance id to its display label, falling back to the raw id."""
    return TOOL_LABELS.get(tool, tool)


def provenance_labels(provenance: Sequence[str]) -> list[str]:
    """The display labels for every tool in ``provenance``, in the tuple's (display) order."""
    return [label_for(tool) for tool in provenance]


def external_tools(provenance: Sequence[str]) -> tuple[str, ...]:
    """The non-native tools in ``provenance`` (the ones whose detection we are crediting)."""
    return tuple(tool for tool in provenance if tool != NATIVE_PROVENANCE)


def provenance_line(provenance: Sequence[str]) -> str | None:
    """The "Found by … · ranked by VulnAdvisor reachability" line, or ``None`` for native-only.

    A finding only our own engine found and ranked needs no provenance line — that is the default
    and adding it would be noise. The line appears exactly when an external scanner corroborated or
    located the finding, crediting every detector while keeping the ranking attribution ours.
    """
    if not external_tools(provenance):
        return None
    detectors = " + ".join(provenance_labels(provenance))
    return f"Found by {detectors} · {_RANKED_BY}"
