"""Render validated fixes as in-line GitHub ``suggestion`` review comments (Task 17.2 core).

This is the **one source of truth** for turning a validated fix's unified diff into the in-line
review comments that a reviewer can click "Commit suggestion" on. It lives in the ``vulnadvisor``
package (moved here in Task 17.4) so two callers share it without duplication:

* the **CLI** ``vulnadvisor suggest`` command, which posts directly from GitHub Actions with the
  built-in ``GITHUB_TOKEN`` (no App, no platform) — :mod:`vulnadvisor.output.github_pr`;
* the **platform** GitHub App webhook, which re-exports this module unchanged
  (:mod:`vulnadvisor_platform.pr_suggestion`).

It is pure and defensive: a unified diff is split into per-hunk ``suggestion`` blocks anchored to
the head (``RIGHT``) side, with the 3-card attack story collapsed in a ``<details>``.

Soundness: a GitHub ``suggestion`` replaces the exact line(s) it is attached to, so committing one
hunk of a multi-hunk fix would leave the code half-patched. We therefore only ever emit in-line
suggestions for a fix when **every** hunk can be expressed as an anchored suggestion
(:attr:`DiffSuggestions.complete`); otherwise the caller falls back to surfacing the fix in the
summary, never posting a partial patch a click could apply.
"""

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "SUGGESTION_MARKER",
    "DiffSuggestions",
    "ReviewComment",
    "ReviewSuggestion",
    "build_review_comments",
    "count_suggestable_fixes",
    "diff_to_suggestions",
    "render_suggestion_body",
]

# Hidden marker on every in-line fix comment so the poster can find and replace its own on a re-run.
SUGGESTION_MARKER = "<!-- vulnadvisor:fix -->"

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Human-readable confidence-tier labels (the SAST tiers from the engine).
_TIER_LABELS = {
    "CONFIRMED-FLOW": "Confirmed source -> sink flow",
    "DYNAMIC-UNKNOWN": "Dynamic construct blocks certainty",
    "POSSIBLE-FLOW": "Sink reached; taint not proven",
    "SANITIZED": "Sanitized on every path",
}


@dataclass(frozen=True)
class ReviewSuggestion:
    """One anchored ``suggestion`` derived from a single diff hunk.

    ``start_line``/``line`` are 1-based line numbers on the PR head (``RIGHT``) side — the lines the
    suggestion replaces. ``start_line`` is ``None`` for a single-line replacement. ``replacement``
    is the exact post-fix text for that range (becomes the body of the ``suggestion`` fence).
    """

    path: str
    start_line: int | None
    line: int
    replacement: str
    side: str = "RIGHT"


@dataclass(frozen=True)
class DiffSuggestions:
    """The suggestions parsed from one fix's diff, plus whether the whole patch is expressible.

    ``complete`` is ``True`` only when every hunk became an anchored :class:`ReviewSuggestion`; the
    caller posts in-line suggestions exclusively in that case (no partially-appliable patch).
    """

    suggestions: tuple[ReviewSuggestion, ...]
    complete: bool


@dataclass(frozen=True)
class ReviewComment:
    """A review comment ready for the GitHub reviews API: an anchor plus the rendered body."""

    path: str
    start_line: int | None
    line: int
    side: str
    body: str

    def to_api(self) -> dict[str, Any]:
        """The GitHub ``pulls/{n}/reviews`` comment payload (multi-line keys only when needed)."""
        payload: dict[str, Any] = {
            "path": self.path,
            "line": self.line,
            "side": self.side,
            "body": self.body,
        }
        if self.start_line is not None and self.start_line != self.line:
            payload["start_line"] = self.start_line
            payload["start_side"] = self.side
        return payload


def _parse_hunks(diff: str) -> list[tuple[str, int, list[str]]] | None:
    """Split a unified diff into ``(path, old_start, body_lines)`` hunks, or ``None`` if malformed.

    ``path`` is the head-side file (``+++ b/<path>``). Returns ``None`` when a hunk references
    ``/dev/null`` (a file add/delete — not expressible as an in-line suggestion on existing lines).
    """
    hunks: list[tuple[str, int, list[str]]] = []
    path: str | None = None
    old_start = 0
    body: list[str] = []
    in_hunk = False

    def flush() -> None:
        if in_hunk and path is not None:
            hunks.append((path, old_start, body.copy()))

    for line in diff.splitlines():
        if line.startswith("+++ "):
            flush()
            in_hunk = False
            target = line[4:].split("\t", 1)[0].strip()
            if target == "/dev/null":
                return None
            path = target[2:] if target.startswith("b/") else target
            continue
        if line.startswith("--- "):
            continue
        header = _HUNK_HEADER.match(line)
        if header:
            flush()
            old_start = int(header.group(1))
            body = []
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith("\\"):  # "\ No newline at end of file" — not a content line
                continue
            if line[:1] in (" ", "+", "-"):
                body.append(line)
            else:
                # A non-prefixed line ends the hunk's content (a validated diff has no such lines
                # mid-hunk; this guards against trailing prose after the patch).
                flush()
                in_hunk = False
    flush()
    return hunks


def _hunk_to_suggestion(path: str, old_start: int, body: list[str]) -> ReviewSuggestion | None:
    """Convert one hunk to an anchored :class:`ReviewSuggestion`, or ``None`` if it cannot anchor.

    The anchor is narrowed to the minimal changed window; a pure insertion borrows one neighbour
    context line so it has a line to attach to. ``None`` means the hunk has no anchorable line at
    all (a pure insertion with no surrounding context), forcing the whole fix out of in-line mode.
    """
    change_indexes = [i for i, ln in enumerate(body) if ln[:1] in ("+", "-")]
    if not change_indexes:
        return None
    first, last = change_indexes[0], change_indexes[-1]
    if not any(body[i][:1] == "-" for i in range(first, last + 1)):
        # Pure insertion: extend the window by one context line to gain an anchor.
        if first > 0:
            first -= 1
        elif last + 1 < len(body):
            last += 1
        else:
            return None
    window = body[first : last + 1]

    # Old (head) lines consumed before the window are all context, one head line each.
    anchor_start = old_start + first
    anchor_count = sum(1 for ln in window if ln[:1] in (" ", "-"))
    if anchor_count == 0:
        return None
    anchor_end = anchor_start + anchor_count - 1
    replacement = "\n".join(ln[1:] for ln in window if ln[:1] in (" ", "+"))
    return ReviewSuggestion(
        path=path,
        start_line=anchor_start if anchor_count > 1 else None,
        line=anchor_end,
        replacement=replacement,
    )


def diff_to_suggestions(diff: str) -> DiffSuggestions:
    """Parse a validated fix's unified diff into anchored suggestions.

    Every hunk that touches existing head lines becomes a :class:`ReviewSuggestion`. ``complete`` is
    ``True`` only if the diff parsed and every hunk anchored — the precondition for safely posting
    one-click suggestions (a hunk that cannot anchor would otherwise be silently dropped).
    """
    hunks = _parse_hunks(diff)
    if not hunks:
        return DiffSuggestions(suggestions=(), complete=False)
    suggestions: list[ReviewSuggestion] = []
    complete = True
    for path, old_start, body in hunks:
        suggestion = _hunk_to_suggestion(path, old_start, body)
        if suggestion is None:
            complete = False
        else:
            suggestions.append(suggestion)
    return DiffSuggestions(suggestions=tuple(suggestions), complete=complete and bool(suggestions))


def _tier_label(tier: str) -> str:
    """A short human label for a SAST confidence tier (falls back to the raw value)."""
    return _TIER_LABELS.get(tier, tier or "unknown")


def render_suggestion_body(
    fix: dict[str, Any], suggestion: ReviewSuggestion, *, index: int, total: int
) -> str:
    """Render one in-line comment body: the ``suggestion`` block + the collapsed attack story.

    ``index``/``total`` (1-based) label a multi-hunk fix so a reviewer knows to commit the whole
    set together. The 3-card story (title, confidence tier, source->sink flow, fix rationale) lives
    inside a ``<details>`` so the suggestion itself stays front-and-centre.
    """
    cwe = fix.get("cwe") or ""
    kind = fix.get("kind") or "finding"
    heading = f"**Validated fix - `{cwe}` {kind}**" if cwe else f"**Validated fix - {kind}**"
    if total > 1:
        heading += f"  (part {index} of {total} - commit all together)"

    lines = [SUGGESTION_MARKER, heading, "", "```suggestion", suggestion.replacement, "```"]

    if index == 1:
        title = fix.get("title") or kind
        tier = str(fix.get("tier") or "")
        flow = fix.get("flow") or ""
        rationale = fix.get("rationale") or ""
        lines += [
            "",
            "<details><summary>Why this fix - the attack story</summary>",
            "",
            f"**{title}**",
            "",
            f"- **Confidence:** {tier} ({_tier_label(tier)})",
        ]
        if flow:
            lines.append(f"- **Flow:** `{flow}`")
        if rationale:
            lines += ["", rationale]
        lines += ["", "</details>"]
    return "\n".join(lines)


def build_review_comments(suggestions: list[dict[str, Any]]) -> list[ReviewComment]:
    """Turn stored validated-fix rows into anchored review comments for the GitHub reviews API.

    A fix contributes comments only when its diff is *fully* expressible as suggestions (every hunk
    anchored); a fix whose patch cannot be cleanly suggested is skipped here (it is still counted in
    the summary). Order follows the input so the review reads top-to-bottom predictably.
    """
    comments: list[ReviewComment] = []
    for fix in suggestions:
        if not isinstance(fix, dict):
            continue
        diff = fix.get("diff")
        if not isinstance(diff, str):
            continue
        parsed = diff_to_suggestions(diff)
        if not parsed.complete:
            continue
        total = len(parsed.suggestions)
        for index, suggestion in enumerate(parsed.suggestions, start=1):
            body = render_suggestion_body(fix, suggestion, index=index, total=total)
            comments.append(
                ReviewComment(
                    path=suggestion.path,
                    start_line=suggestion.start_line,
                    line=suggestion.line,
                    side=suggestion.side,
                    body=body,
                )
            )
    return comments


def count_suggestable_fixes(suggestions: list[dict[str, Any]]) -> int:
    """How many stored fixes can be posted as complete in-line suggestions (for the summary)."""
    count = 0
    for fix in suggestions:
        if not isinstance(fix, dict):
            continue
        diff = fix.get("diff")
        if isinstance(diff, str) and diff_to_suggestions(diff).complete:
            count += 1
    return count
