"""Re-export the shared PR-suggestion renderer (moved into the ``vulnadvisor`` package, Task 17.4).

The pure diff -> ``suggestion`` renderer used to live here (Task 17.2). It now lives in
:mod:`vulnadvisor.output.pr_suggestion` so the CLI's zero-setup ``vulnadvisor suggest`` command can
post in-line suggestions directly from CI (with ``GITHUB_TOKEN``) without depending on the platform,
while the GitHub App webhook keeps using the *same* code. This module re-exports it unchanged, so
every existing import (``from vulnadvisor_platform.pr_suggestion import ...``) keeps working with no
behaviour change — one source of truth, two callers.
"""

from vulnadvisor.output.pr_suggestion import (
    SUGGESTION_MARKER,
    DiffSuggestions,
    ReviewComment,
    ReviewSuggestion,
    build_review_comments,
    count_suggestable_fixes,
    diff_to_suggestions,
    render_suggestion_body,
)

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
