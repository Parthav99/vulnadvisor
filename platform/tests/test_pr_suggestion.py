"""Pure tests for the PR review agent's suggestion rendering (Task 17.2).

The diff -> ``suggestion`` conversion is the soundness-critical part: a suggestion must replace
exactly the right head lines, and a fix is only ever offered in-line when its whole patch is
expressible (no half-appliable click). These are unit-tested without any GitHub I/O.
"""

from vulnadvisor_platform.pr_suggestion import (
    SUGGESTION_MARKER,
    build_review_comments,
    count_suggestable_fixes,
    diff_to_suggestions,
    render_suggestion_body,
)


def test_platform_reexports_the_shared_renderer() -> None:
    """Task 17.4: the renderer moved into the ``vulnadvisor`` package; the platform re-exports it.

    Asserting object identity proves there is one source of truth (no copy drift) shared by the
    CLI's ``vulnadvisor suggest`` and the GitHub App webhook.
    """
    from vulnadvisor.output import pr_suggestion as shared

    assert build_review_comments is shared.build_review_comments
    assert diff_to_suggestions is shared.diff_to_suggestions
    assert render_suggestion_body is shared.render_suggestion_body
    assert count_suggestable_fixes is shared.count_suggestable_fixes
    assert SUGGESTION_MARKER == shared.SUGGESTION_MARKER


# A single-hunk SQLi fix: parameterize the query. The suggestion replaces exactly the sink line.
_SQLI_DIFF = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -10,3 +10,3 @@ def get(uid):\n"
    "     cur = conn.cursor()\n"
    '-    cur.execute("SELECT * FROM u WHERE id = %s" % uid)\n'
    '+    cur.execute("SELECT * FROM u WHERE id = %s", (uid,))\n'
    "     return cur.fetchone()\n"
)
_SQLI_REPLACEMENT = '    cur.execute("SELECT * FROM u WHERE id = %s", (uid,))'

# A two-hunk fix: add an import (pure insertion) AND change the sink line.
_TWO_HUNK_DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,1 +1,2 @@\n"
    " import os\n"
    "+import shlex\n"
    "@@ -5,1 +6,1 @@ def run():\n"
    "-    os.system(cmd)\n"
    "+    os.system(shlex.quote(cmd))\n"
)


def _fix(diff: str, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "finding_id": "app/db.py:11:sql-injection",
        "file": "app/db.py",
        "line": 11,
        "cwe": "CWE-89",
        "kind": "sql-injection",
        "title": "SQL injection",
        "tier": "CONFIRMED-FLOW",
        "flow": "get -> cursor.execute (app/db.py:11)",
        "rationale": "Use a parameterized query so the id is bound, not concatenated.",
        "confidence": "high",
        "diff": diff,
    }
    base.update(over)
    return base


# --- diff -> suggestion -------------------------------------------------------------------------


def test_single_hunk_anchors_to_the_sink_line() -> None:
    parsed = diff_to_suggestions(_SQLI_DIFF)
    assert parsed.complete is True
    assert len(parsed.suggestions) == 1
    sug = parsed.suggestions[0]
    assert sug.path == "app/db.py"
    assert sug.line == 11  # the head line being replaced
    assert sug.start_line is None  # single line
    assert sug.side == "RIGHT"
    # Suggestion block content == the validated diff hunk's new side (the snapshot contract).
    assert sug.replacement == _SQLI_REPLACEMENT


def test_pure_insertion_borrows_a_context_anchor() -> None:
    parsed = diff_to_suggestions(_TWO_HUNK_DIFF)
    assert parsed.complete is True
    assert len(parsed.suggestions) == 2
    add_import, fix_sink = parsed.suggestions
    # The import hunk anchors on line 1 (import os) and rewrites it to include the new import.
    assert add_import.line == 1 and add_import.start_line is None
    assert add_import.replacement == "import os\nimport shlex"
    # The sink hunk anchors to the head (old) side — line 5 — which is where GitHub places it.
    assert fix_sink.line == 5
    assert fix_sink.replacement == "    os.system(shlex.quote(cmd))"


def test_multiline_replacement_sets_start_and_end() -> None:
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -3,2 +3,2 @@\n"
        "-    a = 1\n"
        "-    b = 2\n"
        "+    a = one()\n"
        "+    b = two()\n"
    )
    parsed = diff_to_suggestions(diff)
    sug = parsed.suggestions[0]
    assert sug.start_line == 3 and sug.line == 4  # two head lines replaced
    assert sug.replacement == "    a = one()\n    b = two()"


def test_file_add_is_not_suggestable() -> None:
    diff = "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,1 @@\n+print('hi')\n"
    parsed = diff_to_suggestions(diff)
    assert parsed.complete is False
    assert parsed.suggestions == ()


def test_garbage_diff_is_not_suggestable() -> None:
    parsed = diff_to_suggestions("this is not a diff at all")
    assert parsed.complete is False and parsed.suggestions == ()


# --- comment rendering --------------------------------------------------------------------------


def test_body_has_marker_suggestion_block_and_story() -> None:
    parsed = diff_to_suggestions(_SQLI_DIFF)
    body = render_suggestion_body(_fix(_SQLI_DIFF), parsed.suggestions[0], index=1, total=1)
    assert SUGGESTION_MARKER in body
    assert "```suggestion\n" + _SQLI_REPLACEMENT + "\n```" in body
    assert "<details>" in body and "</details>" in body
    assert "CONFIRMED-FLOW" in body
    assert "parameterized query" in body  # the rationale is shown
    assert "CWE-89" in body


def test_multi_hunk_bodies_label_parts_and_story_once() -> None:
    comments = build_review_comments([_fix(_TWO_HUNK_DIFF)])
    assert len(comments) == 2
    first, second = comments
    assert "part 1 of 2" in first.body and "<details>" in first.body
    assert "part 2 of 2" in second.body and "<details>" not in second.body


def test_build_review_comments_skips_unsuggestable_fixes() -> None:
    fixable = _fix(_SQLI_DIFF, finding_id="a:1:x", file="a.py", line=11)
    unfixable = _fix(
        "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n",
        finding_id="b:1:y",
        file="new.py",
        line=1,
    )
    comments = build_review_comments([fixable, unfixable])
    # Only the cleanly-expressible fix becomes in-line comments.
    assert [c.path for c in comments] == ["app/db.py"]
    assert count_suggestable_fixes([fixable, unfixable]) == 1


def test_to_api_uses_multiline_keys_only_when_needed() -> None:
    comments = build_review_comments(
        [
            _fix(
                "--- a/x.py\n+++ b/x.py\n@@ -3,2 +3,2 @@\n-a\n-b\n+c\n+d\n",
                finding_id="x:3:k",
                file="x.py",
                line=4,
            )
        ]
    )
    api = comments[0].to_api()
    assert api["start_line"] == 3 and api["line"] == 4
    assert api["side"] == "RIGHT" and api["start_side"] == "RIGHT"

    single = build_review_comments([_fix(_SQLI_DIFF)])[0].to_api()
    assert "start_line" not in single and single["line"] == 11
