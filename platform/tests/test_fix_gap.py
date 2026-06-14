"""Task 19.1 — the *visibility* gap, reproduced as a failing regression test.

Even when a validated fix is produced, it never reaches the dashboard finding card (Task 17.5):
the generated setup workflow runs ``vulnadvisor scan . --upload`` **without** ``--suggestions`` and
a separate ``vulnadvisor suggest`` that only posts in-line comments to GitHub. So the platform's
``Scan.suggestions`` stays empty, ``_proposed_fixes`` returns ``[]``, and the read join surfaces no
fix — independent of yield. (Join-key parity ``<file>:<line>:<kind>`` is fine; see
``docs/fix-gap-trace.md`` — the break is purely the missing upload.)

This asserts the generated workflow uploads its validated fixes to the platform. It is marked
``xfail(strict=True)``: it genuinely fails today (the workflow uploads nothing) but is reported as
``xfailed`` so the gate stays green. Task 19.2 wires the workflow to upload suggestions
(``scan --upload --suggestions`` or a unified ``suggest --upload``); when it lands this test will
``XPASS`` and ``strict`` will fail the gate — **remove the ``xfail`` marker then**.
"""

import pytest

from vulnadvisor_platform.setup_pr import render_workflow


@pytest.mark.xfail(
    strict=True,
    reason="19.1 visibility gap: the generated workflow uploads no suggestions, so "
    "Scan.suggestions stays empty and the read join returns none. Task 19.2 makes this "
    "pass — remove this marker then.",
)
def test_setup_workflow_uploads_validated_suggestions() -> None:
    workflow = render_workflow(default_branch="main", api_url="https://api.example.com")

    # The generated workflow must get the validated fixes onto the platform's Scan.suggestions
    # so the dashboard finding card (17.5) can render them. Accept either single-source-of-truth
    # mechanism 19.2 may pick: `scan --upload --suggestions <file>` or a unified `suggest --upload`.
    uploads_suggestions = "--suggestions" in workflow or "suggest --upload" in workflow
    assert uploads_suggestions, (
        "the setup workflow uploads no validated fixes to the platform — Scan.suggestions stays "
        "empty and the dashboard finding card joins nothing (19.1 visibility gap)"
    )
