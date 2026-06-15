"""Task 19.1 visibility-gap regression, repaired in Task 19.2.

The 19.1 gap: even when a validated fix was produced it never reached the dashboard finding card
(Task 17.5), because the generated setup workflow ran ``vulnadvisor scan . --upload`` **without**
``--suggestions`` and a separate ``vulnadvisor suggest`` that only posted in-line comments to
GitHub — so the platform's ``Scan.suggestions`` stayed empty and the read join surfaced nothing.

Task 19.2 wires the workflow to a single source of truth: the fix step writes the validated
patches once, and ``scan --upload --suggestions <file>`` carries them to the platform (the
``suggest --from`` step reposts the same document in-line). This regression test pins that the
generated workflow uploads its validated fixes; it was ``xfail(strict=True)`` in 19.1 and is now a
plain green assertion.
"""

from vulnadvisor_platform.setup_pr import render_workflow


def test_setup_workflow_uploads_validated_suggestions() -> None:
    workflow = render_workflow(default_branch="main", api_url="https://api.example.com")

    # The generated workflow must get the validated fixes onto the platform's Scan.suggestions so
    # the dashboard finding card (17.5) can render them — via `scan --upload --suggestions <file>`.
    assert "--suggestions" in workflow, (
        "the setup workflow must upload its validated fixes to the platform so Scan.suggestions is "
        "populated and the dashboard finding card joins them (19.1 visibility gap, fixed in 19.2)"
    )
    # The fix document is generated once, then reused by the PR-suggestion step (no second loop).
    assert "fix --suggest-json" in workflow
    assert "suggest --from" in workflow
