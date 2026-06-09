<!-- Thanks for contributing to VulnAdvisor. Keep changes focused; one concern per PR. -->

## What this changes

<!-- A short description of the change and why. -->

## Soundness check (required for any change to callgraph/ or reachability/)

<!-- Our hard rule: never make a reachable finding look safe. If this PR touches analysis: -->

- [ ] This change does **not** turn any reachable vulnerability into a lower-concern tier
      (no new false negatives). If it relaxes a tier, explain why it is provably safe.
- [ ] New or changed behavior is covered by a fixture / table-driven test.

## Checklist

- [ ] `ruff check` and `ruff format --check` are clean
- [ ] `mypy --strict src` is clean
- [ ] `pytest` is green
- [ ] Docs / CHANGELOG updated if user-facing
