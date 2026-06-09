# r/Python post

**Title:** VulnAdvisor: a local CLI that tells you which dependency CVEs are actually reachable from your code

**Body:**

Your scanner flags 40 vulnerable dependencies. How many can an attacker actually reach through *your*
code? Usually you have no idea, so you either chase all 40 or ignore the list. I built an open-source
CLI to answer that question for Python.

**How it's different from pip-audit/Snyk:** those tell you a vulnerable package is *installed*;
VulnAdvisor does static reachability analysis (AST + import graph + a demand-driven call graph) to
tell you whether your code actually *reaches* the vulnerable symbol — and it runs entirely locally,
no telemetry, source never leaves your machine.

It never gives a binary reachable/not. Every finding gets a confidence tier:

- `IMPORTED-AND-CALLED` — there's a concrete call path to the vulnerable symbol, and it shows you the
  path: `parse_config -> yaml.load`
- `IMPORTED` — the package is imported, no confirmed call
- `DYNAMIC-UNKNOWN` — reflection / `eval` / dynamic import means it *can't* prove safety, so it
  escalates instead of guessing
- `NOT-IMPORTED` — never imported. The only "confidently safe" tier, and where most of the noise goes

The design rule is soundness over precision: a false "you're safe" can hide a breach, so anything
uncertain escalates. On a synthetic corpus with no dynamic-dispatch escape hatches it cuts 54% of
findings; on 13 real apps (1,210 OSV advisories) it deprioritizes where the code is statically
analyzable (paperless: 37%, BookWyrm: 10%, Mathesar: 14%) and stays conservative everywhere a plugin
loader could hide a call — with **zero missed reachable findings** across all of them. That contrast
is the point: it only says "safe" when it can prove it.

Priority ranking is deterministic (CVSS + EPSS + CISA KEV, computed in code). There's an optional
plain-English "attack story" via your own Anthropic key, but the LLM only explains — it never changes
the score. Output is terminal, JSON, or SARIF (for the GitHub Security tab), with `--fail-on` for CI.

```bash
pip install vulnadvisor      # or: uvx vulnadvisor scan .
vulnadvisor scan .
```

GitHub: https://github.com/Parthav99/vulnadvisor

This is a brand-new 1.0 and I'm sure there are rough edges — I'd genuinely value feedback, especially
any case where it marks something `NOT-IMPORTED` that you think is actually reachable (that's a
false negative and the most important kind of bug to me). Apache-2.0.

Try it on your own projects and tell me what it gets wrong.
