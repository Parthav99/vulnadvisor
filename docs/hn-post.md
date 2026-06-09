# Hacker News "Show HN" post

**Title:** Show HN: VulnAdvisor – which Python dependency CVEs are actually reachable from your code

**Body:**

VulnAdvisor is an open-source CLI that does static reachability analysis (AST + import graph + a
demand-driven call graph) to tell you which of your vulnerable dependencies your code actually
reaches, instead of just which are installed — it runs locally with no telemetry, ranks by EPSS+KEV,
and is soundness-first (every finding gets a confidence tier, and anything it can't prove safe is
escalated rather than hidden). On 13 real apps and 1,210 OSV advisories it deprioritized up to 37%
of findings with zero missed reachable ones.

GitHub: https://github.com/Parthav99/vulnadvisor — PyPI: https://pypi.org/project/vulnadvisor/
(`pip install vulnadvisor`)
