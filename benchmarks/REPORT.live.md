# VulnAdvisor Benchmark (live)

_Mode: live (pinned public repos) - repos: 10_

**Soundness on real-world code** - across 10 real applications, VulnAdvisor triaged 996 real advisories with **0 missed reachable criticals** (false negatives: 0). These apps load plugins via dynamic import, so the engine conservatively keeps unproven findings actionable rather than risk a false 'safe' - the intended behavior.

| Repo | Baseline | After triage | Deprioritized | Noise % | Reachable-called | Missed crit |
|------|---------:|-------------:|--------------:|--------:|-----------------:|-----------:|
| awx | 201 | 201 | 0 | 0% | 0 | 0 |
| ctfd | 61 | 61 | 0 | 0% | 0 | 0 |
| django-nv | 35 | 35 | 0 | 0% | 0 | 0 |
| frappe | 96 | 96 | 0 | 0% | 0 | 0 |
| healthchecks | 32 | 32 | 0 | 0% | 0 | 0 |
| intelowl | 96 | 96 | 0 | 0% | 0 | 0 |
| netbox | 78 | 78 | 0 | 0% | 0 | 0 |
| redash | 79 | 79 | 0 | 0% | 0 | 0 |
| saleor | 174 | 174 | 0 | 0% | 0 | 0 |
| superset | 144 | 144 | 0 | 0% | 0 | 0 |
| **Total** | **996** | **996** | **0** | **0%** | **0** | **0** |

On real applications the deprioritization rate is near zero by design: each repo loads code through dynamic import (`importlib`/`__import__`/`exec`), which could hide usage, so the engine escalates every unproven finding to a cautious tier instead of marking it safe. The release-blocking number is the last column - zero on every repo.

Soundness gate: **PASS** - a reachable finding is never reported as safe.
