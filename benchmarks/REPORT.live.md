# VulnAdvisor Benchmark (live)

_Mode: live (pinned public repos) - repos: 13_

**Real-world soundness + noise reduction** - across 13 real applications (1210 advisories), VulnAdvisor deprioritized 65 as unreachable (5%) and kept the rest actionable, with **0 missed reachable criticals** (false negatives: 0). It stays conservative on apps that load code via runtime dynamic dispatch and removes genuinely-unimported deps on apps it can fully analyze.

| Repo | Baseline | After triage | Deprioritized | Noise % | Reachable-called | Missed crit |
|------|---------:|-------------:|--------------:|--------:|-----------------:|-----------:|
| awx | 201 | 201 | 0 | 0% | 0 | 0 |
| bookwyrm | 41 | 37 | 4 | 10% | 0 | 0 |
| ctfd | 61 | 61 | 0 | 0% | 0 | 0 |
| django-nv | 35 | 35 | 0 | 0% | 0 | 0 |
| frappe | 96 | 96 | 0 | 0% | 0 | 0 |
| healthchecks | 32 | 32 | 0 | 0% | 0 | 0 |
| intelowl | 96 | 96 | 0 | 0% | 0 | 0 |
| mathesar | 14 | 12 | 2 | 14% | 0 | 0 |
| netbox | 78 | 78 | 0 | 0% | 0 | 0 |
| paperless | 159 | 100 | 59 | 37% | 0 | 0 |
| redash | 79 | 79 | 0 | 0% | 0 | 0 |
| saleor | 174 | 174 | 0 | 0% | 0 | 0 |
| superset | 144 | 144 | 0 | 0% | 0 | 0 |
| **Total** | **1210** | **1145** | **65** | **5%** | **0** | **0** |

Deprioritization is bimodal by design. An app that loads code through runtime dynamic dispatch (`eval`/`exec` or an opaque `import_module`/`__import__`) could reach any package, so the engine keeps every unproven finding in an actionable tier rather than mark it safe (0% rows). An app whose code is statically analyzable has its genuinely-unimported dependencies - servers, build/test tools, unused transitive packages - moved to NOT-IMPORTED. The release-blocking number is the last column: zero missed reachable criticals on every repo.

Soundness gate: **PASS** - a reachable finding is never reported as safe.
