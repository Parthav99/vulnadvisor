# VulnAdvisor Benchmark (hermetic)

_Mode: hermetic (synthetic corpus) - repos: 12_

**54% less noise** - 39 naive findings reduced to 18 after reachability triage, with **0 missed reachable criticals** (false negatives: 0).

| Repo | Baseline | After triage | Deprioritized | Noise % | Reachable-called | Missed crit |
|------|---------:|-------------:|--------------:|--------:|-----------------:|-----------:|
| api-gateway | 3 | 1 | 2 | 67% | 1 | 0 |
| auth-service | 3 | 1 | 2 | 67% | 0 | 0 |
| cache-layer | 3 | 2 | 1 | 33% | 1 | 0 |
| cli-tool | 4 | 2 | 2 | 50% | 1 | 0 |
| config-loader | 3 | 1 | 2 | 67% | 1 | 0 |
| data-pipeline | 3 | 2 | 1 | 33% | 1 | 0 |
| ingest-worker | 4 | 1 | 3 | 75% | 0 | 0 |
| notify-bot | 4 | 1 | 3 | 75% | 1 | 0 |
| report-builder | 3 | 2 | 1 | 33% | 2 | 0 |
| schema-tool | 3 | 2 | 1 | 33% | 1 | 0 |
| static-site | 3 | 1 | 2 | 67% | 0 | 0 |
| web-scraper | 3 | 2 | 1 | 33% | 1 | 0 |
| **Total** | **39** | **18** | **21** | **54%** | **10** | **0** |

Soundness gate: **PASS** - a reachable finding is never reported as safe.
