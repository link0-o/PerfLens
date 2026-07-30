# Release readiness

This record maps the final implementation to the planning document's Definition of Done. It records commands that were actually run on 2026-07-30; CI configuration is not presented as a completed remote CI run.

## Functional scope

Milestones 0 through 9 are implemented: folded/perf-script/perf.data analysis, exact Self/Inclusive and call paths, ELF/DWARF providers, candidate-only evidence, JSON/Markdown reporting, typed MCP, repository Skill, Profile/Benchmark comparisons, supported benchmark adapters, and explicitly authorized active collection.

The intentionally excluded product areas remain excluded: LLM APIs, custom agent loops, Web UI, source patching, a benchmark runner, production monitoring, direct perf.data parsing, and application-specific rules.

## Quality gates

| Gate | Command/evidence | Result |
|---|---|---|
| Lint | `ruff check .` | passed |
| Strict types | `pyright` | 0 errors, 0 warnings |
| Python 3.13 | `pytest -q` on 3.13.5 | 96 passed |
| Python 3.12 | isolated package/test environment on 3.12.13 | 96 passed |
| Coverage | `pytest --cov=perflens --cov-fail-under=85` | 85.21%, passed |
| Skill | `quick_validate.py .agents/skills/perflens-performance-analysis` | valid |
| Schemas | checked-in schema equality test | passed |
| Dependency lock | `uv export --locked` | passed |
| Vulnerabilities | `pip-audit` on fully pinned runtime export | no known vulnerabilities |
| SBOM | uv CycloneDX 1.5 export | 41 runtime components |
| Real profile | pinned upstream FlameGraph perf example | full analyze/classify/report flow passed |
| Active perf denial | real perf 6.12.90, `perf_event_paranoid=3` | structured failure; no residual output |
| Performance | reproducible small/medium/large corpus | published in `performance-budget.md` |

Package build, isolated wheel and sdist installation, CLI/MCP/Skill smoke
output, and final artifact hashes are produced by the checked-in release
workflow. See `docs/releasing.md` for the local and tag-driven procedure.

## Compatibility evidence

- Linux: Debian 13, kernel 6.12.74, x86_64.
- Python: 3.12.13 and 3.13.5.
- perf: 6.12.90; read-only syntax/provider tests pass, active denial path verified on the host.
- GNU addr2line: Binutils 2.44, exercised against PIE, shared, stripped, and separate-debug fixtures.
- LLVM symbolizer: JSON protocol and long-lived provider lifecycle are test-double verified because it is not installed on this host.
- MCP: official Python SDK 2.0.0 client/server end-to-end tests.

## Interpretation boundaries

No rule match is a confirmed root cause. Profile percentage deltas are not absolute-time deltas. Benchmark results remain candidates until matched, correctness-preserving A/B validation. The off-CPU collector records sched-switch stack evidence but does not by itself reconstruct blocked duration.
