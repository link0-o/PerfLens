# Release readiness

[简体中文](release-readiness.zh-CN.md) | English

This record maps the final implementation to the planning document's Definition of Done. It records commands that were actually run locally through 2026-08-04; CI configuration is not presented as a completed remote CI run.

## Functional scope

Milestones 0 through 10 are implemented: folded/perf-script/perf.data analysis, exact Self/Inclusive and call paths, ELF/DWARF providers, candidate-only evidence, JSON/Markdown reporting, typed MCP, repository Skill, Profile/Benchmark comparisons, supported benchmark adapters, explicitly authorized active collection, and policy-bounded automatic PID collection through a separate Collector Broker. Project onboarding now also includes a versioned Collector policy and a read-only runtime-readiness status artifact.

The intentionally excluded product areas remain excluded: LLM APIs, custom agent loops, Web UI, source patching, a benchmark runner, production monitoring, direct perf.data parsing, and application-specific rules.

## Quality gates

| Gate | Command/evidence | Result |
|---|---|---|
| Lint | `ruff check .` | passed |
| Strict types | `pyright` | 0 errors, 0 warnings |
| Python 3.13 | isolated `pytest -q` environment | 274 passed |
| Python 3.12 | `pytest -q` on 3.12.13 | previous full release gate: 256 passed; not locally rerun for this change, so CI remains required |
| Coverage | `pytest --cov=perflens --cov-fail-under=85` | 85.76%, passed |
| Skill | structure and package tests | passed |
| Schemas | checked-in schema equality test | passed |
| Dependency lock | `uv export --locked` | passed |
| Vulnerabilities | `pip-audit` on fully pinned runtime export | no known vulnerabilities |
| SBOM | uv CycloneDX 1.5 export | passed |
| Real profile | pinned upstream FlameGraph perf example | full analyze/classify/report flow passed |
| Active perf denial | real perf 6.12.90, `perf_event_paranoid=3` | structured failure; no residual output |
| Automatic Broker | MCP plan → authenticated Unix socket → fixed spool | passed with executable perf test double |
| Collector health protocol | bidirectional kernel peer credentials → read-only `health` | allow, wrong service UID, deny, stale socket, deploy wait, and ordinary-user status paths passed |
| Deployment verification | `accept-collector` → built-in probe → authorized stat plan → at least one measured metric | Chinese/JSON/file output and no-measured-metric denial pass with executable perf test double |
| Collector storage bounds | cumulative bytes/files/free-space reserve before perf | three denial classes and Unix-socket end-to-end passed |
| Collector storage status | `spool-status` → direct regular files → quota/filesystem headroom | Chinese summary, versioned JSON, and unsafe-entry paths passed |
| Collector evidence lifecycle | managed selection → ZIP manifest/hashes → dedicated read-only archive/source verification → authorized prune | no default deletion, root archive, and tamper/identity/unmanaged denial paths passed |
| Safe policy update | separate candidate → validation → atomic replace/restart/health → rollback | fixed UID/spool, preserved comments, dry-run, and denial paths passed |
| Collector user isolation | one UID per instance; policy/staging/deploy deny multiple UIDs | denial and group-read boundary verified |
| Project workload | ordinary-user launch → internal PID → Broker → cleanup | passed end to end with executable perf test double |
| Admin deploy | strict TOML → packaged assets → fixed command allowlist → socket check | Chinese dry-run/success summaries, explicit JSON, rollback, and denial paths passed |
| Admin upgrade | fixed deployed policy → unit hashes → safe replace/restart → rollback | preserve, restart, update, rollback, and denial paths passed |
| Admin undeploy | trusted marker/owner/mode → fixed stop → inode recheck → unit removal | preserve-data and denial paths passed |
| Native DEB | split Debian 13 main/Collector packages | extracted entry-point/config smoke and byte-for-byte rebuild passed locally; CI also enforces installed layout detection, the exact status command, and deployment preflight |
| Performance | reproducible small/medium/large corpus | published in `performance-budget.md` |

Package build, isolated wheel and sdist installation, split DEB extraction,
CLI/MCP/Skill/Collector smoke output, deterministic DEB hashes, and the expected
release artifact hashes also passed in fresh local temporary directories. The
checked-in release workflow repeats these gates. See
`docs/releasing.md` for the local and tag-driven procedure.

## Compatibility evidence

- Linux: Debian 13, kernel 6.12.74, x86_64.
- Python: 3.12.13 and 3.13.5.
- perf: 6.12.90; read-only syntax/provider tests pass, active denial path verified on the host.
- GNU addr2line: Binutils 2.44, exercised against PIE, shared, stripped, and separate-debug fixtures.
- LLVM symbolizer: JSON protocol and long-lived provider lifecycle are test-double verified because it is not installed on this host.
- MCP: official Python SDK 2.0.0 client/server end-to-end tests.
- Collector: Linux Unix socket peer authentication, independent policy, single-use
  PID plan, and fixed spool are end-to-end tested; real privileged sampling is not
  claimed on this host.

## Interpretation boundaries

No rule match is a confirmed root cause. Profile percentage deltas are not absolute-time deltas. Benchmark results remain candidates until matched, correctness-preserving A/B validation. The off-CPU collector records sched-switch stack evidence but does not by itself reconstruct blocked duration.
