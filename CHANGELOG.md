# Changelog

All notable changes follow Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Added

- Chinese maintainer documentation for development, architecture, security,
  and release-readiness workflows.
- Read-only `perflens doctor` capability diagnostics for perf/kernel policy,
  process and file capabilities, tracefs, and every collection mode.
- Short-lived, single-use automatic collection plans bound to PID owner and
  process start time.
- Optional `perflens-collector` Unix-socket Broker with peer authentication,
  an independent immutable policy, fixed spool, and no command execution API.
- MCP tools for capability inspection, automatic planning/execution, and
  analysis of collected perf-data artifacts.
- Packaged systemd, sysusers, and Collector policy templates plus a safe staging
  command and complete Chinese deployment documentation.
- Configurable Collector deployment assets and a bounded, explicitly authorized
  `verify-collector` real perf-stat acceptance probe.
- Chinese-first `perflens setup` onboarding that installs the project Skill and
  generates MCP configuration, capability diagnostics, typed setup metadata,
  and optional Collector deployment assets without elevating privileges.
- Beginner-oriented Chinese and English installation guides plus generated
  GitHub Release notes that explain which asset to download and that wheel
  files must be installed rather than extracted.

### Changed

- Release preparation now requires a CycloneDX JSON SBOM, rejects stale or
  unexpected files in `dist/`, and checksums only the four intended assets.
- CI and release jobs now have explicit timeouts and concurrency controls.
- The Performance Analysis Skill now drives policy-approved live PID collection
  through the plan/Broker workflow before deterministic analysis.
- GitHub Releases now use a checked-in, version-rendered installation guide
  instead of relying on automatically generated commit notes alone.

### Fixed

- Enforced bounded reads for benchmark JSON, persisted artifacts, growing
  profiles, and source files containing extremely long logical lines.
- Rejected non-finite benchmark and `perf stat` values before they can produce
  invalid or misleading JSON artifacts.
- Batched long-lived symbolizer requests to avoid pipe deadlocks on large
  address sets.
- Validated command-runner executables, resource limits, artifact limits, and
  wrapped process-start/output-write failures in stable PerfLens errors.

## [0.1.0] - 2026-07-30

### Added

- Milestone 0 packaging, contracts, quality gates, and documentation.
- Milestone 1 streaming FlameGraph folded-stack analysis.
- Milestone 2 streaming `perf script` parsing with address, DSO, thread, event,
  period, kernel, and source metadata.
- Milestone 3 bounded `perf.data` conversion through an allowlisted system
  `perf` executable, including timeout and process-group cleanup.
- Milestone 4 ELF/Build ID/debug inspection, LLVM JSON and addr2line providers,
  independent debug-file handling, path mapping, and bounded source context.
- Milestone 5 generic YAML classification rules, candidate-only evidence
  bundles, explicit missing evidence, and Markdown reports.
- Milestone 6 official-SDK MCP server with typed structured output, bounded
  paging, artifact storage, annotations, and server-enforced authorization.
- Milestone 7 repository Performance Analysis Skill with routed evidence,
  on-CPU, lock, memory, syscall, benchmark, and report guidance.
- Milestone 8 deterministic Profile and Benchmark comparison, environment
  comparability checks, practical-impact thresholds, Markdown diffs, and
  pyperf/Google Benchmark/hyperfine adapters.
- Milestone 9 default-off active perf record/stat/sched/lock/off-CPU collection
  with server and per-call authorization, a separate PID-attachment gate,
  bounded outputs, immutable publication, and typed perf-stat metrics.
- Installable wheel and source distributions with CLI and MCP entry points.
- A bundled, non-overwriting project Skill installer and safe Codex MCP
  configuration renderer.
- Tag-driven GitHub Release automation with wheel/sdist smoke tests, a
  standalone Skill archive, CycloneDX SBOM, and SHA-256 checksums.

[Unreleased]: https://github.com/link0-o/PerfLens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/link0-o/PerfLens/releases/tag/v0.1.0
