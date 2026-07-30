# Changelog

All notable changes follow Keep a Changelog and Semantic Versioning.

## [Unreleased]

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
