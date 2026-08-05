# Changelog

All notable changes follow Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Added

- `perflens init` as the one-command, project-only opt-in. It activates Codex
  and/or Claude Code without installing a globally discoverable Skill;
  uninitialized projects do not expose PerfLens integration metadata.
- Claude Code support through `.claude/skills/perflens-performance-analysis`
  and safe project `.mcp.json` merging. Existing MCP servers are preserved,
  conflicting user-managed `perflens` entries are refused, and project trust
  remains a Claude Code decision.
- `perflens claude-config` and client selection for `install-skill` and `init`,
  with bilingual onboarding documentation and package smoke coverage.
- Safe `perflens init --update` lifecycle refresh. Existing onboarding must
  prove project ownership; Claude entries must match their recorded sidecar;
  project Skills use bounded SHA-256 fingerprints and user modifications are
  preserved rather than overwritten.
- Complete Codex/Claude project detachment with client selection, dry-run,
  optional `--keep-skills`, exact Claude ownership checks, unchanged-Skill
  verification, and preservation of onboarding, results, and Collector data.

- Crash-durable artifact publication through pinned directory descriptors:
  private temporary files and their containing directory are both fsynced,
  recursively created parent entries are synced, directory replacement is
  detected, and structured failures distinguish pre-publication from ambiguous
  post-publication storage errors.
- Hardened MCP ArtifactStore persistence: JSON artifacts publish without
  overwrite, identical content is idempotent, conflicting IDs fail closed, and
  bounded reads pin the user-owned root plus require unchanged single-link
  `0600` regular files opened with `O_NOFOLLOW|O_NONBLOCK`.
- End-to-end Collector evidence verification before a client accepts success:
  canonical plan-derived filename, service ownership, socket-group identity,
  read-only group access, single-link regular-file metadata, bounded streamed
  size, and SHA-256 are rechecked without following symlinks.
- Fail-closed Collector client authentication and response correlation. Every
  exchange now pins safe socket path metadata, requires the kernel peer UID to
  match the socket owner, bounds and types the response envelope, checks the
  exact request ID, and verifies collection PID/mode against the authorized plan.
- Bounded, versioned JSON-lines Collector operational events for startup,
  successful collection, request rejection, shutdown, and startup failure.
  Stable error/request IDs support journal correlation without logging target
  PIDs, commands, profiles, tool stderr, local paths, or tracebacks.
- Safe project-level Codex MCP configuration installation during `perflens
  setup`. PerfLens creates or updates only its marked block, preserves unrelated
  settings, refuses conflicting user-managed tables and unsafe paths, and
  supports generation-only onboarding through `--skip-codex-config`.
- Chinese-first `verify-collector` summaries for advanced, explicitly authorized
  existing-PID probes, including evidence identity, measured metric count,
  bounded diagnostics, and conclusion limits. `--json` preserves the complete
  collection artifact and `--output` safely writes it to a new file.
- Chinese-first `perflens doctor` capability summaries with mode-by-mode status,
  kernel controls, privilege boundaries, translated recommendations, and exact
  next actions. `--json` keeps console automation and `--output` safely writes
  the unchanged versioned capability artifact.
- Chinese-first terminal error summaries for `perflens` and `perflens-admin`,
  including stable error IDs, code-specific recovery guidance, and the original
  bounded technical detail. `--json-errors` and `PERFLENS_JSON_ERRORS=1`
  preserve the complete versioned `ErrorArtifact` for automation.
- Generated onboarding guides and the setup completion summary now include an
  exact, shell-quoted `perflens status` command bound to that setup directory.
  The Chinese status view prints state-specific, copyable recovery or real
  acceptance steps instead of stopping at issue labels.
- Chinese-first `perflens-admin deploy` dry-run and success summaries with
  reviewed paths, authorized UID, fixed system commands, safety boundaries,
  and an exact next action; `--json` preserves the complete versioned artifact
  for automation.

### Changed

- Collector `artifact_mode` is restricted to `0640` or `0440`; configurations
  that make evidence group-writable or unreadable by the authorized group now
  fail deployment and service startup validation.
- CI and release workflows now pin every external GitHub Action to an immutable
  full commit SHA, disable checkout credential persistence, fail closed on
  missing upload inputs, and retain intermediate artifacts for at most seven
  days. The release workflow builds and verifies with read-only repository
  permissions, then passes one named bundle to a separate publisher job whose
  only write-capable operation is `gh release create`. Weekly Dependabot checks
  now propose reviewed updates for immutable Action pins and the uv lockfile.
- CI and Release now build wheel and source distributions twice with the source
  commit timestamp as `SOURCE_DATE_EPOCH`, then reject the build unless both
  copies are byte-for-byte identical. The comparison tool rejects symlink,
  missing, empty, and oversized package inputs.
- Tag releases now generate SLSA provenance for every downloadable asset in an
  isolated `actions/attest` job. Its OIDC and attestation credentials cannot
  access checked-out project code or publish a Release, and the publisher runs
  only after attestation succeeds. Installation and release notes include
  Chinese-first checksum and signer-workflow verification commands.
- `perflens --help`, every user subcommand, and `perflens-admin --help` are now
  Chinese-first. Previously undocumented analysis limits and administrator
  archive controls now explain their units and safety boundaries; command and
  option names remain unchanged for script compatibility.
- `verify-collector` now defaults to a human-readable Chinese summary. Existing
  automation that parsed its stdout must add `--json`; authorization phrases,
  exit codes, Collector policy checks, and the artifact schema are unchanged.
- `perflens doctor` now defaults to a human-readable Chinese summary. Existing
  automation that parsed stdout must add `--json`; `--output` behavior and the
  `CollectionCapabilityArtifact` schema are unchanged.
- CLI domain errors now default to a human-readable Chinese summary. Automation
  that parses errors must place the global `--json-errors` option before the
  subcommand or set `PERFLENS_JSON_ERRORS=1`; exit codes and the versioned JSON
  schema are unchanged.
- The default `perflens-admin deploy` output is now the human-readable Chinese
  summary. Existing automation that consumes deployment JSON must pass
  `--json` explicitly.

### Fixed

- The isolated GitHub Release publisher now passes the repository explicitly
  to `gh release create`, so tag verification does not require a checkout or a
  local `.git` directory in the write-token job.
- Collector clients now include the socket inode change timestamp in their
  pinned identity, so an unlinked-and-replaced socket is rejected even when
  the filesystem immediately reuses the same inode number. Debian package
  smoke jobs now validate deployment with the real root-managed `perf` entry
  instead of a test executable rejected by the production policy.
- Single-use Collector plans now persist as atomic, private replay tombstones
  before perf starts. Failed collections remain consumed across Collector
  restarts; bounded expiry, spool locking, quota exclusion, archive/prune
  preservation, and unsafe-marker denial paths are enforced.
- Collector request frames now have a separate hard five-second completion
  timeout and an exact 64 KiB wire-size limit, preventing an incomplete local
  connection from blocking health and collection operations for the policy's
  full collection duration.
- The Collector now handles `SIGTERM` and `SIGINT` as graceful shutdown
  requests, tolerates listener-close races, and removes its Unix Socket before
  a normal process exit.
- `perflens status` now revalidates the configured MCP executable instead of
  reporting readiness for a removed, non-executable, moved, or no-longer-trusted
  entry point that merely remains in matching TOML.
- Refresh and detach now reject a marked PerfLens block if unrelated TOML
  tables were inserted inside it, preventing managed-block replacement from
  deleting user configuration that PerfLens does not own.
- Reproducible Debian builds now remove installer `direct_url.json` metadata
  and its wheel RECORD entry, preventing the absolute input-wheel path from
  changing otherwise identical main-package bytes.
- `perflens status` now checks the active project `.codex/config.toml` instead
  of treating a standalone generated snippet as proof that MCP is configured.
  Missing, invalid, oversized, unsafe, or setup-mismatched project
  configuration can no longer produce false automatic-collection readiness.
- `perflens setup --prepare-collector` now safely detects trusted native
  `/usr/bin` package entry points and writes the matching administrator command
  into both generated guides and metadata. Wheel/source installs continue to
  target `/opt/perflens`; a native main package missing its matching Collector
  package now fails early with an actionable Chinese-first error instead of
  generating unusable paths.
- Debian onboarding and Collector deployment now preserve the trusted
  `/usr/bin/perflens-mcp` and `/usr/bin/perflens-collector` entry-point symlinks
  instead of resolving them to the identity-neutral generic launcher; symlinks
  in untrusted writable directories remain rejected.
- `perflens status` now requires a bounded, authenticated Collector health
  handshake before reporting `ready_for_verification`, preventing stale,
  unreachable, malformed, or wrong-identity Unix sockets from producing false
  readiness.

## [0.1.1] - 2026-08-04

### Added

- Chinese maintainer documentation for development, architecture, security,
  and release-readiness workflows.
- Simplified Chinese counterparts and bidirectional language navigation for
  compatibility, limitations, real-world acceptance, profile semantics,
  performance budgets, schema migration, and dependency decisions.
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
- `perflens-admin deploy` for one-command, administrator-invoked Collector
  deployment from a strictly validated data-only policy, including dry-run,
  fixed command allowlists, no-overwrite behavior, and versioned results.
- An unprivileged project-workload coordinator and MCP tool that launches one
  confirmed in-project executable, captures its PID internally, and submits
  only a PID-bound plan to the Collector.
- Bilingual Chinese/English field guidance in generated `collector.toml`
  policies, including tunable, fixed-path, and security-sensitive settings.
- A versioned Collector policy format and Chinese-first `perflens status`
  command for read-only project, MCP, socket, group, and perf readiness checks.
- Reproducible split Debian 13 packages for the unprivileged toolkit and optional
  Collector entry points, with no service activation during package installation.
- `perflens-admin undeploy`, which removes only a verified managed service unit
  while preserving administrator policy, collected artifacts, users, and groups.
- A no-PID `perflens accept-collector` command that profiles a fixed,
  self-owned probe and emits versioned end-to-end host acceptance evidence.
- Independent Collector spool byte, artifact-count, and filesystem free-space
  quotas that deny new collections without deleting existing evidence.
- Read-only `perflens-admin spool-status` capacity inspection with a Chinese
  summary, versioned JSON evidence, quota headroom, and safe handling of
  unexpected non-regular spool entries.
- `perflens-admin upgrade` for explicit one-command Collector upgrades that
  preserve administrator policy and evidence, compare unit hashes, replace only
  verified managed units, and attempt rollback after activation failure.
- A versioned, read-only Collector health operation with bidirectional kernel
  peer-credential checks, used by deploy and upgrade so stale or wrong-identity
  sockets cannot produce false readiness.
- `perflens-admin update-policy` for strict dry-run validation and atomic
  application of a separate policy candidate, with authenticated health checks,
  rollback on activation failure, and immutable UID/spool boundaries.
- An explicit `archive-spool` and `prune-archived-spool` evidence lifecycle with
  bounded selection, stored ZIP manifests, per-file SHA-256 and source-identity
  verification, root-managed archives, dry-run review, and destructive
  authorization without automatic retention deletion.
- A Chinese-first `accept-collector` success summary with evidence identity,
  size, hash, metric count, conclusion boundaries, and explicit `--json` output
  for automation; acceptance now rejects runs containing no measured metric.
- Read-only `perflens-admin verify-spool-archive` validation for archive
  structure, manifest consistency, member hashes, and optional surviving-source
  identity checks, without exposing any deletion operation.

### Changed

- Collector deployment now requires exactly one authorized ordinary UID per
  instance, preventing group-readable profiles from leaking across callers.
- Release preparation now requires a CycloneDX JSON SBOM, rejects stale or
  unexpected files in `dist/`, and checksums only the six intended assets.
- CI and release jobs now have explicit timeouts and concurrency controls.
- The Performance Analysis Skill now drives policy-approved live PID collection
  through the plan/Broker workflow before deterministic analysis.
- Guided setup can opt into bounded automatic project execution and generates
  a complete MCP configuration plus natural-language, no-PID usage examples.
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
- Updated the locked `cryptography` transitive dependency from 49.0.0 to
  50.0.0 after release auditing identified CVE-2026-69247.

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

[Unreleased]: https://github.com/link0-o/PerfLens/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/link0-o/PerfLens/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/link0-o/PerfLens/releases/tag/v0.1.0
