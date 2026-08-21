# Release readiness

[简体中文](release-readiness.zh-CN.md) | English

This is a 2026-08-15 validation snapshot for the repaired 0.2.0 line, not a
permanent marketing claim. Every release must rerun all gates in the
[release procedure](releasing.md). A configured workflow is not evidence that
its corresponding remote GitHub Actions run passed.

## Current releasable scope

The stable loop includes folded, `perf script`, and system-perf-converted
`perf.data` analysis; provenance-bound hotspot/call-path/source evidence;
Profile and Benchmark comparison; typed and paged MCP tools; project-local
Codex and Claude Code Skills; and an explicitly authorized, PID-only Collector.
The Collector supports `cap_perfmon` and opt-in `paranoid3_helper` deployment,
stable `stat` and `record`, auditable hardware-to-software fallback, deployment,
upgrade, policy update, undeploy, spool inspection, archive, and explicit prune.

`sched`, `lock`, and `off_cpu` are **not part of the current stable release
claim**. They are disabled raw experiments in the `cap_perfmon` Broker without
mode-specific deterministic analyzers; the `paranoid3_helper` rejects them. The
candidate next feature release is `v0.3.0`; see the
[collector capability roadmap](collector-capability-roadmap.md).

The project still excludes an LLM API, custom agent loop, Web UI, arbitrary
automatic source editing, general benchmark platform, production APM, direct
`perf.data` binary parsing, heap/leak analysis, GPU analysis, distributed
tracing, and application-specific rules.

## Latest local gate snapshot

| Gate | Command/evidence | 2026-08-15 snapshot |
|---|---|---|
| Lint | `ruff check .` | passed |
| Strict types | `pyright` | 0 errors, 0 warnings |
| Full Python suite | `pytest -q` in the current development environment | 554 passed |
| Coverage | `pytest --cov=perflens --cov-fail-under=85` | 85.48%, passed |
| Python CI matrix | `.github/workflows/ci.yml` | Python 3.12 and 3.13 configured; the release uses the actual remote results |
| Rust format/static checks | pinned `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` | passed |
| Rust tests | `cargo test --locked` | 25 library and 2 binary tests passed |
| Schema/protocol | checked-in Schemas, cross-language valid/invalid goldens, unknown-field rejection | passed |
| Skill | structure, package, and workflow-safety tests | passed |
| wheel/sdist | repeated build, byte comparison, isolated install | passed |
| Native DEB | split Debian 13 main/Collector packages, repeat build, extract/install smoke | passed |
| Dependencies/supply chain | lock, license/vulnerability checks, SBOM, pinned Actions, provenance configuration | local gates passed; remote attestation is produced by the tag workflow |

These counts are a snapshot. As tests grow, documentation must not preserve
stale totals; a release record should retain the actual commands, commit SHA,
Python/Rust versions, and logs. The coverage gate remains 85% and must not be
lowered to accommodate new functionality.

## Collector and real-host evidence

Automation covers real Unix sockets, peer identity, PID reuse/cross-UID/replay/
expiry denial, fixed spool and quotas, artifact hashes and permissions,
deploy/upgrade/rollback/undeploy, and Python/Rust private-protocol denial paths.
Controlled executable perf test doubles exercise success and failure without
mistaking CI host privilege for product capability.

Manual Debian 13 acceptance has additionally demonstrated an authenticated
`paranoid3_helper`/unprivileged-Broker handshake, software `stat`, and
`cpu-clock record` when VMware exposed no usable hardware PMU counts. The
Collection reported `actual_event_source=software`, the fallback reason, and
the IPC/cache/branch limitations. Raw-evidence, Collection, conversion,
analysis, and Agent-visible hashes and weight conservation were verified.

That proves only the tested host and bounded workload. It does not prove a
hardware PMU, another kernel/VM/LSM, another PID, or an experimental trace mode.
Each host still requires an acceptance run by the authorized ordinary user:

```bash
perflens accept-collector --authorize-host-acceptance
```

## Security and interpretation gates

- No shell execution; user paths are canonicalized and symlink escape is denied;
  source profiles are never overwritten.
- MCP, Skill, Agent, and Python Broker do not run sudo or hold Helper privilege.
- User workloads run as the ordinary user; Collector/Helper receive only short,
  single-use, same-UID PID plans.
- The `paranoid3_helper` executes only the fixed root-owned perf path and permits
  only `stat` and `record`.
- Raw input, conversion, final analysis, and Agent-visible pages remain bound by
  identifiers and hashes.
- Parser warnings, unknown frames, lost events, truncation, and unresolved
  weight remain visible rather than becoming zero.
- A rule match is not a root cause; a Profile percentage is not elapsed time;
  software events do not support IPC/cache/branch conclusions.
- Only matched workloads, identical actual event sources, passing correctness,
  and repeated A/B measurements support a verified-improvement claim.

## Tags and next version

This historical snapshot was recorded while the source version was `0.2.0`.
The current release metadata is `0.3.0`; every `v0.3.0` tag attempt must run the
fresh gates in the release workflow rather than treating this old snapshot as proof.

Published tags should remain immutable. Even when an old tag/Release was never
distributed, deleting and recreating it is a separately reviewed repository
recovery operation. The [release procedure](releasing.md) does not present tag
replacement as a normal step; the default is to fix the issue in a new version.
