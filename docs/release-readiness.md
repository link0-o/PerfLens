# Release readiness

[简体中文](release-readiness.zh-CN.md) | English

This is the 2026-08-26 validation record for release v0.3.2. It is not a substitute for the remote
tag workflow or for acceptance on each deployed host. Every release reruns the
[release procedure](releasing.md), and a configured workflow is not evidence that its remote run
passed.

## Release scope

The v0.3.0 Linux-host `stat/record/sched/off_cpu/lock` path and v0.3.1 fixed-image Docker path
remain supported. v0.3.2 adds the opt-in `bounded_optimization_session`:

- one reviewed authorization binds the client connection, Recipe, immutable context, mutable
  paths, Benchmark contract, Collector policy, Builder/network identity, and hard budgets;
- baseline plus at most three candidate builds use private, content-addressed context snapshots;
- the Agent chooses `stat`, `record`, or an available Trace mode from evidence rather than running
  every mode mechanically;
- Build Artifacts, workload evidence, correctness/Benchmark output, resource context, treatment,
  and deterministic replay are bound into matched A/B iterations;
- preview never builds or pulls, and the session never authorizes arbitrary Docker arguments,
  paths, commits, pushes, tags, or releases.

The compatible v0.3.1 target runtime provides one explicit process in a local Linux Docker Engine
with cgroup v2:

- bounded discovery and identity binding for an existing container;
- fixed-policy managed temporary containers held at the packaged Container Gate;
- `per_run` and connection-scoped, memory-only `bounded_session` authorization;
- container-bound `stat/record` and `full_diagnostics` trace plans;
- cgroup v2 resource context, module/Build-ID/source mapping, and PMU-fallback provenance;
- evidence-bound Benchmark, treatment, correctness, and matched A/B verification;
- project-scoped Codex, Claude Code, OpenCode, and local Copilot Skill/MCP integration through
  `perflens init --docker` and explicit client selection.

The release does not include remote Docker, Docker Desktop VMs, Compose/Kubernetes, arbitrary
Docker arguments, whole-container perf aggregation, or the planned v0.4.0
C/C++/Java/Python/Go runtime-lock adapters. Optimization builds are available only through the
typed local Build Adapter and one of its three explicit network tiers.

## Automated local gates

| Gate | 2026-08-26 release result |
|---|---|
| Ruff | passed |
| Pyright strict mode | 0 errors, 0 warnings |
| Python 3.12 | 1324 passed; 85.19% coverage |
| Python 3.13 | 1324 passed; 85.19% coverage |
| Rust format/Clippy/tests | passed |
| Rust dependencies | `cargo audit` clean with the official local advisory DB clone; `cargo deny check` passed |
| Protocol/Schema | generated files clean; Python/Rust valid and invalid goldens passed |
| Python packages | wheel and sdist built reproducibly and passed isolated smoke tests |
| Debian packages | two reproducible `0.3.2-1` amd64 DEBs passed extract/package smoke; no service or Docker activation |
| Python dependencies | locked runtime export passed `pip-audit --no-deps --disable-pip --strict`; CycloneDX 1.5 SBOM generated |

Exact counts describe the tagged checkout and will change as tests grow. The coverage gate
remains 85% and must not be lowered for a release.

## Security and interpretation gates

- Docker, Agent, Skill, MCP, Broker, and Helper boundaries remain separate; no component invokes
  sudo or changes sysctl, Docker groups, daemon configuration, or socket permissions.
- Docker commands and mount/network/resource policy derive from typed project contracts. Remote
  endpoints, arbitrary arguments, unbound build/pull, privileged mode, host PID, devices, extra
  capabilities, Docker-socket mounts, and host-path escape are rejected.
- Offline build tiers reject every explicit `RUN --network` value except `none`; the pinned
  administrator-network tier admits only `none` or `default`.
- Preview/session expiry has a bounded cleanup timer and interaction-time pruning; MCP disconnect
  revokes active optimization authority and conservatively releases identity-verified resources.
- The Broker, stat/record Helper, and Trace Helper independently verify the container target's UID,
  PID start time, namespace, cgroup, plan lifetime, single-use identity, and limits.
- Public output omits full inspect data, environment, labels, socket/mount-source/cgroup paths, and
  out-of-target argv. Missing symbol/source evidence remains `partial`.
- A cgroup delta is whole-container context, not target-process-exclusive evidence. Software PMU
  fallback cannot support IPC, cache-miss, branch-miss, or microarchitectural conclusions.
- `Verified Improvement` requires a changed treatment, identical environment fingerprint,
  container-bound successful correctness/Benchmark evidence, absolute improvement, deterministic
  replay, and no observed resource transfer.

## Real-host acceptance and remaining compatibility boundary

Automation uses real Unix sockets plus bounded Docker/perf test doubles. On 2026-08-26 one installed
rootful-Docker host ran a non-root v0.3.2 bounded optimization session end to end: Preview and one
authorization, baseline/candidate builds, correctness plus seven-sample Benchmark, software-event
`stat` and `record` on both sides, deterministic comparison, and identity-verified container
cleanup. The Benchmark and absolute CPU time strongly separated, the fixed environment and event
source matched, and deterministic replay passed. The Iteration nevertheless remained
`not_comparable` because both profiles had partial unresolved-symbol quality and the short-lived
containers exposed only lower-bound cgroup resource deltas. This is the intended conservative
gate; it is not a `Verified Improvement` claim.

That acceptance proves only the tested rootful daemon, non-root workload, kernel, perf, Builder,
and project contract. Rootless Docker, administrator-enabled UID 0 targets, different Builders,
and other host combinations still require independent acceptance. Package non-activation and
upgrade/rollback/removal remain covered by package/transaction tests and should also be checked by
administrators on their deployment host.

Create the local annotated tag only from the clean, validated release commit. Do not push it until
that commit is on `origin/main` and branch CI is green; the tag-triggered release workflow then
repeats all release gates before publication. Existing `v0.3.0` and `v0.3.1` tags remain immutable.
