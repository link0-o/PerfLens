# PerfLens v0.4.0 Runtime Lock workflow

[简体中文](runtime-locks.zh-CN.md) | English

Status: **implemented in the repository as a v0.4.0 prerelease; not part of the published v0.3.2 packages**.
The feature becomes a stable release claim only after the v0.4.0 version, package, runtime-matrix,
and real-host gates pass. Release v0.3.2 remains the published baseline.

Runtime Lock is a deterministic evidence pipeline for language-level waiting and contention. It
does not treat every futex as a language lock, does not infer an owner or hold interval that the
source did not provide, and does not make sampled or cumulative profiles look like exact events.

## Enable a project

```bash
cd /absolute/path/to/project
perflens init --runtime-locks

# Combine it with the managed/optimization Docker policy when needed:
perflens init --docker --runtime-locks
```

Initialization writes `perflens-setup/runtime-locks.toml` and updates the project-local MCP and
Skill integration. It performs capability discovery only. It does not instrument or attach a
process, import evidence, start a workload, access pprof, or grant authority. `perflens init
--update` preserves the reviewed policy and does not enlarge adapters, target scopes, import roots,
or budgets.

The default policy bounds a session to six workloads, 1,200 active seconds, a 3,600-second hard
expiry, 64 MiB per raw/public artifact, 512 MiB total evidence, one concurrent Adapter, 30 seconds
per normal collection, and a three-second/20,000-event exact-mode ceiling. These values are
ceilings, not instructions to consume every run or Adapter.

## Authorization and evidence flow

The MCP workflow is:

```text
inspect_runtime_lock_capability
  -> preview_runtime_lock_session
  -> show the exact target, Adapter, semantics, payload, tools, paths, and budgets
  -> wait for one fresh user confirmation
  -> authorize_runtime_lock_session
  -> collect_runtime_lock_evidence or import_runtime_lock_evidence
  -> analyze_runtime_lock_evidence
  -> verify_runtime_lock_analysis
  -> bounded hotspot/call-path queries and optional comparison/diagnosis
  -> revoke_runtime_lock_session
```

Preview and authorization are content-bound to the project policy, target/workload identity,
Adapter payload and tools, measurement semantics, import roots, and budgets. Authorization is kept
in the current MCP process; persisted Artifacts contain only a receipt digest. An MCP permission
popup or client allowlist is categorical tool access, not consent to a resolved target.

The stable target model is deliberately narrow:

- a host workload launched under the reviewed Runtime Lock session;
- a PerfLens managed temporary container or Docker optimization baseline/candidate;
- controlled import from an authorized project-relative root;
- for Go only, an explicitly authorized same-UID local process whose literal-loopback pprof socket
  and PID identity can be bound.

PerfLens does not inject into an arbitrary running process or arbitrary existing container. Native,
CPython, and Java active collection is launch-time only. There is no live JVM attach or stable
eBPF/uprobe path in v0.4.0.

## Evidence semantics

Runtime Lock Evidence schema 1.1 represents OS threads, Java platform/virtual threads, Go
goroutines, and process aggregates. One Evidence Artifact has exactly one of these semantics:

- `exact`: visible events are exact within the bounded observation surface;
- `thresholded`: only events meeting the configured duration threshold are present;
- `sampled`: observations are sampled and are not exact contention counts;
- `cumulative`: a runtime Profile reports aggregates rather than an event log.

Different JFR thresholds and Go mutex/block profiles remain separate Evidence Artifacts. The
Analyzer aggregates by opaque lock ID, execution context, call path, wait result, and lock kind,
while preserving omitted counts and weights. A lock ID is stable only inside one Artifact and is
derived without exposing its source address. Exact owner and hold-time fields require genuine,
pairable source evidence.

The independent verifier replays conversion when the private source is available, validates source
and normalized digests, event pairing and time order, target/context isolation, pagination, and
count/time conservation. `partial` is a usable but explicitly limited quality result; it is never
automatically upgraded to a root cause or Verified Improvement.

## Adapter matrix

| Adapter | Repository v0.4.0 prerelease boundary | Important limits |
|---|---|---|
| Native pthread | Debian 12/13 amd64, glibc 2.36/2.41, dynamically linked pthread mutex/rwlock/condition; launch-time fixed `LD_PRELOAD`; thresholded 1 us and bounded exact modes | Static/musl/setuid/file-cap targets, inline/custom atomics, spinlocks, and invisible fast paths are partial or unsupported; no live uprobe/eBPF |
| Java JFR | JDK 17/21/25; launch-time JFR; fixed `balanced` 10 ms or `deep` 1 ms configuration; `JavaMonitorEnter`, `JavaMonitorWait`, `ThreadPark`, and metadata-discovered virtual-thread events | No live attach; the matching JDK `jfr print --json` performs bounded conversion; threshold omission is not “no wait”; absent acquire/release pairs forbid owner/hold claims |
| CPython threading | CPython 3.12/3.13 public `threading.Lock`, `RLock`, `Condition`, and `Semaphore`; ordinary-user launch bootstrap; thresholded 10 us and bounded exact modes | Does not impersonate every `_thread` or C-extension lock; GIL/internal/application locks stay separate; free-threaded 3.13 forbids traditional-GIL conclusions |
| Go pprof | Go 1.24-1.27 fixed `go tool pprof -raw`; private file mutex/block profiles; same-UID literal-loopback host pprof when explicitly enabled | Docker defaults to the file backend and opens no network; PerfLens does not enable runtime profile rates or modify source; mutex/block remain separate cumulative Evidence whose rows are sampled contention observations, without fabricated TID, owner, or lock object |
| Generic NDJSON | Strict schema 1.0/1.1 controlled import with bounded streaming and replay | Import source must declare its exact/thresholded/sampled/cumulative meaning, clocks, visibility, loss, owner and hold provenance; malformed, cross-target, out-of-order, or non-conserving input is rejected |

JDK, Go, async-profiler, DTrace/SystemTap, and other runtime tools are optional external
dependencies. PerfLens detects them; the two core DEBs do not download or bundle those runtimes.
The main native DEB carries the fixed, root-owned, capability-free pthread probe and Runtime Lock
supervisor. Neither is activated by package installation.

## Docker optimization integration

In the repository v0.4.0 prerelease, a Docker optimization Preview may extend the v0.3.2 workflow
with one reviewed Runtime Lock Adapter and semantics. When it does, the one Docker optimization
confirmation also authorizes that bounded Runtime Lock scope; PerfLens does not create a second
hidden authorization. Runtime Lock budget is checked before container creation and charged only to
the same single-use workload lease. Published v0.3.2 packages cannot request this extension.

Baseline and candidate comparisons bind the exact Build content digest, recipe, Builder/network
policy, platform, immutable context, Container Run and Measurement, runtime/tool/payload identity,
and resource comparison. A changed candidate image digest is valid Treatment only when the mutable
manifest changed under the same fixed environment. Runtime Lock evidence alone can produce a
candidate or `no_material_change`; final `verified_improvement` still requires the outer Docker A/B
correctness, Benchmark, perf-event-source, resource-transfer, and deterministic replay gates.

Any post-processing or persistence failure makes Runtime Lock unavailable for the parent session
and prevents misleading continuation. Identity replacement, policy/tool/payload changes, budget
exhaustion, revocation, or expiry fail closed and are not retried unchanged.

## Offline CLI

The CLI can handle controlled evidence without launching a target:

```bash
perflens import-runtime-lock-evidence \
  --input ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-evidence.json

perflens analyze-runtime-lock-evidence \
  --input ./runtime-lock-evidence.json \
  --output ./runtime-lock-analysis.json

perflens verify-runtime-lock-analysis \
  --analysis ./runtime-lock-analysis.json \
  --evidence ./runtime-lock-evidence.json \
  --source ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-verification.json
```

Outputs are append-only and redacted. They do not persist private raw paths, authorization tokens,
source contents, raw lock addresses, environment variables, or credentials.
