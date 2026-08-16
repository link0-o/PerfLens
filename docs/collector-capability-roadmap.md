# PerfLens v0.3.x Collector and user-space lock roadmap

English | [简体中文](collector-capability-roadmap.zh-CN.md)

Status: **v0.3.0 implemented in source; not released**

Last audited: 2026-08-16 against the current pre-release v0.3.0 `main`

Candidate releases: `v0.3.0` and `v0.3.1`

This document separates the shipped `0.2.0` baseline, v0.3.0 code awaiting release gates, and
planned v0.3.1 work. Source presence is not a stable release claim. v0.3.0 still requires the full
Python, Rust, DEB, lifecycle, and real-Debian-host gates below.

The source tree now contains the versioned Trace contracts, target-filtered Rust Trace Helper,
three deterministic analyzers and verifier, separate policy/socket/spool, transactional setup and
profile lifecycle, and three-mode `accept-collector` probe. The v0.3.1 runtime adapters remain
unimplemented.

## 1. Decisions

1. **`v0.3.0` completes generic wait diagnosis.** It retains the stable `stat/record` CPU workflow
   and adds deterministic `sched`, `off_cpu`, and `lock` analysis, bounded collection, guided
   deployment, and real-host acceptance.
2. **Feature profiles and privilege modes are orthogonal.** `full_diagnostics/cpu_only` select the
   evidence surface; `cap_perfmon/paranoid3_helper` select how system services obtain privilege.
3. **Full diagnostics is recommended for a compatible fresh host, but never silently activated.**
   DEB installation remains non-interactive and inactive. An administrator explicitly runs
   `sudo perflens-admin setup`, reviews preflight, chooses a profile, and acknowledges risk.
4. **The existing Rust Helper remains permanently limited to `stat/record`.** Level-3 trace work
   goes through a new, separate Trace Helper with its own service, socket, protocol, policy, raw
   spool, lifecycle, and audit.
5. **`v0.3.1` adds four formal user-space lock adapters:** native pthread, Java JFR, CPython locks,
   and Go mutex/block profiles. Custom, inlined, uninstrumented, spinning, and lock-free paths must
   disclose visibility gaps rather than claim universal coverage.
6. Evidence semantics, Golden fixtures, conservation checks, and independent verification precede
   every privilege expansion.

## 2. Current `0.2.0` baseline

| Layer | `stat` / `record` | `sched` / `lock` / `off_cpu` |
|---|---|---|
| Public Python and CLI/MCP types | shipped and used | raw entry points exist; this is not stable support |
| Generated policy | permits `record, stat` | denies by default |
| `cap_perfmon` Collector | fixed argv, duration, and artifacts | fixed raw commands but no dedicated analysis loop |
| `paranoid3_helper` | Rust protocol permits `Record/Stat` | strictly rejects them |
| Deterministic analysis | typed stat plus verified on-CPU profiles | no stable interval/latency/wait artifacts |

The shipped CPU workflow binds the exact workload, runs short stat and optional record collection,
binds raw evidence hashes and event source through conversion, and requires correctness plus a
matched A/B before claiming a verified improvement. Software fallback remains useful for on-CPU
hotspots but cannot support IPC, hardware cache-miss, or branch-miss conclusions.

The missing areas are runnable delay, paired off-CPU intervals, stable kernel-lock/futex
relationships, and runtime-specific user-space lock semantics. A low context-switch, migration, or
page-fault count does not prove that I/O waits, contention, allocator churn, or memory pressure are
absent.

## 3. `v0.3.0` guided setup and mode model

### 3.1 Package boundary

The `perflens` and `perflens-collector` DEBs install only programs, templates, and documentation.
Package installation must not prompt, create administrator policy, start services, edit sysctl or
file capabilities, or touch projects. Its completion message may direct the administrator to:

```bash
sudo perflens-admin setup
```

### 3.2 Two primary feature profiles

The planned interactive wizard first presents exactly two primary profiles:

```text
1. Full diagnostics (recommended)
   stat + record + sched + off_cpu + lock

2. CPU-only tuning
   stat + record, with a smaller evidence and privilege surface
```

- `full_diagnostics` is recommended only when every required host preflight passes.
- `cpu_only` is the minimum profile and the compatibility result for every existing `0.2.0`
  deployment after package upgrade.
- If tracefs, kernel events, perf support, or a security prerequisite is missing, the wizard marks
  full diagnostics unavailable and recommends `cpu_only`; it never deploys a partial profile under
  the full name.
- `analysis_only` remains an advanced automation value and failure fallback, not a third primary
  feature profile.

The planned non-interactive form is:

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode cap_perfmon \
  --dry-run
```

`--feature-profile` is implemented in the v0.3.0 source tree but is not present in `0.2.0`
packages. It remains a source/local-build validation interface until the release gates pass.

### 3.3 Privilege recommendation and acknowledgement

| Privilege mode | Recommended host | `cpu_only` | `full_diagnostics` |
|---|---|---|---|
| `cap_perfmon` | dedicated capability works in a real short probe | Python Broker runs stat/record | Broker plus separate Trace Helper with audited Trace capabilities |
| `paranoid3_helper` | Debian level 3 must remain | current Helper runs stat/record | current Helper plus a separate Trace Helper |

The wizard recommends from observed host facts while retaining explicit `--mode` selection. It
never changes `perf_event_paranoid`; an incompatible explicit choice is rejected before writes.
Full diagnostics requires trace-data/privacy/overhead acknowledgement. The level-3 implementation
also requires the existing privileged-Helper acknowledgement:

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode paranoid3_helper \
  --acknowledge-privileged-helper-risk \
  --acknowledge-trace-risk
```

### 3.4 Post-install profile switching

The implemented v0.3.0 profile lifecycle is separate from privilege-mode switching:

```bash
sudo perflens-admin switch-profile full_diagnostics --dry-run
sudo perflens-admin switch-profile full_diagnostics --acknowledge-trace-risk
sudo perflens-admin switch-profile cpu_only --dry-run
sudo perflens-admin switch-profile cpu_only
```

`switch-profile` validates policy, managed units, host capabilities, and a deterministic command
plan; applies the trace topology atomically; authenticates health; and restores the previous
policy, units, and services on failure. Switching back to CPU-only stops the Trace Helper but
preserves administrator configuration and every artifact.

Existing `switch-mode` continues to change only `cap_perfmon/paranoid3_helper`. With full
diagnostics active, that transaction must converge the Broker and both Helper topologies to the
selected mode. Package upgrade from `0.2.0` never creates trace policy, starts a Trace Helper, or
expands allowed modes. Projects continue to run plain `perflens init`, which safely discovers both
the deployed privilege mode and feature profile.

## 4. `v0.3.0` Trace architecture

```text
ordinary Agent / Skill / MCP
        │ typed, explicitly authorized PID/workload plan
        ▼
unprivileged Python Broker
        │ private Trace Helper socket
        ▼
separate Rust Trace Helper + packaged fixed eBPF
        │ in-kernel authorized-TGID/TID filtering
        │ private target-only NDJSON (not perf.data)
        ▼
fixed streaming sanitizer → TraceEvidence → deterministic analysis + verifier
```

Both privilege modes use the separate Trace Helper for advanced collection; the Python Broker does
not perform all-CPU trace. The current Rust Helper continues to accept only `Record/Stat`. The new Trace Helper has a
separate binary, systemd unit, private socket/group, Rust protocol and JSON Schema, policy, fixed
raw spool, capability audit, acknowledgement, upgrade, rollback, and removal path. Ordinary users
cannot access its socket or raw spool; only target-scoped, bounded, privacy-checked derived evidence
is published to the MCP-readable spool.

Stock `perf record -p PID` cannot completely observe an external waker or the target's switch-in
event, so it is not a stable sched/off-CPU backend. PerfLens never invokes or silently falls back
to `perf -a` or equivalent `-C 0-N` capture. The packaged backend filters the authorized target in
kernel before any event or foreign metadata reaches a user-space spool.

Fixed constraints include:

- same-UID PID/TID and start-time binding, short expiry, and single use;
- no `perf -a`, system-wide target, arbitrary tracepoint, arbitrary argv, arbitrary output, shell,
  environment, or privileged workload launch;
- fixed mode/event allowlists, at most 10 seconds, 64 MiB, and one concurrent worker by default;
- isolation or redaction of other-task metadata;
- `partial` or failure for excessive loss, unpaired records, or truncation;
- no capability expansion beyond the independently audited minimum; failure is preferred to an
  unrestricted root service or `CAP_SYS_ADMIN` on the Python Broker;
- no `perf.data` in the Trace path; record profiles still use an external-tool adapter rather than
  direct binary parsing.

## 5. `v0.3.0` deterministic analysis

Every new artifact carries `schema_version`, input hash/size, converter path/version/hash/argv,
target identity, event clock and units, loss/order/duplicate/unpaired counts, `quality_status`,
allowed and forbidden conclusions, content digest, conversion fingerprint, and an independent
verifier.

`v0.3.0` fixes these public artifact names. Renaming or changing field semantics requires a Schema
migration rather than same-version MCP guessing:

- **TraceEvidenceArtifact:** target-filtered, normalized, bounded trace events and source manifest.
- **SchedulerAnalysisArtifact:** runtime intervals and runnable-delay analysis.
- **OffCpuAnalysisArtifact:** blocked/sleeping, wakeup, and resumed-runtime intervals.
- **LockAnalysisArtifact:** kernel locks and generic futex/user-wait candidates.
- **TraceAnalysisVerificationArtifact:** independent input identity, event-count, interval
  conservation, quality, and Agent-visible-content verification.

TraceEvidenceArtifact carries no private path, foreign identity, or raw address. It references the
immutable private target-only NDJSON by SHA-256, size, collection ID, target identity, and fixed
converter manifest and carries the public canonical NDJSON SHA-256. Conversion writes a new temporary output and publishes it
atomically only after complete validation; bounded raw diagnostics are retained on parser failure,
and the source profile is never overwritten.

- **SchedulerAnalysisArtifact:** per-thread runtime, runnable delay, switches, migrations, mean,
  p50/p95/p99/max, sample count, and worst intervals. Missing wakeup/switch-in pairs never produce
  fabricated latency.
- **OffCpuAnalysisArtifact:** paired switch-out, wakeup, and switch-in intervals; separable blocked
  and runnable time; task state, switch-out stack, waker, and completeness. Disk/network/lock/timer
  categories remain candidates unless directly established.
- **LockAnalysisArtifact:** only contention counts, wait distributions, opaque lock identity,
  owner/waiter, and call paths actually supplied by evidence. Hold time requires reliable
  acquire/release pairing. Futex/off-CPU correlation is a user-lock wait candidate in `v0.3.0`, not
  a complete language-runtime lock view.

TraceAnalysisVerificationArtifact reports `passed/failed/skipped` for raw identity, converter
manifest, target scope, event counts, time intervals, aggregate conservation, loss/truncation
consistency, and Agent-visible digest. Any safety or conservation failure prevents the MCP from
publishing that analysis as usable evidence.

## 6. `v0.3.0` milestones

1. **Complete in source:** freeze stat/record compatibility.
2. **Complete in source:** target-filtered IR, Schemas, Goldens, and verification.
3. **Complete in source:** deterministic sched/off-CPU/lock analysis and denial paths.
4. **Complete in source:** separate Rust Trace Helper, private protocol, BPF target filtering, and
   privacy checks.
5. **Complete in source:** setup/switch-profile/status/acceptance, MCP routing, lifecycle rollback.
6. **Pre-release:** synchronize the Skill and bilingual user documentation.
7. **Pre-release:** full Python coverage plus Rust fmt/clippy/test/audit/deny and protocol matrix.
8. **Pre-release:** reproducible two-DEB install/upgrade/switch/remove/non-activation smoke tests.
9. **Pre-release:** Debian 12/13 four-topology host tests including external wakeup, switch-in,
   dynamic threads, lock contention, loss, cross-UID denial, and public-byte privacy scanning.

Installed capability is not permission to collect everything on every request. The Skill starts
with short stat evidence, adds record for CPU stacks, sched for runnable-delay candidates, off-CPU
for low-CPU wall-time gaps, or lock evidence for contention. It cannot expand the authorized PID,
command, duration, event set, or privilege.

## 7. `v0.3.1` user-space lock adapters

### 7.1 Coverage contract

There is no single perf command that observes every user-space lock implementation. “Complete
coverage” in `v0.3.1` means that four formal runtime families have capability discovery,
collection/import, normalized deterministic analysis, and explicit quality boundaries. It does not
mean that arbitrary custom locks, lock-free algorithms, inlined paths, or invisible fast paths are
observable.

`v0.3.1` fixes these public artifacts:

- **RuntimeAdapterCapabilityArtifact:** runtime/version, adapter/backend version, availability,
  supported locks/events, required external tools, launch-instrumentation/attach/privilege needs,
  fast-path visibility, and limitations.
- **RuntimeLockEvidenceArtifact:** target identity, source manifest, normalized events,
  sampling/threshold configuration, loss/truncation counters, and input hashes.
- **RuntimeLockAnalysisArtifact:** evidence-qualified aggregation by lock, thread, call path, and
  wait type.
- **RuntimeLockAnalysisVerificationArtifact:** independent input, converter, event-count,
  wait/hold conservation, aggregate, and Agent-visible-content verification.

Normalized events use strict enums:

```text
event_kind = wait_begin | wait_end | acquire | release |
             park | unpark | sampled_contention
measurement_semantics = exact | thresholded | sampled | cumulative
```

Common fields include runtime/backend, PID/TID and process-start identity, `lock_kind`, an
artifact-scoped opaque `lock_id`, waiter and only evidence-supplied owner, `timestamp_ns`, optional
`duration_ns`, `stack_id`, symbol/source, sampling period or fraction, threshold, loss/truncation,
fast-path visibility, coverage scope, allowed/forbidden conclusions, and converter manifest.

Lock IDs are assigned deterministically by first canonical appearance within one artifact, expose
no raw address, and cannot be correlated across artifacts. Sample counts are never exact event
counts, cumulative profiles are not event streams, and hold time is unavailable without reliable
acquire/release pairing. Strict readers reject unknown fields, oversized frames, invalid or
mismatched PIDs, negative/reversed time, duplicate event IDs, non-finite weights, unknown enums,
excessive lock/TID/stack cardinality, and non-conserving aggregates.

### 7.2 Native C/C++

- Formally support dynamically linked glibc/pthread mutex, rwlock, and condition-variable paths.
- Offer explicit launch-time instrumentation/interposition that runs as the target ordinary user.
- Import existing USDT/uprobe evidence while recording library version, symbol, and ABI capability.
- Mark static linkage, inlined/custom atomics, spin locks, uncontended fast paths, missing symbols,
  unknown ABIs, and incompatible wrappers `partial/unsupported` when they are not observable.
- Live eBPF/uprobe remains disabled and belongs to neither existing Helper nor the Trace Helper. If
  acceptance proves new privilege necessary, it receives a separate service, policy, socket,
  removal flow, and administrator risk acknowledgement.

### 7.3 Java

- Prefer a user-installed JDK Flight Recorder and support JDK 17, 21, and 25 LTS.
- Use fixed, PerfLens-versioned JFR settings for `jdk.JavaMonitorEnter`, `jdk.JavaMonitorWait`, and
  `jdk.ThreadPark`, plus virtual-thread events discovered from the actual runtime.
- Preserve enablement and duration threshold per event. Default templates may omit events below a
  threshold, so absence is not proof of no wait; lowering thresholds must disclose extra overhead.
- Detect async-profiler as an optional enhanced backend; expose JVMTI only as a controlled import
  interface.
- Do not bundle a JDK, async-profiler, or a general custom JVMTI agent in the core DEBs.

Event names and threshold semantics follow the
[Oracle JFR performance guide](https://docs.oracle.com/en/java/javase/17/troubleshoot/troubleshoot-performance-issues-using-jfr.html),
while startup capability discovery still verifies the current JDK event metadata.

### 7.4 Python

- Formally support CPython 3.12/3.13 `threading.Lock`, `RLock`, `Condition`, and `Semaphore`.
- Model the GIL, CPython-internal locks, and application threading locks separately.
- Detect CPython 3.13 free-threaded builds and suppress traditional GIL conclusions.
- Treat DTrace/SystemTap/USDT as optional import backends with build/version capability reporting.
- Mark C-extension, custom atomic, and uninstrumented locks invisible or partial.

Probe names and arguments are implementation details. The adapter records the interpreter build,
version, and actual probe inventory and does not assume cross-version compatibility; see the
[CPython DTrace/SystemTap instrumentation guide](https://docs.python.org/3.13/howto/instrumentation.html).

### 7.5 Go

- Adapt the official mutex and block profiles from an existing local pprof endpoint or an
  application that explicitly configures `SetMutexProfileFraction/SetBlockProfileRate`.
- Use the user's fixed `go tool pprof` as the adapter rather than directly parsing the binary
  profile format.
- A mutex profile attributes approximate cumulative blocked time at the end-of-critical-section or
  unlock stack and uses event-based sampling; it is not an exact contention log.
- A block profile attributes cumulative time at the location that blocked and uses time-based
  sampling; it does not provide a complete owner relationship.
- Report channels, WaitGroups, Conds, and runtime-internal locks only to the extent represented by
  the official profile, without inventing exact owners or per-event wait/hold intervals.

The canonical semantics are the official [Go runtime](https://pkg.go.dev/runtime) and
[Go runtime/pprof](https://pkg.go.dev/runtime/pprof) documentation. Artifacts retain the actual
`SetMutexProfileFraction` and `SetBlockProfileRate` values and never merge those sampling models.

### 7.6 External tools, authorization, and custom import

JDK, Go, async-profiler, and SystemTap remain optional external dependencies. PerfLens detects
versions and gives Chinese setup guidance but neither downloads nor bundles them into the two core
DEBs. Every runtime adapter is disabled by default. JFR, pprof, and ordinary launch-time
instrumentation must run as the target ordinary user, never root. `LD_PRELOAD`, JVM/JFR attachment,
pprof access, or probe deployment always needs a separate explicit authorization. Privileged
eBPF/uprobe is an independent, default-off administrator boundary and cannot widen the MCP, Skill,
Python Broker, current stat/record Helper, or `v0.3.0` Trace Helper. The planned project opt-in is
`perflens init --runtime-locks`.

Custom locks may use a versioned NDJSON import contract. A strict header declares source/version,
adapter version, target identity, timestamp clock/unit, measurement semantics, visible lock and
fast paths, sampling/threshold settings, lost events, and whether owner/hold time is genuinely
available before normalized events are accepted. Unknown fields, duplicate headers, oversized
frames, invalid/mismatched PIDs, reversed time, undeclared semantics, non-conserving aggregates,
and fabricated owner capability are rejected before artifact publication. This remains an adapter
boundary, not a new Agent or plugin framework.

### 7.7 `v0.3.1` implementation commit order

Implementation is split into independent, reviewable, reversible commits:

1. Public artifact Schemas, capability discovery, quality model, NDJSON contract, and verifier.
2. Native pthread adapter, ABI capability detection, and ordinary-user instrumentation.
3. Java JFR adapter, fixed settings, and optional async-profiler/JVMTI import interface.
4. CPython adapter, GIL/internal/threading layers, and free-threaded capability discovery.
5. Go mutex/block pprof adapter with both sampling models.
6. CLI/MCP/Skill selection, unified reports, paging, and diagnosis bundles.
7. Security denials, instrumentation overhead, compatibility matrix, and four real runtimes.
8. Bilingual release docs, both-DEB upgrade/removal smoke tests, and the `v0.3.1` release gate.

## 8. Acceptance and release wording

Every new mode and adapter needs versioned Schemas, bilingual semantics, real fixtures, Goldens,
strict unknown-field rejection, malformed/bounded/loss/order/PID-reuse/tool-substitution tests,
hash and conservation verification, cross-UID/replay/path/command/spool-escape denial tests,
overhead budgets, exact-versus-statistical acceptance, complete deployment lifecycle tests, Python
and Rust quality gates, a real Debian systemd matrix, and real C/C++/Java/Python/Go workloads.

The runtime-lock matrix covers uncontended, low-contention, high-contention, recursive, read/write,
and condition-variable waits, plus target exit, PID reuse, missing symbols, lost events, and an
unavailable adapter. Exact backends use exact event/interval expectations; thresholded, sampled,
and cumulative backends use declared statistical tolerances, and “not sampled” never means “no
contention.” Each backend measures target overhead when disabled, enabled but idle, and under high
contention; exceeding budget produces a warning or fails closed.

Where perf privilege is needed, dedicated `CAP_PERFMON` is preferred over broad `CAP_SYS_ADMIN`, as
recommended by the [Linux perf security guide](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html).
Any additional capability needs evidence from the corresponding isolated service's real denial
and acceptance path.

Until those gates pass, the shipped release continues to advertise only `stat/record` as stable.
`v0.3.0` may advertise `full_diagnostics` only if every included mode is complete. `v0.3.1` must
publish an exact runtime/backend/version/sampling/fast-path support matrix. Software fallback still
forbids IPC/cache/branch claims, and PerfLens remains outside heap profiling, request-level I/O APM,
GPU profiling, and distributed tracing. Release notes must be generated from the final
implementation and test evidence, not copied from this roadmap.

`v0.3.1` is stable only after all four adapters, the shared verifier, security denial paths, the
real-runtime matrix, and installation, upgrade, rollback, and removal tests for both DEBs pass. If
one adapter is missing, the release claim is narrowed or the version is delayed; it cannot retain
the “four formal runtime families” wording.
