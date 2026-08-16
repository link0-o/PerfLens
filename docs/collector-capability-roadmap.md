# PerfLens v0.3.x Collector and user-space lock roadmap

English | [简体中文](collector-capability-roadmap.zh-CN.md)

Status: **next-version design and acceptance contract**

Last audited: 2026-08-16 against the `0.2.0` line after `a7a5002`

Candidate releases: `v0.3.0` and `v0.3.1`

This document separates shipped facts from planned work. Nothing marked as planned may be
advertised as available, selected by the Skill, or enabled by default before implementation and
all acceptance gates are complete.

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

`--feature-profile` is a `v0.3.0` design, not a command shipped by `0.2.0`.

### 3.3 Privilege recommendation and acknowledgement

| Privilege mode | Recommended host | `cpu_only` | `full_diagnostics` |
|---|---|---|---|
| `cap_perfmon` | dedicated capability works in a real short probe | Python Broker runs stat/record | bounded Python Collector trace path |
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

The planned profile lifecycle is separate from privilege-mode switching:

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
  ├─ cap_perfmon: fixed perf trace argv
  └─ level 3: private Trace Helper socket → separate Rust Trace Helper
                                                   │ private raw perf.data
                                                   ▼
fixed perf adapter → bounded canonical events → deterministic analysis artifact
```

The current Rust Helper continues to accept only `Record/Stat`. The new Trace Helper has a
separate binary, systemd unit, private socket/group, Rust protocol and JSON Schema, policy, fixed
raw spool, capability audit, acknowledgement, upgrade, rollback, and removal path. Ordinary users
cannot access its socket or raw spool; only target-scoped, bounded, privacy-checked derived evidence
is published to the MCP-readable spool.

Fixed constraints include:

- same-UID PID/TID and start-time binding, short expiry, and single use;
- no `perf -a`, system-wide target, arbitrary tracepoint, arbitrary argv, arbitrary output, shell,
  environment, or privileged workload launch;
- fixed mode/event allowlists, at most 10 seconds, 64 MiB, and one concurrent worker by default;
- isolation or redaction of other-task metadata;
- `partial` or failure for excessive loss, unpaired records, or truncation;
- no capability expansion beyond the independently audited minimum; failure is preferred to an
  unrestricted root service or `CAP_SYS_ADMIN` on the Python Broker;
- external-tool adapters rather than direct `perf.data` binary parsing.

## 5. `v0.3.0` deterministic analysis

Every new artifact carries `schema_version`, input hash/size, converter path/version/hash/argv,
target identity, event clock and units, loss/order/duplicate/unpaired counts, `quality_status`,
allowed and forbidden conclusions, content digest, conversion fingerprint, and an independent
verifier.

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

## 6. `v0.3.0` milestones

1. Freeze the `stat/record` and policy-compatibility baseline.
2. Fix conversion commands, common event IR, Schemas, Goldens, and verifiers.
3. Implement sched analysis, paging, diagnosis bundles, and conservation tests.
4. Implement off-CPU interval analysis over the common scheduler IR.
5. Implement kernel-lock and futex wait candidates without conflating wait and hold time.
6. Pass privacy and real-host gates for fixed `cap_perfmon` trace collection.
7. Define the private protocol and implement the separate Rust Trace Helper.
8. Implement setup, switch-profile, status, acceptance, MCP, and Skill routing.
9. Pass upgrade, rollback, removal, DEB non-activation, and real-Debian release acceptance.

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

The common contract distinguishes exact events, thresholded events, sampled contention, and
cumulative profiles. It carries runtime/backend, target identity, opaque lock ID, waiter and only
evidence-supplied owner, timestamps/durations, stacks/source, sampling rate/threshold, loss,
truncation, fast-path visibility, coverage scope, allowed/forbidden conclusions, content digest,
converter manifest, and verifier. Sample counts are never presented as exact event counts, and
hold time is unavailable without reliable acquire/release pairing.

### 7.2 Native C/C++

- Formally support dynamically linked glibc/pthread mutex, rwlock, and condition-variable paths.
- Offer explicit launch-time instrumentation/interposition that runs as the target ordinary user.
- Import existing USDT/uprobe evidence while recording library version, symbol, and ABI capability.
- Mark static linkage, inlined/custom atomics, spin locks, and uncontended fast paths
  `partial/unsupported` when they are not observable.
- Any future live eBPF/uprobe privilege uses a separate policy and risk gate, not either existing
  Helper.

### 7.3 Java

- Prefer a user-installed JDK Flight Recorder and support JDK 17, 21, and 25 LTS.
- Use versioned JFR settings for monitor enter/wait, thread park, and available virtual-thread
  events; preserve thresholds and missing-event semantics.
- Detect async-profiler as an optional enhanced backend; expose JVMTI only as a controlled import
  interface.
- Do not bundle a JDK, async-profiler, or a general custom JVMTI agent in the core DEBs.

### 7.4 Python

- Formally support CPython 3.12/3.13 `threading.Lock`, `RLock`, `Condition`, and `Semaphore`.
- Model the GIL, CPython-internal locks, and application threading locks separately.
- Detect CPython 3.13 free-threaded builds and suppress traditional GIL conclusions.
- Treat DTrace/SystemTap/USDT as optional import backends with build/version capability reporting.
- Mark C-extension, custom atomic, and uninstrumented locks invisible or partial.

### 7.5 Go

- Adapt the official mutex and block profiles from an existing local pprof endpoint or an
  application that explicitly configures `SetMutexProfileFraction/SetBlockProfileRate`.
- Use the user's fixed `go tool pprof` as the adapter rather than directly parsing the binary
  profile format.
- Preserve sampling and cumulative semantics; never invent exact owners or per-event wait/hold
  intervals.
- Report channels, WaitGroups, Conds, and runtime-internal locks only to the extent represented by
  the official profile.

JDK, Go, async-profiler, and SystemTap remain optional external dependencies. PerfLens detects
versions and gives Chinese setup guidance but neither downloads nor bundles them into the two core
DEBs. Runtime instrumentation or attachment (`LD_PRELOAD`, JVM/JFR attachment, pprof access, or
probe deployment) always needs a separate explicit authorization and runs as the target ordinary
user whenever possible. The planned project opt-in is `perflens init --runtime-locks`.

Custom locks may use a versioned NDJSON import contract. This remains an adapter boundary, not a
new Agent or plugin framework.

## 8. Acceptance and release wording

Every new mode and adapter needs versioned Schemas, bilingual semantics, real fixtures, Goldens,
strict unknown-field rejection, malformed/bounded/loss/order/PID-reuse/tool-substitution tests,
hash and conservation verification, cross-UID/replay/path/command/spool-escape denial tests,
overhead budgets, exact-versus-statistical acceptance, complete deployment lifecycle tests, Python
and Rust quality gates, a real Debian systemd matrix, and real C/C++/Java/Python/Go workloads.

Until those gates pass, the shipped release continues to advertise only `stat/record` as stable.
`v0.3.0` may advertise `full_diagnostics` only if every included mode is complete. `v0.3.1` must
publish an exact runtime/backend/version/sampling/fast-path support matrix. Software fallback still
forbids IPC/cache/branch claims, and PerfLens remains outside heap profiling, request-level I/O APM,
GPU profiling, and distributed tracing. Release notes must be generated from the final
implementation and test evidence, not copied from this roadmap.
