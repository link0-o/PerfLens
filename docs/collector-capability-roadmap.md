# PerfLens v0.3.0 Collector capability expansion plan

[简体中文](collector-capability-roadmap.zh-CN.md) | English

Status: **next-release design and acceptance plan**

Last audited: 2026-08-15 against the post-`b8b1eec` `0.2.0` line

Candidate target: `v0.3.0`

This document separates shipped behavior from planned work. A planned item is not a product claim,
an onboarding default, or authorization for a Skill to collect it.

## Decision

PerfLens should expand scheduler, lock, and off-CPU analysis, but in this order:

1. Build deterministic offline analysis before expanding live privilege.
2. Keep `stat` and `record` as the only default, stable collection modes.
3. Consider one `cap_perfmon` trace mode at a time only after its analyzer, privacy checks, and
   real-host acceptance pass. Every advanced mode remains default-off.
4. Keep `paranoid3_helper` hard-limited to `stat/record` throughout `v0.3.0`.
5. If level-3 trace collection is eventually required, design a separate optional Trace Helper,
   unit, socket, protocol, policy, private raw spool, acknowledgement, and lifecycle.

The recommended `v0.3.0` position is therefore: retain the reliable CPU-tuning core, add
quality-gated offline waiting/scheduling analysis, and expose only security-approved experimental
`cap_perfmon` trace collection without widening the existing root Helper.

## Current `0.2.0` facts

Collector privilege modes (`cap_perfmon`, `paranoid3_helper`) are distinct from collection modes
(`stat`, `record`, `sched`, `lock`, `off_cpu`). A mode appearing in a Python type or public Schema
does not prove that every privilege mode safely supports it or that PerfLens can interpret it.

| Layer | `stat` / `record` | `sched` / `lock` / `off_cpu` |
|---|---|---|
| Public Python types and Schemas | represented | represented |
| MCP/CLI parameters | exposed | exposed, not a stability claim |
| Project onboarding defaults | enabled | disabled |
| Broker policy default | allowed | denied |
| `cap_perfmon` Python Collector | fixed argv and artifacts | fixed raw command entry points |
| `paranoid3_helper` Python policy | allowed | hard-denied |
| Rust Helper private protocol | `Record`, `Stat` only | enum absent and rejected |
| Deterministic Agent analysis | typed stat; record hotspots, paths, source, verification | no dedicated delay/wait Artifact |
| Maturity | **stable current** | **raw experimental entry point** |

The Python path can construct `perf sched record`, `perf lock record`, and a
`sched:sched_switch` stack recording. Those commands do not provide stable paired intervals,
latency distributions, owner/waiter attribution, loss accounting, or mode-specific conclusion
gates. Generic perf-script hotspot parsing is not a replacement for those analyzers.

The post-`b8b1eec` baseline already includes raw-stat replay, Collection/event/conversion binding,
unknown-frame preservation, Agent-visible content digests, independent analysis verification,
weight conservation, cross-language symbol fixtures, identity-checked MCP paging, project process
cleanup, readiness handshakes, and bounded hardware-to-software recovery. Those are completed
foundations, not future backlog.

## Present tuning boundary

| Question | Current result | Boundary |
|---|---|---|
| CPU saturation and algorithmic cost | good | requires correctness and matched A/B for an improvement claim |
| functions and call paths | good | depends on unwind, symbols, Build ID, and debug information |
| C/C++/Rust/Go CPU tuning | good | may be symbol-only without debug data |
| Python/JIT CPU tuning | moderate to good | depends on runtime maps/sidecars; replay may be time-bounded |
| IPC/cache/branch behavior | conditional | hardware PMU evidence is mandatory |
| before/after CPU validation | usable | workload and actual event source must match |
| scheduler delay/runnable starvation | incomplete | activity counters do not reconstruct delay intervals |
| lock contention/owner-waiter | incomplete | on-CPU lock frames do not prove wait duration |
| low CPU with long wall time | incomplete | paired off-CPU/wakeup/run intervals are missing |
| heap, device/network latency, GPU, distributed tracing | unsupported | outside `v0.3.0` |

The current product can perform useful, verifiable CPU-bound tuning. Software fallback in a VM
still supports on-CPU hotspots and paths, but not IPC or microarchitecture. Low switch, migration,
or fault counts do not prove the absence of I/O wait, lock contention, allocation churn, or memory
pressure.

## `v0.3.0` scope

Required:

- preserve the existing `stat/record` policy and artifact compatibility;
- introduce versioned, streaming, bounded scheduling/wait evidence models;
- complete imported `sched` and `off_cpu` deterministic analysis;
- give `lock` at least a stable conversion contract, public model, fixtures, and golden tests, and
  promote it only if aggregation semantics pass;
- return mode-specific EvidenceQuality, allowed/forbidden conclusions, loss, unpaired, and
  truncation counts;
- make Skill, CLI, MCP, status, and documentation use the same maturity terms.

Conditional: one default-off `cap_perfmon` advanced mode may ship experimentally only after every
privacy and host gate passes.

Excluded: widening the existing Rust Helper, system-wide collection, arbitrary tracepoints or perf
arguments, automatic sysctl/tracefs/capability changes, direct perf.data binary parsing, eBPF as a
shortcut, heap/APM/GPU/distributed tracing, and non-Linux platforms.

## Evidence models

Every advanced Artifact must retain schema version, ID, input digest/size, converter path/version/
digest/argv/locale, target identity and time range when available, clock/unit, CPUs and events,
lost/duplicate/out-of-order/unpaired/truncated counts, observed non-target metadata, EvidenceQuality,
allowed and forbidden conclusions, a content digest, and a conversion fingerprint. System `perf`
converts perf.data to fixed text; PerfLens does not decode the binary format.

### SchedulerAnalysisArtifact

Reconstruct per-thread on-CPU intervals and wakeup-to-switch-in run-queue delay. Report runtime,
switches, wakeups, migrations, mean/p50/p95/p99/max with sample counts, bounded worst intervals and
paths, preempted versus sleeping state, and trace-boundary/PID-reuse/unpaired-event loss. Never emit
a delay when the required pair is incomplete.

### OffCpuAnalysisArtifact

Represent switch-out, optional blocked/sleeping interval, wakeup, runnable delay, and switch-in.
Retain PID/TID, times, total off-CPU duration, separable blocked/runnable duration, switch-out path,
waker, task state, CPU movement, and completeness. Disk/network/lock/timer labels remain candidates
unless discriminating evidence confirms them.

### LockAnalysisArtifact

Where the selected perf/kernel output actually supports it, retain contention count, wait
distribution, stable opaque lock identity, owner/waiter and acquire/wait paths, source, and hold
duration only from reliable acquire/release pairs. Unavailable hold or owner evidence remains
unavailable; wait time must never be relabeled as hold time.

## Milestones

### M0: freeze the CPU core

Keep `stat/record` defaults and compatibility. Move completed integrity work out of backlog and fix
stale TTL, host-version, coverage, release-candidate, and five-mode support wording. Existing Python,
Rust, wheel, and DEB gates must not regress.

### M1: conversion contracts and Schemas

Fix the external conversion commands and fields, implement a common event IR and three versioned
Artifacts, reject unknown/non-finite/reversed/over-limit input, add real and synthetic fixtures,
goldens, schemas, bounded diagnostics, and deterministic replay.

### M2: imported sched analysis

Pair switch and wakeup events, expose per-thread runtime and runnable delay, handle migration,
preemption, trace boundaries, PID/TID reuse, loss and ordering, and add CLI/MCP analyze/detail/page/
verify/bundle tools. Incomplete pairing yields `partial`, never fabricated precision.

### M3: imported off-CPU analysis

Build on the scheduling IR, separate provable sleeping/blocked and runnable intervals, aggregate
switch-out paths, wakers and task states, preserve boundary/unpaired loss, and prevent cross-task
metadata from escaping through details or pages.

### M4: imported lock analysis

Fix supported perf output contracts, implement contention/wait/optional hold and owner/waiter
semantics, link related scheduling evidence by Artifact ID rather than merging unlike weights, and
require concurrency, stress, and race validation.

### M5: `cap_perfmon` experimental-collection decision

Real-host research must prove target-only publication, minimal tracefs/kernel/LSM capabilities,
no silent `CAP_SYS_ADMIN` expansion, owner/start-time binding, fixed events, bounded loss, and raw
artifact privacy. If any gate fails, no advanced live collection ships.

If accepted, a policy-v2 experimental section is explicit and default-off; installed policy v1
continues to support `stat/record` and is never auto-migrated. This example is a design target, not
current syntax:

```toml
[collector]
policy_version = 2
allowed_modes = ["record", "stat"]

[collector.experimental_trace]
enabled = false
allowed_modes = []
max_duration_seconds = 10
max_output_bytes = 67108864
allow_other_task_metadata = false
```

### M6: Skill routing and validation

Use short stat triage, record for on-CPU stacks, and an advanced analyzer only when its named
missing evidence is required and the approved policy permits it. The Skill cannot widen PID,
command, mode, event, duration, output, or privilege. A verified optimization still requires the
same workload/environment/actual event source, correctness tests, and matched A/B.

### M7: release, upgrade, and rollback

Preserve policies, spools, service mode, and old artifacts. Experimental policy is default-off and
atomically rollbackable. The Helper protocol stays `record/stat`. Packages do not activate a
service or modify host policy. A failed advanced-mode gate removes live collection from release
scope rather than blocking CPU-core fixes.

## Why the existing Helper stays narrow

Scheduler and lock traces naturally mention schedulers, wakers, owners, and tasks beyond the
target. Tracefs, LSM, kernel, and perf behavior varies; raw data may expose other task names, PIDs,
stacks, or kernel addresses; and each perf subcommand adds lifecycle and cleanup semantics. The
current Rust protocol and conformance matrix prove only `stat/record`. Adding allowlist strings
would bypass that independent design.

A future `v0.4.0+` Trace Helper would need a separate unit, user, private socket and raw spool,
protocol, capability review, derived/redacted publication, administrator acknowledgement, full
lifecycle, and cross-UID/non-target/PID-reuse/replay/expiry/limit/escape/failure tests.

## Performance, security, and release gates

New parsers remain streaming and bounded, document exact versus approximate quantiles, benchmark
high event/TID/lock cardinality, deep stacks, loss and disorder with throughput/p95/peak RSS, and
return only bounded MCP pages. Budgets are recorded from reproducible measurements, not guessed.

Each mode requires versioned Schemas and semantics, real-format and malformed/limit/loss fixtures,
goldens, digests and an independent verifier, authorization and cross-UID denials, PID-reuse/replay/
expiry/unknown-field/path/command/event denials, spool and failure cleanup, package non-activation,
real Debian systemd acceptance with kernel/perf/tracefs/LSM/capability records, Python quality gates,
and Rust/cross-language gates whenever the privileged boundary changes.

Only an accepted analyzer may enter collection-security review. Only an accepted security and host
matrix may become experimental support. Stable-by-default support requires at least one release
cycle of field evidence.

## Recommended order and release wording

```text
M0 CPU baseline → M1 contracts → M2 sched → M3 off_cpu → M4 lock
                → M5 one cap_perfmon experiment → M6 Skill/A-B → M7 release
```

Do not expand Helper privilege while inventing all three analyzers. Release notes must be generated
from completed implementation and tests, not copied from this plan. Until each gate passes, the
accurate user-facing statement remains: `stat/record` are stable; advanced modes are raw or planned;
`paranoid3_helper` supports only `stat/record`; software fallback cannot support IPC/cache/branch
claims; and PerfLens is not a heap profiler, I/O APM, GPU profiler, or distributed tracer.
