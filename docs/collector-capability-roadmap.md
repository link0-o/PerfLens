# Collector capability assessment, repair plan, and expansion roadmap

[简体中文](collector-capability-roadmap.zh-CN.md) | English

Status: this document describes the current PerfLens 0.2.0 line. It is a design and acceptance
roadmap; items marked as planned or candidates are not claims of completed implementation.

## Terminology and conclusion

PerfLens has two different kinds of modes:

- Collector privilege modes are `cap_perfmon` and `paranoid3_helper`.
- Collection modes are `stat`, `record`, `sched`, `lock`, and `off_cpu`.

The supported product baseline is owner-PID `stat` and `record`. Together they provide a useful
CPU-tuning loop: an ordinary user starts or authorizes a bounded workload, the Collector acquires
counters or stacks, deterministic tools analyze the artifact, and matched before/after evidence
validates a change.

This baseline can identify CPU saturation, on-CPU hotspots and call paths, scheduling-activity
candidates, and page-fault activity. It is not a complete Linux observability suite: precise
scheduler delay, lock wait, off-CPU duration, heap behavior, storage/network latency, GPU, and
distributed tracing remain outside the mature boundary.

## Privilege-mode assessment

| Property | `cap_perfmon` | `paranoid3_helper` |
| --- | --- | --- |
| Selection | default and preferred | opt-in when Debian `perf_event_paranoid=3` must remain |
| Public Broker | dedicated non-root user with bounded `CAP_PERFMON` | dedicated non-root user with no capabilities |
| Higher-privilege process | none | private Rust Helper running as root with a systemd ceiling of `CAP_PERFMON`, `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE` |
| Collection-mode policy | model supports five modes; defaults to `record/stat` | immutable owner-only `record/stat` |
| Security boundary | smaller | larger, narrowed by a private typed protocol and independent validation |
| Recommended host | a host whose kernel policy accepts `CAP_PERFMON` | a controlled single-user development host that cannot lower paranoid level 3 |

Neither mode grants privilege to the Agent, Skill, MCP server, or project workload. Plans are
versioned, short-lived, single-use, and bound to PID owner and start time. The Collector accepts no
shell, arbitrary command, arbitrary environment, arbitrary output path, or system-wide target. A
project executable always starts as the ordinary MCP user.

The Helper ceiling is 30 seconds, 99 Hz, 256 MiB per artifact, a 120-second plan lifetime, a
5-GiB/500-artifact spool, and 2 GiB of reserved filesystem space. Python and Rust enforce the
boundary independently.

`cap_perfmon` is the best long-term default because it is simpler and less privileged. The Helper
mode has completed real software-stat and `cpu-clock`-record acceptance on the current Debian 13
level-3 host, but hardware-PMU availability still depends on the physical/virtual platform rather
than root alone.

## Collection-mode maturity

| Mode | Current evidence | Maturity | Main gap |
| --- | --- | --- | --- |
| `stat` | hardware counters, or fixed software task-clock/switch/migration/fault counters | core usable | derived metrics and automated matched A/B |
| `record` | hardware cycles, or software `cpu-clock` call stacks | core usable | unwind diagnostics, bulk source attribution, static FlameGraph export |
| `sched` | raw `perf sched record` evidence | experimental | deterministic interval and run-queue-delay analysis |
| `lock` | raw `perf lock record` evidence | experimental | wait/hold aggregation and source attribution |
| `off_cpu` | `sched:sched_switch` stacks | experimental | paired duration reconstruction and loss handling |

The Python `cap_perfmon` path has fixed command construction for the last three modes, but that is
not equivalent to a mature analysis product. The Rust Helper intentionally rejects them.

Collection is not fixed at ten seconds. Policy defaults to a 30-second maximum, while the Skill
keeps initial diagnosis at or below ten seconds. A preferred sequence is a one- or two-second stat
triage followed by a five- to ten-second record only when stacks are needed.

## PMU fallback and tuning value

With `event_source=auto` and an allowing policy, PerfLens performs a fixed short hardware probe on
the same PID and within the original time bound. Useful hardware counts retain the hardware path;
an unavailable or unusable PMU changes stat to fixed software events and record to `cpu-clock`.
The Collection records the requested and actual sources, fallback reason, and limitations.

Software fallback supports CPU-time, scheduler-activity, page-fault, and on-CPU hotspot
observations. It cannot support IPC, hardware cache-miss, branch-miss, or other microarchitectural
claims. Baseline and candidate runs with different `actual_event_source` values are not matched
A/B evidence.

Current effectiveness is good for CPU-bound algorithm and call-path tuning, partial for scheduler
and lock investigations, and insufficient for heap, I/O-latency, or distributed-performance
questions. Hardware-PMU hosts add valuable microarchitectural evidence; PMU-limited virtual
machines remain useful for algorithmic hotspots but not cache/pipeline tuning.

## Confirmed repair backlog

Unless explicitly stated otherwise, these are planned changes.

### P0: correctness and release trust

1. Pin profile input identity. Hashing and parsing currently reopen the same path; replacement
   between the reads could make the recorded digest disagree with the analyzed bytes. Use one
   descriptor-pinned snapshot/byte source and verify device, inode, size, and timestamp identity.
2. Synchronize stale compatibility, limitation, release-readiness, and automatic-collection text.
   The code ceiling for plan TTL is 120 seconds, and FlameGraph wording must not imply a built-in
   SVG renderer until one exists.
3. Persist an informational acceptance receipt in ordinary-user XDG state. Bind it to PerfLens
   version, policy digest/mode, perf version, kernel boot ID, and service identity; invalidate it on
   change and never use it as authorization.
4. Increase coverage headroom in the MCP server, project launcher, storage, Skill distribution,
   CLI, and deployment denial paths. Target a routine 87-90% rather than weakening the 85% gate.

### P1: analysis and MCP performance candidates

- Benchmark high-cardinality data before replacing full hotspot/call-path sorts with deterministic
  bounded Top-K and cached frame sort keys.
- Merge profile hashing and parsing through the pinned input source.
- Serialize MCP artifacts once while preserving no-overwrite, fsync, and directory-sync semantics.
- Add a bounded, file-identity-bound LRU/index for repeated analysis pages and details.
- Expose Build-ID/DSO-grouped bulk source resolution and a bounded long-lived provider pool.
- Add high-cardinality, deep-stack, perf-script, MCP cold/warm, and symbol cold/warm benchmarks
  with throughput, p95, and peak RSS.

### P1: evidence and UX

- Add typed `get_collection_details` and bounded `list_artifacts` tools.
- `source_locations` are now populated with a deterministic per-hotspot bound. Add similarly
  bounded `top_callers` and `top_callees` from retained evidence.
- Bind project runs to executable SHA-256/Build ID, Git revision, and controlled environment
  identity for reliable A/B.
- Add an explicit diff, backup, and reinstall flow for a locally modified Skill.
- Separate direct-process capability, Broker health, and last real acceptance in doctor/status,
  with a bounded Collector diagnostic bundle.

## Expansion phases

### C0: stabilize the CPU loop

Keep both privilege modes and default `record/stat`. Add package-level real acceptance for
`cap_perfmon` on paranoid <= 2, Helper on paranoid 3, hardware-PMU and software-fallback lanes,
project record-to-analysis/source attribution, and install/upgrade/switch/rollback/uninstall. Finish
the P0 input, status, documentation, and coverage work first.

### C1: improve CPU tuning without more privilege

Compute IPC/cache/branch derivatives only from measured hardware counters; report unwind and
unresolved-symbol quality; add bulk source attribution and static SVG/HTML FlameGraph export; use
bounded adaptive stat-then-record selection; and add an unprivileged benchmark recipe with warmup,
repetition, correctness checks, workload identity, and same-source A/B. Benchmark execution must
never move into the Helper.

### C2: build offline waiting/contention analysis first

Implement streaming bounded schemas, parsers, golden fixtures, and reports for sched intervals and
run-queue delay, lock wait/hold evidence, and paired off-CPU intervals. Analyze imported evidence
before adding any new privileged collection surface.

### C3: make privileged expansion separately optional

Do not merely add `sched/lock/off_cpu` to the Helper allowlist. Each mode requires a new typed
protocol enum, fixed argv and event allowlist, tracefs/LSM/capability review, independent Rust
validation, denial-path and real-host tests, and explicit administrator selection. Prefer a
mode-specific Helper/unit when capabilities differ instead of widening the existing service. Keep
default Helper policy at `stat/record`.

### C4: product and platform work

Add per-UID systemd instances/sockets/spools, container namespace and DSO mapping, then Ubuntu,
aarch64, and later RPM support. Add external adapters for allocator, heap, block-I/O, network, or
JIT evidence only with explicit evidence contracts. Fuzz the private protocol and add real systemd
VM and hardware-PMU CI lanes.

## Acceptance gates and order

Every result must retain artifact IDs, event-source provenance, and missing evidence. Software
fallback must never produce microarchitectural claims, and mismatched sources must never be called
matched A/B. New protocol fields require shared schema/golden conformance and strict unknown-field
rejection; new modes require peer, cross-UID, PID-reuse, replay, expiry, limit, spool-escape, worker
failure, and real-host tests. Analysis remains streaming and bounded and never directly parses the
`perf.data` binary.

The recommended order is **P0/C0, then C1, C2, C3, and C4**. Completing a reliable, explainable,
reproducible stat/record-to-A/B loop is more valuable than adding broader root capability first.
