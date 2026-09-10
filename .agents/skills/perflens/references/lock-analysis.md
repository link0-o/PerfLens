# PerfLens lock and scheduling analysis

An on-CPU profile shows CPU time around synchronization code but omits most blocked time. A futex or mutex frame can represent contention, normal coordination, retry spinning, or a caller pattern.

Required follow-up evidence may include `perf lock`, `perf sched`, off-CPU stacks, wait duration, owner/waiter relationships, critical-section duration, fairness, and workload concurrency.

When the installed Collector reports `full_diagnostics` and the exact plan is authorized, PerfLens
provides dedicated deterministic `sched`, `off_cpu`, and `lock` analysis through the separate
target-filtered Trace Helper. Use one mode for a demonstrated evidence gap, then run
`analyze_trace_evidence` and `verify_trace_analysis`. A futex wait is only a user-lock candidate;
missing acquire/release pairs cannot support hold time, and missing source owner data cannot
support owner claims. Preserve every `partial`, lost, unpaired, threshold, and sampling boundary.

If the project policy is CPU-only, the plan is denied, or host acceptance has not passed, report
the gap instead of invoking direct perf, broadening to system-wide capture, or treating an on-CPU
profile as blocked-time evidence.

## Runtime Lock evidence

Use Runtime Lock only when `runtime-locks.toml` enables the exact target scope, Adapter, semantics,
and budget. Capability discovery and project initialization are not authorization. The bounded
Preview must be shown in full and confirmed before collection or controlled import.

One Evidence Artifact has one meaning:

- `exact` records visible events exactly inside its bounded surface;
- `thresholded` omits events below its declared duration threshold;
- `sampled` reports sampled observations, never exact contention counts;
- `cumulative` is an aggregate runtime profile, not an event stream.

Never merge JFR profiles with different thresholds or Go mutex/block profiles into one Evidence.
Inspect the execution context (`os_thread`, Java platform/virtual thread, Go goroutine, or process
aggregate), visible lock kinds/fast paths, lost/truncated/omitted counts and weights, and whether
owner or acquire/release evidence is genuinely present. Lock IDs are opaque and stable only within
one Artifact.

Adapter boundaries:

- Native pthread: launch-time dynamic glibc pthread mutex/rwlock/condition instrumentation. Static
  or musl binaries, setuid/file-cap programs, spin/custom atomics, inline and invisible fast paths
  are partial or unsupported. Do not substitute live uprobe/eBPF.
- Java JFR: launch-time JDK 17/21/25 JFR with fixed `balanced` or `deep` settings. Threshold omission
  is not absence of waiting. Metadata, not a guessed version, decides virtual-thread event support;
  no live JVM attach.
- CPython: launch-time 3.12/3.13 public `threading.Lock`, `RLock`, `Condition`, and `Semaphore`
  wrappers. Do not infer C-extension/internal locks or the GIL. Free-threaded builds forbid
  traditional-GIL conclusions.
- Go: Go 1.24-1.27 private mutex/block profile files, or an explicitly enabled same-UID literal
  loopback pprof endpoint. PerfLens does not enable profiling rates or modify application source.
  Missing TID, owner, or lock identity stays missing.

Treat those versions as the target matrix, not proof that every entry passed the current release
gate. Follow the capability Artifact exactly: Go versions without a reviewed matching Golden are
`partial`, and a release-readiness blocker must not be described as stable merely because its
version is recognized. The current candidate evidence and blockers are recorded in
`docs/v0.4.0-release-readiness.md`.

Call the independent Runtime Lock verifier before any interpretation. A verified `partial` result
can support only its explicit allowed conclusions. Runtime Lock A/B must bind target, Adapter,
runtime/tool/payload, workload, semantics/threshold, resource environment, and correctness. A
Runtime Lock-only change is a candidate; the surrounding matched performance/Benchmark evidence
still decides Verified Improvement.

Do not recommend removing a lock, weakening atomics, changing memory ordering, or disabling correctness checks without an explicit concurrency proof and stress/race testing. Prefer experiments that reduce critical-section work or shard contention while preserving invariants.
