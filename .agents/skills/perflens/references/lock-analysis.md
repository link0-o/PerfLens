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

Do not recommend removing a lock, weakening atomics, changing memory ordering, or disabling correctness checks without an explicit concurrency proof and stress/race testing. Prefer experiments that reduce critical-section work or shard contention while preserving invariants.
