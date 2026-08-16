# PerfLens lock and scheduling analysis

An on-CPU profile shows CPU time around synchronization code but omits most blocked time. A futex or mutex frame can represent contention, normal coordination, retry spinning, or a caller pattern.

Required follow-up evidence may include `perf lock`, `perf sched`, off-CPU stacks, wait duration, owner/waiter relationships, critical-section duration, fairness, and workload concurrency.

In the current PerfLens release, integrated `sched`, `lock`, and `off_cpu` collection is a disabled
raw `cap_perfmon` experiment without a mode-specific deterministic analyzer, and the
`paranoid3_helper` rejects those modes. Treat the list above as evidence requirements, not as an
instruction to enable an unavailable mode. Report the gap or analyze an explicitly supplied export
within its preserved fields.

Do not recommend removing a lock, weakening atomics, changing memory ordering, or disabling correctness checks without an explicit concurrency proof and stress/race testing. Prefer experiments that reduce critical-section work or shard contention while preserving invariants.
