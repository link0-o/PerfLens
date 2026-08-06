# PerfLens lock and scheduling analysis

An on-CPU profile shows CPU time around synchronization code but omits most blocked time. A futex or mutex frame can represent contention, normal coordination, retry spinning, or a caller pattern.

Required follow-up evidence may include `perf lock`, `perf sched`, off-CPU stacks, wait duration, owner/waiter relationships, critical-section duration, fairness, and workload concurrency.

Do not recommend removing a lock, weakening atomics, changing memory ordering, or disabling correctness checks without an explicit concurrency proof and stress/race testing. Prefer experiments that reduce critical-section work or shard contention while preserving invariants.
