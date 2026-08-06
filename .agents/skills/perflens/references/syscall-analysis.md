# PerfLens syscall and I/O candidates

On-CPU syscall samples measure CPU work on sampled paths, not blocked latency. `read`, `write`, `send`, `recv`, `poll`, or `fsync` cannot identify disk versus network behavior by name alone.

Collect syscall frequency, sizes, return values, errno distribution, off-CPU duration, queue depth, iostat, storage latency, network counters, and request-level correlation as appropriate.

Do not recommend disabling durability, batching unboundedly, ignoring partial I/O, or removing error handling. Any batching proposal must include latency, memory, backpressure, and failure-semantics risks.
