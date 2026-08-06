# PerfLens benchmark and optimization validation

Before comparing, verify identical workload, input, build mode, CPU affinity, warmup, duration, concurrency, environment, event, sampling settings, and correctness criteria.

Report sample count, center, spread, outlier policy, and run ordering. Separate statistically noisy changes from material effects. Compare both the target metric and profile distribution so an apparent gain is not merely shifted cost.

An optimization is verified only when the target metric improves under equivalent conditions, the predicted profile evidence changes, correctness tests pass, error rate does not regress, and CPU/memory/I/O cost is not transferred unacceptably.
