# PerfLens on-CPU profile analysis

Confirm the event and weight source before interpreting percentages. `cycles` approximates sampled CPU-cycle distribution; `instructions` measures a different property; folded sample count has no elapsed-time semantics.

Read Self and Inclusive together:

- High Self: samples land inside the function. Inspect instructions, source, and compiler output.
- Low Self but high Inclusive: the function is a path or caller container. Drill into callees before proposing changes.
- High weight in one thread or path: confirm workload partitioning and repeatability.
- Kernel weight: inspect the user-to-kernel path and correlate system metrics; do not label the kernel defective.

Check unresolved-symbol weight, missing stacks, event mixing, profile duration, and workload representativeness. Prefer several hypotheses over a single name-based story.

Read `EvidenceQuality` before ranking functions. Distinguish unresolved Self weight from missing
call graphs and missing source lines; they constrain different claims. Check output omissions and
normalization merges before calling a displayed symbol/path complete or unique. A structurally
verified profile is still a sampled distribution, not a causal proof.

PerfLens exposes call paths in root/caller-to-leaf/callee order. For `perf stat`, never interpret
`running_percent` as CPU utilization: it is the percentage of enabled measurement time for which
perf could schedule that event. Use `task-clock` plus a trustworthy wall interval for a bounded CPU
utilization estimate, and remember that multi-threaded task-clock can exceed one CPU.
