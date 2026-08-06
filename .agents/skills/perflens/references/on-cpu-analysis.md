# PerfLens on-CPU profile analysis

Confirm the event and weight source before interpreting percentages. `cycles` approximates sampled CPU-cycle distribution; `instructions` measures a different property; folded sample count has no elapsed-time semantics.

Read Self and Inclusive together:

- High Self: samples land inside the function. Inspect instructions, source, and compiler output.
- Low Self but high Inclusive: the function is a path or caller container. Drill into callees before proposing changes.
- High weight in one thread or path: confirm workload partitioning and repeatability.
- Kernel weight: inspect the user-to-kernel path and correlate system metrics; do not label the kernel defective.

Check unresolved-symbol weight, missing stacks, event mixing, profile duration, and workload representativeness. Prefer several hypotheses over a single name-based story.
