# PerfLens evidence model

Use the lowest level fully supported by the available data.

- L0: experience or guess only. Exclude from final conclusions.
- L1: one hotspot without useful call paths or source. Low-confidence candidate only.
- L2: hotspot plus dominant call paths. A candidate mechanism may be described, with missing source and auxiliary evidence stated.
- L3: profile, call path, source, and relevant auxiliary metric or benchmark. A likely candidate is possible, not a verified improvement.
- L4: equivalent-workload before/after measurement, corresponding hotspot change, correctness pass, stable error rate, and no unacceptable resource transfer. Only this level supports `Verified Improvement`.

Allowed conclusion states are `observed`, `candidate`, `likely`, `confirmed`, `rejected`, and `unknown`. Generic classification rules always produce `candidate`. A direct tool measurement can be `observed`. Use `confirmed` only when the claim itself has direct, discriminating evidence; use `Verified Improvement` only for L4.

Event-source provenance is part of the evidence level. Software-event fallback can support CPU-time,
scheduler-activity, page-fault, and sampled on-CPU hotspot observations. It cannot support IPC,
hardware cache-miss, branch-miss, or other microarchitectural conclusions. A comparison whose two
sides have different `actual_event_source` values is not matched A/B evidence.

For every hypothesis record:

1. Supporting evidence with artifact and hotspot IDs.
2. Counter-evidence or alternative explanations.
3. Missing evidence.
4. Confidence and evidence level.
5. A falsifiable next experiment.
