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

Before assigning an evidence level, require a successful `verify_analysis` result and inspect the
Analysis `EvidenceQuality`. Its content digest binds every Agent-visible field; its analysis
fingerprint binds the raw-input hash, conversion manifest, limits, and optional source Collection.
Neither digest is a signature or a proof that perf/hardware is correct. They detect mismatched or
altered evidence inside PerfLens, while fixtures, conservation checks, and explicit limitations
bound parser/tool uncertainty.

`quality_status=verified` means deterministic structural checks passed. It does not raise an
observation to `confirmed`. With `quality_status=partial`, use only `allowed_conclusions`, include
the limitations, and never make a claim named by `forbidden_conclusions`. Normalization merges and
bounded-output omissions lower identity/completeness claims even when the underlying records parse.
When `symbol_variants_truncated=true`, treat `symbol_variant_count` as an observed lower bound and
do not report it as an exact number of machine-code identities.

In a typed `perf stat` metric, `running_percent` is counter scheduling coverage, not workload CPU
utilization. `task-clock` is accumulated CPU time. Sparse context-switch, migration, or page-fault
counts are positive observations only and cannot establish that I/O wait, lock contention,
allocation churn, or memory pressure is absent. Inspect metric status and Collection warnings;
`not_supported` and `not_counted` are missing evidence, never numeric zero, and a truncated-warning
marker forbids claiming that every stat row was accepted.

Treat a typed stat Collection as usable only after its retained raw CSV hash/size and exact metric
replay pass verification. For record, require the selected Collection event to match the parsed
transcript event; fixed hybrid-PMU spellings of cycles are equivalent, but unknown event aliases are
not. An `unknown` callchain Frame is preserved to prevent false Self attribution and is evidence
loss, not an instruction to infer the missing symbol.

For sampled profiles, read `event` and `weight_unit` together. CPU/task-clock periods are
nanoseconds, cycles/instructions use their native counts, and an unfamiliar event deliberately
retains `event_count`; never assign it a guessed time, instruction, or cycle unit.

For every hypothesis record:

1. Supporting evidence with artifact and hotspot IDs.
2. Counter-evidence or alternative explanations.
3. Missing evidence.
4. Confidence and evidence level.
5. A falsifiable next experiment.
