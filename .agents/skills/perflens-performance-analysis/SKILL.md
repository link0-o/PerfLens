---
name: perflens-performance-analysis
description: Diagnose Linux performance profiles and explicitly authorized live Linux PIDs with PerfLens MCP tools using an evidence-first workflow. Use for automatic bounded perf collection, FlameGraph folded stacks, perf script text, perf.data, CPU hotspot investigation, source attribution, regression analysis, or optimization validation. Do not use for general code review without a performance question or for live targets outside an approved collection policy.
---

# PerfLens Performance Analysis

Use PerfLens as the deterministic analysis engine and this skill as the investigation protocol. Keep direct observations, candidate explanations, and verified improvements distinct.

## Start with scope and evidence

Before calling tools, establish the performance question, target metric, workload, environment, and available profile type. If the metric or workload is missing, state the assumption and ask for it when it changes the diagnosis.

Always read [evidence-model.md](references/evidence-model.md). Load the topic reference that matches the profile:

- Read [on-cpu-analysis.md](references/on-cpu-analysis.md) for CPU profiles and general hotspot analysis.
- Read [lock-analysis.md](references/lock-analysis.md) when synchronization, futex, mutex, scheduling, or contention appears.
- Read [memory-analysis.md](references/memory-analysis.md) for allocation, copying, ownership, or cache/memory candidates.
- Read [syscall-analysis.md](references/syscall-analysis.md) for read/write/send/recv/poll/fsync or kernel-heavy paths.
- Read [benchmark-validation.md](references/benchmark-validation.md) for regressions, before/after comparisons, or optimization claims.
- Read [active-collection-safety.md](references/active-collection-safety.md) before any live collection request.

## Default workflow

1. If an existing Profile is available, call `analyze_profile` with its input path and explicit source type when auto-detection is ambiguous. If a live PID is the authorized evidence source, follow **Automatic live collection** below first.
2. Inspect the returned sample count, event, weight semantics, call-graph availability, source availability, warnings, and unresolved frames before interpreting hotspots.
3. Call `list_hotspots` for a bounded top page. Compare Self and Inclusive values; do not equate either with elapsed wall time.
4. Call `get_hotspot_details` and `get_call_paths` for each material hotspot. Do not infer business semantics from a function name alone.
5. When a verified module offset and matching binary/debug file exist, call `resolve_source`. Then call `get_source_context` within an allowed workspace. Never infer an ASLR/PIE base from runtime IP alone.
6. Call `classify_hotspots` for investigation categories. Treat every rule result as `candidate`, never as a confirmed cause.
7. Call `build_diagnosis_bundle` when a durable evidence artifact is useful. Use `read_artifact_page` for bounded retrieval instead of requesting an entire large result.
8. For a regression or change, analyze both profiles and call `compare_profiles`. Normalize pyperf, Google Benchmark, hyperfine, or PerfLens JSON with `analyze_benchmark`, then call `compare_benchmarks`. Treat commit as an expected A/B variable, while other environment differences reduce comparability.
9. Form multiple hypotheses. For each, list supporting evidence, counter-evidence, missing evidence, risk, and the smallest discriminating experiment.
10. For changes, run correctness tests and equivalent-workload before/after measurements. Only matched A/B evidence may be described as a verified improvement.
11. Produce the final report using [diagnosis-report-template.md](assets/diagnosis-report-template.md).

## Automatic live collection

Read [active-collection-safety.md](references/active-collection-safety.md) before using a live target.

When the user identifies a live PID and the MCP server has an administrator-approved automatic collection policy:

1. Call `inspect_collection_capabilities`; preserve blocked/conditional modes as evidence.
2. Start with the least intrusive discriminating mode: `stat`, then `record`; use `sched`, `lock`, or `off_cpu` only when the question requires that evidence.
3. Call `plan_automatic_collection` with the exact PID, short duration, bounded frequency and output size. Do not execute a denied plan or alter the target to make it pass.
4. Call `execute_collection_plan` only if the MCP host's active-tool approval and server policy permit it. The plan is PID-incarnation-bound, short-lived, and single-use.
5. For `stat`, interpret the typed metrics already stored in the collection artifact. For perf-data modes, call `analyze_collection`, then continue the default evidence workflow.
6. Escalate to a stronger mode only when the prior result names missing evidence that the stronger mode can supply.

The Skill may select and sequence collection automatically inside an already granted scope. The Skill itself is not authorization. Never add collection server flags, launch the privileged broker, invoke sudo, change sysctl/capabilities, broaden allowed roots, or select another user's PID on the user's behalf.

The legacy `collect_profile` tool remains for manually confirmed command/PID collection and requires its exact per-call tokens. Prefer the plan/Broker workflow for Agent-driven PID collection.

## Mandatory interpretation rules

- A hotspot is an observation, not a root cause.
- Self weight identifies where samples land; Inclusive weight identifies stacks containing the function. Recursion is counted separately.
- Confirm the sampled event. Cycles, instructions, faults, and sample counts support different statements.
- Lock waiting and I/O waiting cannot be established from an on-CPU profile alone.
- Do not recommend replacing an allocator without allocation counts, sizes, lifetimes, and caller evidence.
- Do not recommend disabling synchronization, validation, durability, bounds checks, or error handling by default.
- Keep unknown symbols, missing debug data, truncated diagnostics, and non-comparable workloads visible in conclusions.
- Estimated gains must name their basis and uncertainty.
- `confirmed` and `Verified Improvement` require correctness-preserving L4 A/B evidence.

## When not to use

Do not invoke this skill for generic refactoring, style review, or speculative optimization without a performance question or profile. Do not attach to a live process or start sampling unless the user explicitly authorizes that separate operation and every server/per-call gate allows it.
