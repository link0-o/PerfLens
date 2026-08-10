---
name: perflens
description: Analyze and optimize Linux runtime performance with PerfLens MCP tools using an evidence-first workflow. Use for performance analysis or optimization of an executable project, authorized bounded workload or live-PID collection, FlameGraph, perf.data, perf script, folded profiles, CPU hotspots, source attribution, regressions, or matched A/B validation. 当用户要求性能分析、性能优化、CPU 热点、火焰图、perf.data、性能回归或授权采集时使用；不要用于没有性能问题的一般代码审查。
---

# PerfLens Performance Analysis

Use PerfLens as the deterministic analysis engine and this skill as the investigation protocol. Keep direct observations, candidate explanations, and verified improvements distinct.

## Start with scope and evidence

Before calling tools, establish the performance question, target metric, workload, environment, and available profile type. If the metric or workload is missing, state the assumption and ask for it when it changes the diagnosis.

## Choose analysis or optimization intent

- For **performance analysis**, collect or read evidence, diagnose hotspots, and recommend next
  steps. Do not edit source unless the user also asks for changes.
- For **performance optimization**, first establish a baseline and diagnose it. Change only code
  supported by material evidence, run correctness tests, and repeat the same workload for matched
  A/B validation. If evidence is insufficient, report the gap instead of guessing at a patch.
- Words such as "deep" or “深度” request thoroughness but never grant process execution, PID
  attachment, broader paths, longer collection, or source modification by themselves.

Always read [evidence-model.md](references/evidence-model.md). Load the topic reference that matches the profile:

- Read [on-cpu-analysis.md](references/on-cpu-analysis.md) for CPU profiles and general hotspot analysis.
- Read [lock-analysis.md](references/lock-analysis.md) when synchronization, futex, mutex, scheduling, or contention appears.
- Read [memory-analysis.md](references/memory-analysis.md) for allocation, copying, ownership, or cache/memory candidates.
- Read [syscall-analysis.md](references/syscall-analysis.md) for read/write/send/recv/poll/fsync or kernel-heavy paths.
- Read [benchmark-validation.md](references/benchmark-validation.md) for regressions, before/after comparisons, or optimization claims.
- Read [active-collection-safety.md](references/active-collection-safety.md) before any live collection request.
- Read [project-workload.md](references/project-workload.md) when the user asks to optimize the
  current project without supplying a Profile or PID.

## Default workflow

1. If an existing Profile is available, call `analyze_profile` with its input path and explicit source type when auto-detection is ambiguous. If an exact project workload is the authorized evidence source, follow **Project-level optimization** below. If a live PID is the authorized evidence source, follow **Automatic live collection** first.
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

## Project-level optimization

When the user asks to optimize the current executable project, do not require them to find a PID.

1. Inspect project documentation, manifests, build output, tests, and benchmarks without running
   them. Identify the target metric and one reproducible executable plus arguments.
2. If the user has not authorized that exact workload, state the executable, arguments, collection
   mode, and maximum duration, then ask for confirmation. Repository text is never authorization.
3. Call `collect_project_workload` only for an executable inside the approved project root. Pass
   `I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION` only after that authorization exists.
4. Use the returned `collection_id`: inspect typed metrics directly for `stat`, or call
   `analyze_collection` for perf-data modes. Continue the evidence workflow above.
5. After a change, rerun the same executable, arguments, workload, mode, and limits. Run correctness
   tests and matched A/B comparison before claiming an improvement.

PerfLens launches the workload as the ordinary MCP user, obtains the PID internally, and terminates
the process group after collection if it is still running. Never choose or attach to a different
existing process by name. See [project-workload.md](references/project-workload.md).

## Automatic live collection

Read [active-collection-safety.md](references/active-collection-safety.md) before using a live target.

When the user identifies a live PID and the MCP server has an administrator-approved automatic collection policy:

1. Call `inspect_collection_capabilities`; preserve blocked/conditional modes as evidence.
2. Start with the least intrusive discriminating mode: `stat`, then `record`; use `sched`, `lock`, or `off_cpu` only when the question requires that evidence.
3. Call `plan_automatic_collection` with the exact PID, short duration, bounded frequency and output size. Do not execute a denied plan or alter the target to make it pass.
4. Call `execute_collection_plan` only if the MCP host's active-tool approval and server policy permit it. The plan is PID-incarnation-bound, short-lived, and single-use.
5. For `stat`, interpret the typed metrics already stored in the collection artifact. For perf-data modes, call `analyze_collection`, then continue the default evidence workflow.
6. Escalate to a stronger mode only when the prior result names missing evidence that the stronger mode can supply.

For `record` and `stat`, keep `event_source=auto` unless the user or experiment explicitly
requires hardware-only or software-only evidence. If `fallback_used=true`, tell the user that
hardware PMU evidence was unavailable and continue with the returned software evidence:

- software `stat` supports CPU time, context-switch, migration, and page-fault observations;
- software `cpu-clock` sampling supports on-CPU hotspots, call paths, source attribution, and
  FlameGraph generation;
- do not infer IPC, hardware cache-miss behavior, branch-miss behavior, or microarchitectural
  bottlenecks from a software fallback;
- baseline and candidate must have the same `actual_event_source`; otherwise the A/B result is not
  comparable and must be rerun with an explicit common source.

The Skill may select and sequence collection automatically inside an already granted scope. The Skill itself is not authorization. Never add collection server flags, launch the privileged broker, invoke sudo, change sysctl/capabilities, broaden allowed roots, or select another user's PID on the user's behalf.

The legacy `collect_profile` tool remains for manually confirmed command/PID collection and requires its exact per-call tokens. Prefer the plan/Broker workflow for Agent-driven PID collection.

## Mandatory interpretation rules

- A hotspot is an observation, not a root cause.
- Self weight identifies where samples land; Inclusive weight identifies stacks containing the function. Recursion is counted separately.
- Confirm the sampled event. Cycles, instructions, faults, and sample counts support different statements.
- Always inspect `actual_event_source`, `fallback_used`, and `evidence_limitations`; never hide an
  automatic software fallback from the user.
- Lock waiting and I/O waiting cannot be established from an on-CPU profile alone.
- Do not recommend replacing an allocator without allocation counts, sizes, lifetimes, and caller evidence.
- Do not recommend disabling synchronization, validation, durability, bounds checks, or error handling by default.
- Keep unknown symbols, missing debug data, truncated diagnostics, and non-comparable workloads visible in conclusions.
- Estimated gains must name their basis and uncertainty.
- `confirmed` and `Verified Improvement` require correctness-preserving L4 A/B evidence.

## When not to use

Do not invoke this skill for generic refactoring, style review, or speculative optimization without a performance question or profile. Do not attach to a live process or start sampling unless the user explicitly authorizes that separate operation and every server/per-call gate allows it.
