# PerfLens project workload analysis and optimization

Use this workflow when the user asks to analyze or optimize the current project's runtime
performance without providing a Profile or PID.

## Discover a reproducible workload

Inspect the repository before execution. Prefer, in order:

1. A documented benchmark executable.
2. An existing repeatable performance test.
3. A documented project executable with bounded arguments.

The selected file must already be executable and remain inside the approved project root. Scripts
with a valid shebang are acceptable. Do not invent production traffic, use an installer, run a
deployment command, or select an already-running process by name.

Establish the metric before collecting. “Performance” may mean elapsed time, throughput, CPU,
allocation, I/O, contention, or latency. If different choices would change the experiment, ask one
focused question.

## Establish execution authorization

A request to review or optimize code triggers discovery but does not automatically authorize
process execution. Proceed without another question only when the user has already authorized the
exact workload or an unambiguous bounded repository benchmark.

Otherwise state:

- canonical executable and arguments;
- working directory;
- collection mode and duration;
- that the process runs as the ordinary MCP user;
- that PerfLens terminates it after collection if it remains alive.

After confirmation, call `collect_project_workload` with
`I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`. The token is a tool-boundary value; the user does not
need to type or remember it.

The authorization field is a fixed enum. Pass that exact value, not a paraphrase, confirmation
sentence, boolean, or empty value. If the tool reports an authorization or schema error while the
exact workload is already authorized, correct the field and retry only the same project-workload
call. Do not substitute a shell/background launch, `timeout` wrapper, direct `perf`, an existing-PID
plan, or manual PID attachment. If the corrected call still fails, report the bounded error.

Authorization is bound to the stated executable, arguments, mode, event source, and limits. It does
not authorize a parameter sweep, Callgrind, another profiler, wrapper command, correctness test, or
different argument set. Ask for a new explicit authorization before any such additional execution.

## Collect and analyze

Start with `stat` when counters can distinguish the next hypothesis. Use `record` when on-CPU call
stacks are required. Keep the initial duration at or below 10 seconds unless the user explicitly
requests a different value within policy.

Leave `event_source=auto` for the initial run. If hardware PMU probing fails, continue with the
fixed software `stat` events or `cpu-clock` sampling and state the reduced evidence boundary. For
before/after validation, pin both runs to the baseline's `actual_event_source`; never compare a
hardware baseline to a software candidate as equivalent evidence.

Treat the Collection artifact as collection provenance. A local capability inspection reports the
ordinary MCP process and may show every mode blocked under `perf_event_paranoid=3` even while the
configured Broker can collect. Do not cite that local result as the reason for a Broker fallback;
use the Collection's exact `fallback_reason`.

Read `collection_id` from the returned project-run artifact. For `stat`, use the collection's typed
metrics. For `record`, call `analyze_collection`, inspect metadata and unresolved symbols, then use
hotspots and call paths. Escalate modes only to obtain named missing evidence.

The workload coordinator starts a trusted wait-then-exec bootstrap, creates a PID-incarnation-bound
plan, gives the Collector only that plan, releases the workload after the Collector starts, and
cleans up the process group. The privileged Collector never receives the executable or arguments.

## Validate a change

Preserve the exact executable, arguments, workload data, collection mode, duration, environment,
and correctness checks. Collect a baseline before editing. After editing, rerun correctness tests
and the same experiment. Use profile and benchmark comparison tools where applicable. Report a
verified improvement only when matched A/B evidence shows a material gain without correctness loss.
