# Active Collection Safety

Use active collection only when existing artifacts cannot answer the stated performance question and the user explicitly authorizes the exact target.

## Authorization gates

- Command collection requires server startup flags `--allow-writes`, `--allow-process-execution`, and `--allow-active-collection`.
- Each call must pass `I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING` as its authorization value.
- PID attachment additionally requires server flag `--allow-pid-attach` and per-call value `I_EXPLICITLY_AUTHORIZE_PID_ATTACH`.
- The CLI has matching `--authorize-target` and `--authorize-pid-attach` confirmation switches in addition to the exact tokens.

Do not infer authorization from a general request to diagnose performance. Never choose a PID by process-name matching. Never invoke sudo or modify `perf_event_paranoid`, tracefs, sysctl, capabilities, ownership, or host security policy.

## Bounds and target integrity

State the exact target executable or PID, collection mode, duration, frequency, events, timeout, and maximum output size before collection. Use an absolute canonical executable path. Preserve target arguments exactly and do not expose them in reports; PerfLens records only their count and a SHA-256 digest.

Use `record` for on-CPU stacks, `stat` for typed counters, `sched` for scheduler data, `lock` for lock events, and `off_cpu` for sched-switch stack evidence. off-CPU interpretation still requires workload-aware post-processing and must not be described as blocked-time proof by itself.

If kernel policy rejects collection, report the error and continue with existing evidence or user-generated exports. Do not escalate privileges automatically.
