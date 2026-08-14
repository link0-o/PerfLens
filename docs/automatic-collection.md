# Automatic collection and the Collector Broker

English | [简体中文](automatic-collection.zh-CN.md)

PerfLens closes the loop from an approved live PID to evidence, analysis, and a report without making the Agent or MCP server privileged.

```text
user grant → Skill → optional ordinary-user launch → PID-bound MCP plan → restricted Collector → analysis
```

The optional `perflens-collector` is a Unix-socket broker. It authenticates peers with `SO_PEERCRED`, accepts only typed PID plans, revalidates PID owner/start time, enforces an independent root-owned policy, and writes only to a fixed spool. Plans have a bounded lifetime, and the running Broker rejects replay of the same plan. It also rejects a `perf` executable that is both non-root-owned and writable by the service account. It never accepts a shell command, arbitrary executable, environment, output path, or system-wide target.

Authentication is bidirectional for health and collection requests. The client
pins safe socket metadata, matches the kernel peer UID to the socket owner,
requires an exact request-ID response, and confirms that returned collection
PID/mode match the authorized plan. Malformed, oversized, timed-out, stale, or
mismatched responses fail closed.

The client also streams the returned spool file through size and SHA-256
verification before accepting collection success. It rejects symlinks,
replacements, extra hard links, unexpected names/owners/groups, and any mode
other than `0640` or `0440`.

Before starting perf, the Broker reserves against independent spool byte and
artifact-count quotas and a filesystem free-space floor. Exhaustion denies the
new collection without deleting or overwriting existing evidence.

For `record` and `stat`, the default `event_source=auto` performs a fixed
hardware `cycles`/`instructions` probe of at most 250ms against the same bound
PID. Probe time counts toward the requested duration. Plans shorter than 300ms
go directly to software events with reason `hardware_probe_skipped_for_short_collection`, so the
probe cannot consume most of the window. If the hardware PMU cannot produce useful counts,
`stat` falls back to fixed software events and
`record` falls back to `cpu-clock`. The Collection reports the actual source,
fallback reason, and limitations. Software evidence can support CPU-time,
scheduler-activity, page-fault, and on-CPU hotspot analysis, but not IPC,
hardware cache-miss, branch-miss, or microarchitectural conclusions. Matched
A/B validation requires the same actual source on both sides.

If the probe succeeds but the formal hardware collection subsequently fails,
`auto` may make one software retry only when at least 50ms remains in the
original collection window. The retry never extends the user-authorized
duration and still uses the fixed software event allowlist and output path.
Authorization, PID-identity, timeout, output-limit, spool-safety, and quota
errors are not fallback signals and remain visible failures.

Evidence retention is a separate human-administrator archive-then-prune flow.
Archives have a dedicated read-only verifier; the MCP, Skill, and Collector
protocol expose no automatic deletion operation.

Run `perflens doctor` for a Chinese-first, read-only capability summary. Use
`perflens doctor --json` for the complete versioned stdout artifact or
`--output <new-file.json>` to preserve it safely. Stage the packaged service templates with:

The example below uses the native DEB path; wheel deployments should replace it
with the administrator-controlled `/opt/perflens/bin/perflens-collector`.

```bash
perflens stage-collector-assets \
  --output-directory ./collector-assets \
  --allowed-uid 1000 \
  --collector-command /usr/bin/perflens-collector \
  --perf-path /usr/bin/perf
```

Review `collector.toml`, `perflens-collector.service`, and `perflens.sysusers`.
Configure exactly one `allowed_uids` entry. Multiple callers sharing the
`perflens` group could read each other's group-readable profiles, so policy and
deployment reject shared multi-user instances.
Validate the policy with `perflens-admin deploy --config <toml> --dry-run`,
then run that trusted system-package entry point once with `sudo` and without
`--dry-run`. Wheel deployments use `/opt/perflens/bin/perflens-admin`. The fixed deployer uses packaged templates and never
executes project-provided commands or changes sysctl.

On Debian, `perf_event_paranoid=3` blocks perf before the normal CAP_PERFMON
path. An administrator may either review and lower that policy for the
dedicated Collector or explicitly deploy the packaged `paranoid3_helper` Rust
boundary and acknowledge its bounded root, `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE`
risk. `CAP_SYS_PTRACE` is needed only inside that opt-in Helper so `perf record`
can synthesize the authorized target's mappings; it is not granted to the Broker.
Do not run the MCP
server, Agent, or Python Broker as root.

For automatic MCP collection, enable all explicit server gates, configure `--collector-socket`, include the collector spool as an `--allowed-root`, and bound modes/duration/frequency. See the [Chinese guide](automatic-collection.zh-CN.md) for the complete configuration and safety model.

The automatic workflow is:

1. `inspect_collection_capabilities`;
2. `plan_automatic_collection`;
3. verify the plan is allowed;
4. `execute_collection_plan` once before it expires;
5. read typed stat metrics or call `analyze_collection` for perf-data output;
6. continue the normal evidence workflow.

After execution, always inspect `actual_event_source`, `fallback_used`, and
`evidence_limitations`. A software fallback is a reduced evidence source, not
an automatic reason to abandon performance analysis.

The Skill may automate these steps inside an already granted scope. Skill text is never authorization.

For a current-project request, the user does not need a PID. After confirming
one exact in-project executable, arguments, representative workload, and the
per-call authorization, the Skill calls `collect_project_workload`. An
ordinary-user coordinator creates the process, captures its identity, submits
the PID-only plan, and keeps it waiting. The first hardware-probe or formal perf
stage starts disabled; after perf confirms binding, the Collector revalidates
PID/UID/start time, enables events, and streams a versioned readiness frame
bound to the plan and PID. The authenticated client then releases the same
process to execute, replacing the former fixed 200ms delay. An `auto` probe
therefore observes the released workload instead of an idle bootstrap. The
privileged Collector never receives or launches the workload command. Interactive,
setuid/setgid, shell, arbitrary-environment, and system-wide workloads are not
supported; daemonizing programs should expose a foreground mode. The user does
not memorize the fixed token: after exact confirmation, the Agent supplies
`I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`. A denied call must not be replaced
with shell/direct-perf/existing-PID execution. Callgrind, parameter sweeps,
changed arguments, and other additional executions require separate explicit
authorization.

Local capability inspection describes the ordinary MCP process, not the
independent Collector. Under `perf_event_paranoid=3`, local access can be
blocked while Broker collection succeeds. Treat the executed Collection's
actual source and fallback reason as authoritative. Older software record
artifacts without sample CPU identity are read through a narrowly matched
compatibility path and marked `MISSING_SAMPLE_CPU`; per-CPU analysis is not
available for those files.

See [Product deployment](deployment.md) for configurable asset rendering, the
no-PID `accept-collector` host probe, advanced existing-PID verification,
upgrades, and uninstall behavior.
