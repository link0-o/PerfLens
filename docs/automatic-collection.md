# Automatic collection and the Collector Broker

English | [简体中文](automatic-collection.zh-CN.md)

PerfLens closes the loop from an approved live PID to evidence, analysis, and a report without making the Agent or MCP server privileged.

```text
user/admin grant → Skill → PID-bound MCP plan → restricted Collector → perf spool → analysis
```

The optional `perflens-collector` is a Unix-socket broker. It authenticates peers with `SO_PEERCRED`, accepts only typed PID plans, revalidates PID owner/start time, enforces an independent root-owned policy, and writes only to a fixed spool. Plans have a bounded lifetime, and the running Broker rejects replay of the same plan. It also rejects a `perf` executable that is both non-root-owned and writable by the service account. It never accepts a shell command, arbitrary executable, environment, output path, or system-wide target.

Run `perflens doctor` for a read-only capability report. Stage the packaged service templates with:

```bash
perflens stage-collector-assets --output-directory ./collector-assets
```

Review `collector.example.toml`, `perflens-collector.service`, and `perflens.sysusers` before an administrator installs them. The service template uses a dedicated account and `CAP_PERFMON`; PerfLens never changes sysctl, capabilities, ownership, or service state at runtime.

On Debian, `perf_event_paranoid=3` blocks perf before the normal CAP_PERFMON path. An administrator must either review and lower that policy for the dedicated collector or design a more privileged isolation boundary. Do not run the MCP server or Agent as root.

For automatic MCP collection, enable all explicit server gates, configure `--collector-socket`, include the collector spool as an `--allowed-root`, and bound modes/duration/frequency. See the [Chinese guide](automatic-collection.zh-CN.md) for the complete configuration and safety model.

The automatic workflow is:

1. `inspect_collection_capabilities`;
2. `plan_automatic_collection`;
3. verify the plan is allowed;
4. `execute_collection_plan` once before it expires;
5. read typed stat metrics or call `analyze_collection` for perf-data output;
6. continue the normal evidence workflow.

The Skill may automate these steps inside an already granted scope. Skill text is never authorization.
