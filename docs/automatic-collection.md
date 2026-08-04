# Automatic collection and the Collector Broker

English | [简体中文](automatic-collection.zh-CN.md)

PerfLens closes the loop from an approved live PID to evidence, analysis, and a report without making the Agent or MCP server privileged.

```text
user grant → Skill → optional ordinary-user launch → PID-bound MCP plan → restricted Collector → analysis
```

The optional `perflens-collector` is a Unix-socket broker. It authenticates peers with `SO_PEERCRED`, accepts only typed PID plans, revalidates PID owner/start time, enforces an independent root-owned policy, and writes only to a fixed spool. Plans have a bounded lifetime, and the running Broker rejects replay of the same plan. It also rejects a `perf` executable that is both non-root-owned and writable by the service account. It never accepts a shell command, arbitrary executable, environment, output path, or system-wide target.

Run `perflens doctor` for a read-only capability report. Stage the packaged service templates with:

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
Validate the policy with `perflens-admin deploy --config <toml> --dry-run`,
then run that trusted system-package entry point once with `sudo` and without
`--dry-run`. Wheel deployments use `/opt/perflens/bin/perflens-admin`. The fixed deployer uses packaged templates and never
executes project-provided commands or changes sysctl.

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

For a current-project request, the user does not need a PID. After confirming
one exact in-project executable, arguments, representative workload, and the
per-call authorization, the Skill calls `collect_project_workload`. An
ordinary-user coordinator creates the process, captures its identity, submits
the PID-only plan, and then releases the same process to execute. The privileged
Collector never receives or launches the workload command. Interactive,
setuid/setgid, shell, arbitrary-environment, and system-wide workloads are not
supported; daemonizing programs should expose a foreground mode.

See [Product deployment](deployment.md) for configurable asset rendering, the
no-PID `accept-collector` host probe, advanced existing-PID verification,
upgrades, and uninstall behavior.
