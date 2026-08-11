# Collector privilege-mode lifecycle

This document defines the PerfLens 0.2.0 first-deployment, project-detection, and mode-switching contract. See the [complete Simplified Chinese guide](collector-mode-lifecycle.zh-CN.md) for the primary user-facing instructions.

PerfLens ships, but never automatically activates, two mutually exclusive host-level modes:

- `cap_perfmon` is the default and smaller boundary. The dedicated non-root Broker owns the required performance-monitoring capability. On Debian it normally requires `perf_event_paranoid <= 2`.
- `paranoid3_helper` keeps `perf_event_paranoid=3`. The public Python Broker remains unprivileged and delegates typed, bounded PID plans to a private Rust Helper. The Helper is a root service with an explicitly bounded capability set, so selection requires risk acknowledgement.

Package installation does not choose a mode, edit sysctl, start either service, or grant capabilities. First-time interactive setup is:

```bash
sudo perflens-admin setup
```

`setup` is first-install only. If a deployed policy already exists, it stops before mutation and
directs the administrator to `switch-mode`, `upgrade`, or `update-policy`; it never overwrites an
administrator policy with generated defaults.

Non-interactive automation selects a mode explicitly and runs a dry-run first:

```bash
sudo perflens-admin setup --mode cap_perfmon --dry-run
sudo perflens-admin setup --mode cap_perfmon
```

The third setup choice, `analysis_only`, leaves the host unchanged.
Selecting `cap_perfmon` while `perf_event_paranoid > 2` produces a blocked dry-run and is
refused before system writes. The administrator must select another outcome or review host
kernel policy separately.

`perflens init` is project-scoped. It safely validates `/etc/perflens/collector.toml`, detects the active host mode, and configures the project MCP to read the matching spool. An unsafe installed policy is an error rather than a reason to guess. With no deployed policy, a new project falls back to `cap_perfmon` without deploying anything; `perflens init --update` preserves an existing project's recorded candidate mode so its MCP and staged assets stay consistent.

An explicit project mode that conflicts with an installed host policy is always rejected, including
when `--prepare-collector` is present. This prevents MCP configuration from being pointed at a
candidate spool before the host switch. Switch the host first, then run `perflens init --update`.

Switches are explicit host-level transactions:

```bash
sudo perflens-admin switch-mode cap_perfmon --dry-run
sudo perflens-admin switch-mode paranoid3_helper --dry-run
sudo perflens-admin switch-mode paranoid3_helper \
  --acknowledge-privileged-helper-risk
```

A switch validates the current policy and managed units, stops the old mode, atomically replaces only verified PerfLens files, starts the target mode, and performs an authenticated Socket health check. Failure restores the prior policy, units, and services. Neither spool is migrated or deleted. Switching to `cap_perfmon` is refused while `perf_event_paranoid > 2`; PerfLens never edits that sysctl.

Formal `deploy`, `switch-mode`, `upgrade`, `update-policy`, and `undeploy` mutations share one
fixed, permission-restricted host transaction lock. The installed
`/etc/perflens/collector.toml` must be root-owned; an invoking-user-owned mode-`0600` file is only
accepted as a reviewed candidate input.

After a successful host switch, each previously initialized project runs:

```bash
perflens init --update
```

If the requested mode is already active but the packaged managed unit differs, `switch-mode`
leaves it untouched and directs the administrator to `perflens-admin upgrade`.

If `cap_perfmon` is active but a managed privileged Helper unit remains, same-mode
`switch-mode cap_perfmon` and `upgrade` instead converge the host by stopping and removing the
stale Helper. Failure restores the previous file but leaves that stale Helper stopped rather than
re-expanding privilege during rollback; the Broker is restored. A failed switch that restores the
old mode reports `details.rollback_performed=true` in its structured error; a rollback failure
reports `false`.

`deploy --config` remains the advanced reviewed-policy path. `update-policy` changes bounded fields within the current mode; `upgrade` refreshes managed service files; neither command switches privilege mode.
