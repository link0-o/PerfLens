# Collector privilege-mode and feature-profile lifecycle

This document records the shipped PerfLens `0.2.0` first-deployment, project-detection, and
privilege-mode lifecycle and defines the feature-profile contract implemented in the pre-release
v0.3.0 source tree. These commands are absent from `0.2.0` packages and remain source/local-build
validation interfaces until all v0.3.0 release gates pass. See the
[complete Simplified Chinese guide](collector-mode-lifecycle.zh-CN.md).

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

## Feature-profile wizard in the pre-release `v0.3.0` source tree

Feature profiles are independent from the two privilege modes:

- `full_diagnostics`: `stat`, `record`, `sched`, `off_cpu`, and `lock`; recommended for a fresh
  host only when every trace preflight passes.
- `cpu_only`: `stat` and `record`; the smaller boundary and the compatibility profile for an
  existing `0.2.0` deployment after package upgrade.

DEB installation remains non-interactive and inactive and only directs the administrator to
`sudo perflens-admin setup`. The wizard shows these two primary profiles first. It retains
`analysis_only` as an advanced automation/fallback value, not a third feature profile. Missing
tracefs, perf, kernel-event, privilege, or real-probe prerequisites mark full diagnostics
unavailable and make CPU-only the recommendation; a partial feature set must not be deployed under
the full name.

After profile selection, the wizard recommends `cap_perfmon` or `paranoid3_helper` from observed
host facts. An explicit incompatible choice is rejected before writes, and PerfLens never changes
`perf_event_paranoid`. The automation interface is:

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode cap_perfmon \
  --dry-run

sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode paranoid3_helper \
  --acknowledge-privileged-helper-risk \
  --acknowledge-trace-risk
```

Full diagnostics requires explicit trace privacy/data/overhead acknowledgement. The level-3 path
also requires the existing Helper acknowledgement. The current Rust Helper stays limited to
`stat/record`; a separate Trace Helper owns its own unit, private socket, protocol, policy, raw
spool, lifecycle, and risk review.

Full diagnostics in both privilege modes uses that separate Trace Helper and packaged fixed eBPF.
It filters the authorized TGID/TIDs in kernel before writing target-only NDJSON to the private
spool. It neither treats stock `perf -p` as complete scheduler evidence nor invokes or falls back
to `perf -a` or equivalent all-CPU capture.

`perflens init` is project-scoped. It safely validates `/etc/perflens/collector.toml`, detects the active host mode, and configures the project MCP to read the matching spool. An unsafe installed policy is an error rather than a reason to guess. With no deployed policy, a new project falls back to `cap_perfmon` without deploying anything; `perflens init --update` preserves an existing project's recorded candidate mode so its MCP and staged assets stay consistent.

Plain `perflens init` now discovers the
deployed feature profile and produces consistent MCP mode gates and evidence roots. Project users
do not need host privilege or feature-profile flags.

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

## Feature-profile switching in the pre-release `v0.3.0` source tree

Feature changes use a separate transaction rather than editing `allowed_modes` or overloading
`switch-mode`:

```bash
sudo perflens-admin switch-profile full_diagnostics --dry-run
sudo perflens-admin switch-profile full_diagnostics --acknowledge-trace-risk
sudo perflens-admin switch-profile cpu_only --dry-run
sudo perflens-admin switch-profile cpu_only
```

`switch-profile` shares the fixed host transaction lock, validates policy, managed units, target
profile, and host capabilities, presents a deterministic diff, atomically applies the trace
topology, authenticates health, and restores prior policy/units/services on failure. Returning to
CPU-only stops the Trace Helper but preserves administrator configuration and all evidence.

A successful profile switch proves topology health only. The administrator must then run
`perflens accept-collector --authorize-host-acceptance` as the ordinary user. For full diagnostics
it requires substantive target evidence plus deterministic analysis and replay verification for
`sched`, `off_cpu`, and `lock`; an empty stream or merely live service cannot pass.

When a privilege-mode switch occurs with full diagnostics active, the same transaction converges
the Broker, current Helper, and Trace Helper to the selected privilege topology. No switch migrates
or deletes a spool. Existing projects run `perflens init --update` afterward.

A package upgrade from `0.2.0` preserves `cpu_only`: it does not create trace policy, start the
Trace Helper, or expand allowed modes. Only an explicit reviewed `switch-profile
full_diagnostics` may widen that boundary.

Privilege mode describes deployment and security boundaries, not maturity of every performance
collection mode. See the [Collector capability expansion roadmap](collector-capability-roadmap.md)
for the audited current state and staged `sched/lock/off_cpu` acceptance gates.

Acceptance must cover both primary profile prompts, dynamic recommendation, non-TTY missing-input
failure, both risk acknowledgements, the two privilege modes times two feature profiles, profile
rollback and artifact preservation, and package non-activation. Existing `0.2.0` upgrades must
never opt into full diagnostics automatically.
