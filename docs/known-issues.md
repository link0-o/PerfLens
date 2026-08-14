# PerfLens known issues

[简体中文](known-issues.zh-CN.md) | English

This document records reproduced issues and their bounded workarounds, including
resolved issues. Do not weaken deployment safety checks to work around them.

## KI-2026-08-12: software record succeeded but analysis required a missing CPU field (resolved)

- Confirmed affected scope: `cpu-clock` perf.data created after software fallback by withdrawn
  same-version `v0.2.0` `paranoid3_helper` packages. The fix covers both software and hardware
  record commands; text profiles were not affected.
- Symptom: the Collection reported a successful, multi-megabyte record artifact, but
  `analyze_collection` returned `EXTERNAL_TOOL_FAILED`. The underlying `perf script` said that
  samples did not have the CPU attribute set and that it could not print the `cpu` field.
- Cause: the Helper's fixed record command omitted `--sample-cpu`, while the PerfLens perf-script
  adapter requested a per-sample CPU field.
- New-recording fix: both hardware and software record commands now include fixed
  `--sample-cpu`. Every perf argument is still derived from the typed plan; arbitrary perf options
  are not exposed.
- Existing-artifact compatibility: only after matching that exact perf error, the analyzer retries
  without the CPU field and emits `MISSING_SAMPLE_CPU`. Hotspots, call paths, and source attribution
  remain available, but per-CPU distribution does not. Unrelated perf-script errors remain visible.

This was a mismatch between capture and conversion fields, not a
`perf_event_paranoid=3` or VMware fallback failure. Replacement `v0.2.0` packages preserve CPU
identity in new recordings; affected existing artifacts do not need to be deleted.

## KI-2026-08-12: project authorization was easy to omit and an Agent escaped its scope (resolved)

- Previous symptom: after the user confirmed a project workload, an Agent omitted the fixed
  authorization value from `collect_project_workload`. The server correctly denied the call, but
  the Agent then tried shell/background execution, direct perf, an existing-PID plan, Callgrind,
  or parameter sweeps.
- Boundary: one project-workload authorization covers only the confirmed executable, arguments,
  mode, and limits. It does not authorize shell/`timeout` wrappers, direct perf, existing-PID
  attachment, Callgrind, parameter sweeps, changed arguments, or extra correctness commands.
  `PID attachment is disabled by server policy` is the expected result when that separate feature
  is not enabled; it is not a Collector failure.
- Fix: the MCP input Schema now constrains `authorization` to the sole fixed value
  `I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`. Server instructions, error guidance, and the Skill
  require correcting that field inside the approved scope and retrying only the same tool. They
  explicitly prohibit switching execution channels as a workaround.
- Provenance: `inspect_collection_capabilities` describes the ordinary MCP process. A local
  `blocked` result under `perf_event_paranoid=3` does not prove the independent Collector is
  blocked and is not the fallback cause. The Collection's `actual_event_source`, `fallback_used`,
  and `fallback_reason` are authoritative; a common VMware result is
  `hardware_probe_produced_no_usable_counts`.
- Reporting: Callgrind `Ir` is an instruction-reference share produced by simulation or
  instrumentation, not a PerfLens `cpu-clock` record self-CPU percentage. Reports must name the
  tool and unit before combining those observations as candidate evidence.

The user does not need to memorize or repeat the fixed token. The Agent supplies it after the user
explicitly approves the exact workload. If the corrected tool call still fails, preserve and report
the error instead of widening execution scope.

## KL-2026-08-09: zero hardware-PMU counts on some VMware/hybrid hosts (automatic fallback available)

Some VMware guests on Intel hybrid hosts expose PMU devices but still return
zero `cycles`/`instructions`, `not supported`, `not counted`, or `ENOMEM` while
software events work. This is commonly a virtual-PMU/host-hypervisor
compatibility boundary, not insufficient guest CPU capacity, and root alone
does not repair it.

`record` and `stat` now default to `event_source=auto`. A fixed, same-PID probe
of at most 250ms selects hardware evidence when useful, otherwise stat uses
fixed software events and record uses `cpu-clock`. Results expose the actual
source, fallback reason, and limitations. Software fallback still supports CPU
time, scheduling activity, page faults, on-CPU hotspots, call paths, source
attribution, FlameGraphs, and same-source A/B validation. It does not support
IPC, hardware cache-miss, branch-miss, or other microarchitectural claims.

Use `hardware_required` when those counters are mandatory, or `software_only`
to pin comparable A/B runs on a host with a known-broken PMU. Never compare a
hardware baseline directly with a software candidate as equivalent evidence.

## KI-2026-08-10: Helper stat succeeded but record could not synthesize target mappings (resolved)

- Affected scope: the withdrawn native `v0.2.0` `paranoid3_helper` packages whose Helper unit
  bounded root to `CAP_PERFMON` and `CAP_SYS_ADMIN`. The default `cap_perfmon` mode and
  unprivileged components were not changed.
- Symptom: explicit `verify-collector --event-source software_only` stat collection succeeded,
  but `accept-collector` failed during its software `record` step with
  `EXTERNAL_TOOL_FAILED`. Running the equivalent `perf record` in a transient unit failed with the
  two-capability set but captured samples after adding `CAP_SYS_PTRACE`.
- Cause: `CAP_PERFMON` authorizes performance-event access, while this attached `perf record`
  workflow also needs ptrace-equivalent access to inspect the already-authorized target's mappings
  and synthesize usable sampling metadata. A successful stat-only probe did not exercise that path.
- Fix: the replacement same-version Helper unit has an exact ceiling of `CAP_PERFMON`,
  `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE`. The typed PID protocol, target UID/start-time checks,
  expiry, replay protection, event/duration/output bounds, and fixed spool remain unchanged.
  No capability is added to the Agent, Skill, MCP server, or Python Broker.
- Upgrade safety: `perflens-admin upgrade --dry-run` reports `CAP_SYS_PTRACE` in
  `helper_capability_expansion`. The real upgrade fails before writing or restarting until the
  administrator supplies `--acknowledge-privileged-helper-risk`.

Install the replacement packages, then run:

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade --acknowledge-privileged-helper-risk
perflens accept-collector --authorize-host-acceptance
```

The legacy `--acknowledge-cap-sys-admin-risk` option remains accepted, but new guides use the
capability-neutral name because the acknowledged boundary now includes both `CAP_SYS_ADMIN` and
`CAP_SYS_PTRACE`.

## KI-2026-08-10: Helper rejected Linux perf's NUL-terminated control ACK (resolved)

- Affected scope: the withdrawn native `v0.2.0` `paranoid3_helper` packages. The default
  `cap_perfmon` mode does not use this private Helper protocol.
- Symptom: service health and policy validation passed, but `accept-collector` or an explicit
  `verify-collector --event-source software_only` immediately returned `EXTERNAL_TOOL_FAILED`.
  Only the consumed-plan marker appeared in the Helper spool; no performance artifact was
  published.
- Cause: the control-fd documentation calls the completion response `ack\n`, while the Linux 6.12
  implementation writes the C-string size and therefore emits `ack\n\0`. The old line reader left
  the NUL buffered after the first ACK, read the next response as `\0ack\n`, and failed closed.
  Test doubles emitted only `ack\n`, so they did not reproduce the real framing.
- Fix: the replacement `v0.2.0` uses a strict, 16-byte-bounded binary ACK parser. It permits only
  implementation-produced leading NUL bytes before the documented ACK and rejects every other or
  oversized response. The startup barrier now uses perf's non-mutating `ping` command, preserving
  PID owner/start-time revalidation before events are enabled.
- Regression coverage: perf test doubles now emit the real `ack\n\0` response for every command,
  including the NUL carried into the following frame.

This was a Helper protocol compatibility defect, not a `perf_event_paranoid=3`, software-policy,
or VMware PMU fallback failure. Install the replacement same-version packages, run
`sudo perflens-admin upgrade`, and repeat ordinary-user acceptance. Do not weaken sysctl or grant
privilege to the Agent, MCP server, or Python Broker.

## KI-2026-08-07: withdrawn v0.2.0 Helper unit failed during systemd USER setup (resolved)

- Affected scope: the withdrawn initial native v0.2.0 `perflens-collector` DEB when Debian 13
  selected `paranoid3_helper`; the default `cap_perfmon` mode was not affected.
- Symptom: deployment health validation failed and the journal reported
  `Failed to drop keep capabilities flag` followed by `Failed at step USER`. The Broker could then
  fail its NAMESPACE step because the Helper runtime directory did not exist.
- Cause: the Helper unit set `keep-caps-locked` before systemd finished USER setup, while systemd
  still needed to clear `PR_SET_KEEPCAPS`; the kernel correctly denied the locked transition.
- Fix: the replacement `v0.2.0` artifacts remove the conflicting secure-bit lock. This USER-stage
  fix itself did not widen capabilities; the final replacement unit's separately documented record
  fix uses the explicit three-capability boundary above. No Agent, MCP, or Python Broker capability
  boundary is widened.

The failed deployment rolls back its new policy, units, and sockets. Do not edit the installed
package or weaken the unit manually; install the replacement `v0.2.0` artifacts and deploy the
reviewed policy again.

## KI-2026-08-07: bounded Helper collection treated expected SIGINT as failure (resolved)

- Affected scope: the withdrawn initial `v0.2.0` `paranoid3_helper` implementation.
- Symptom: deployment and the authenticated health handshake succeeded, but
  `perflens accept-collector --authorize-host-acceptance` returned `EXTERNAL_TOOL_FAILED` with
  `Privileged perf returned a non-zero result`.
- Cause: after disabling the events at the requested duration boundary, the Helper sent SIGINT so
  an attached `perf` process would flush and close its artifact. Linux reports that expected exit
  as signal 2/status 130, which the Helper incorrectly treated as an external failure.
- Fix: the replacement `v0.2.0` accepts SIGINT only when this Helper successfully sent it in the
  bounded shutdown path. An early SIGINT, any other signal, an ordinary non-zero exit, a control
  failure, or an empty/unsafe artifact still fails closed.

This fix does not make unavailable performance counters measurable. If acceptance proceeds to
`PROFILE_PARSE_FAILED` and every metric is `not_supported` or `not_counted`, check the host PMU. In
particular, a virtual machine may require virtual CPU performance counters to be enabled by its
hypervisor.

## KL-2026-08-07: Rust Helper private-spool archival was not supported (resolved)

- Affected scope: the withdrawn initial `v0.2.0` implementation of `paranoid3_helper`.
- Fix status: resolved in the replacement `v0.2.0` artifacts.
- Previous behavior: archive, verification, and prune commands explicitly returned
  `UNSUPPORTED_FORMAT` instead of inspecting the wrong spool.
- Fix: the lifecycle now selects the active spool from the reviewed privilege mode and separately
  verifies Helper directory/tombstone ownership (`root:perflens-internal`) and artifact ownership
  (`root:perflens`). The manifest binds the archive to its privilege mode and spool path.

Installations using the withdrawn artifacts should install the replacement v0.2.0 packages before
attempting Helper spool cleanup. Do not manually delete unknown evidence or loosen directory
permissions.

## KI-2026-08-06: native DEB upgrade can retain stale Python bytecode

- Affected path: an in-place native DEB upgrade from `v0.1.2` to `v0.1.3`.
- Fix status: fixed on the development branch for the next release.
- Symptom: `dpkg-query` reports `0.1.3-1` while a PerfLens entry point still reports `0.1.2`.
- Cause: reproducible packages fix Python source mtimes, allowing an old same-path `.pyc` to remain
  timestamp/size-valid when the older package did not remove it during configure.

The development fix makes the native launcher ignore inline package caches and disables bytecode
writes before importing PerfLens. The main package `postinst` also removes only legacy `.pyc/.pyo`
files and empty cache directories below fixed `/usr/lib/perflens` during `configure`.

Affected `v0.1.3` systems can use this bounded workaround:

```bash
dpkg-query -W -f='${Package} ${Version}\n' perflens perflens-collector
sudo find /usr/lib/perflens -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
sudo find /usr/lib/perflens -depth -type d -name '__pycache__' -empty -delete
hash -r
perflens --version
```

Do not delete the whole `/usr/lib/perflens` package runtime.

## KI-2026-08-05: `umask 0002` makes staged Collector policy undeployable

- Affected version: `v0.1.2`.
- Fixed in: `v0.1.3`.
- Status: resolved; the bounded workaround remains valid for `v0.1.2`.
- Scope: a new `collector.toml` produced by `perflens init --prepare-collector`
  or `perflens setup --prepare-collector`.
- Not affected: a policy already installed at `/etc/perflens/collector.toml`,
  existing-profile analysis, and read-only use without the Collector.

### Symptom and cause

On a host with `umask 0002`, the generated policy can have mode `0664`.
`perflens-admin deploy --dry-run` then correctly fails with
`PATH_SAFETY_VIOLATION` because the policy is group-writable. The `v0.1.2`
asset generator relies on the process umask instead of explicitly setting the
final policy mode. The deployer's ownership, type, size, and non-writable checks
must not be weakened.

### `v0.1.3` fix

The staging directory is now explicitly `0700`, `collector.toml` is `0600`, and
the systemd/sysusers templates are `0644`, independent of the caller's umask.
All deployer safety checks remain in place. After upgrading, run
`perflens init --update --prepare-collector` to regenerate assets; an unchanged
v0.1.2 Skill is also safely migrated to the shorter `perflens` directory name.

### `v0.1.2` workaround

Run as the ordinary user who generated the configuration:

```bash
chmod 600 "$PWD/perflens-setup/collector-assets/collector.toml"
stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"

perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run

sudo perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml"
```

Confirm mode `600` before deployment. Do not use `sudo` to bypass the mode
correction. This is a one-time host deployment for the authorized Linux user;
other projects only need their project-level `perflens init`.

### Fix acceptance

`v0.1.3` explicitly sets staged `collector.toml` to `0600`, tests generation
under `umask 0002` and `0000`, proves that the unmodified generated policy passes
deployment validation, and preserves every current deployer safety check.
