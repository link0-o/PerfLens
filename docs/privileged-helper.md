# PerfLens privileged Helper for `paranoid=3`

[简体中文](privileged-helper.zh-CN.md) | English

Status: implemented in `v0.2.0` and packaged in the native Debian Collector package. Enabling it
still requires explicit administrator selection, risk acknowledgement, and real acceptance.

## Goal and non-goals

The goal is bounded PID collection on Debian while `perf_event_paranoid=3` remains unchanged. The
CLI, MCP server, Skill, analyzers, and public Collector Broker remain unprivileged Python. Only a
new, small Rust Helper crosses the higher-privilege boundary after explicit administrator setup.

This design does not run the Python Broker as root, let an Agent invoke sudo, change sysctl, accept
commands/environments/paths/system-wide targets, or launch a user workload with Helper privileges.

## Deployment modes

`cap_perfmon` remains the default and requires a host policy compatible with `CAP_PERFMON` (normally
`perf_event_paranoid <= 2` on Debian). `paranoid3_helper` is an explicit advanced mode: the public
Broker has no capability and a separate Rust Helper receives only the capabilities in its reviewed
systemd unit. Package installation never activates this mode, and both a policy selection and an
administrator risk acknowledgement are required.

Use `sudo perflens-admin setup` for first selection. Existing deployments use
`perflens-admin switch-mode paranoid3_helper --dry-run` and explicit risk acknowledgement;
the transaction health-checks the target and rolls back on failure without deleting either
spool. See the [Collector privilege-mode lifecycle](collector-mode-lifecycle.md).

The reviewed unit bounds the Helper to `CAP_PERFMON`, `CAP_SYS_ADMIN`, and
`CAP_SYS_PTRACE`. `CAP_SYS_PTRACE` is required by `perf record` to inspect the
already-authorized target's mappings and synthesize usable sampling metadata; a
stat-only probe does not prove record is usable. This capability does not bypass
the typed owner-PID plan: both processes still verify peer identity, target UID,
PID start time, expiry, replay state, mode, events, and resource limits.

At level 3 onboarding offers three outcomes: keep the safer default and have an administrator
review host policy, retain level 3 and deploy the Helper, or analyze existing profiles only.
PerfLens detects and explains sysctl but never changes it.

## Process and identity boundary

```text
ordinary Agent / Skill / MCP
        │ public Unix socket
        ▼
Python Collector Broker (no capabilities)
        │ private Broker-only Unix socket
        ▼
Rust privileged Helper (root UID, systemd capability bounding set)
        │ fixed perf executable and typed PID target
        ▼
fixed /var/lib/perflens-helper spool
```

Public and private sockets use different directories, groups, and modes. The Helper verifies the
fixed Broker UID through `SO_PEERCRED`; knowing the pathname or belonging to the client group never
authorizes direct Helper access. The Broker independently verifies the Helper UID, socket/parent
identity, and response ID on every exchange.

## Private protocol

Messages are versioned, at most 64 KiB, and reject unknown fields. The sole stateful request carries
only a request ID, single-use plan ID, PID, target UID, process start time, enum mode, integer
duration, allowlisted events, bounded frequency, and output limit. There are no argv, shell,
environment, working-directory, perf-path, output-path, or system-wide-target fields.

Python/Pydantic and Rust/Serde share checked-in JSON Schemas and valid/invalid golden fixtures. Both
sides reject duplicate or unknown fields, non-finite/out-of-range numbers, trailing data, unsupported
versions, and mismatched response IDs. The Helper repeats every security check independently of the
Python validation.

## Execution and artifacts

The Helper executes only the root-owned, non-writable absolute perf path selected by administrator
policy. Arguments are derived from enums and allowlists without a shell. Artifact names derive only
from plan IDs and are published into the fixed spool after identity, symlink/link, ownership, mode,
size, digest, quota, and free-space checks.

To close PID reuse between identity validation and attachment, perf first opens the target with
events disabled. An inherited control-FD `ping/ack` barrier proves that binding completed; the
Helper then revalidates owner and start time before sending `enable`. The resulting kernel event
descriptors remain bound to the task perf actually opened. The Helper launches only perf and uses
the control channel plus signals for duration enforcement, never a sleep process or workload.

When a project workload requests readiness, private protocol `1.2` emits exactly one
request/plan/PID-bound `collection_ready` frame only after that sequence. If `auto` starts with a
hardware probe, the probe is the first stage and reports readiness. The Python Broker authenticates
and relays it as public Broker protocol `1.1`; the ordinary-user program does not execute earlier.

Fresh deployment requires `--acknowledge-privileged-helper-risk`. During an
upgrade, `--dry-run` reports any newly added capability in
`helper_capability_expansion`; the real upgrade refuses to modify the managed unit
without the same explicit acknowledgement. The legacy
`--acknowledge-cap-sys-admin-risk` spelling remains accepted.

A plan is durably consumed before perf starts. Failure, timeout, and Broker/Helper restart do not
make it reusable. Timeout or overflow terminates the controlled process and returns a bounded error;
operational logs exclude profiles, arbitrary stderr, target commands, and sensitive paths.
After a crash, only internal temporary files whose names, ownership, modes, link counts, and inode
relationships all match the immutable recovery rules are removed; unknown spool entries still fail
closed. Capacity scans use no-follow metadata and independently validate exact artifact and replay
marker names, owners, groups, modes, and link counts. Replay markers are retained for the protocol's
maximum plan lifetime, then durably pruned under a fixed count ceiling.

## Rust and release boundary

Rust is used only for the Helper. Ordinary wheels neither contain nor build it, so Python analysis
does not need a Rust toolchain. Native packages build target-specific binaries in CI with a pinned
stable toolchain and checked-in `Cargo.lock`; users install no Cargo or rustc.

Unsafe Rust is forbidden in the current crate and covered by focused tests. Dependencies stay
minimal, locked, listed in third-party notices, and checked by Rust supply-chain audits.

## Required acceptance

Tests cover unauthorized peers, forged/replaced sockets, PID owner/start-time mismatch, expiry,
replay, cross-UID denial, every bound, unknown command/path/environment fields, spool escape,
capacity failure, Helper crashes, deploy/upgrade/rollback/undeploy, and package non-activation. Both
deployment modes require a real bounded perf probe; health alone is never sufficient.
