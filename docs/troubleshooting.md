# Troubleshooting

[简体中文](troubleshooting.zh-CN.md) | English

For failures limited to a published version, first check
[known issues, fixes, and bounded workarounds](known-issues.md), including the `v0.1.2`
group-writable Collector policy generated under `umask 0002`.

## Start with one read-only status command

Run:

```bash
perflens status --project /absolute/path/to/project
```

If setup used `--output-directory`, preserve the exact generated
`--setup-directory /absolute/path/to/project/<bundle>` argument. Otherwise the
default may inspect an older `perflens-setup` bundle and report automatic
collection as unconfigured. The Chinese summary ends with a state-specific
recovery or acceptance command.

It checks onboarding, Skill, whether project `.codex/config.toml` matches the
selected setup, staged Collector assets, the Unix
socket, current login-group membership, and host perf conditions. It never
samples or attaches to a process. If those prerequisites pass, it additionally
performs a 500 ms-bounded, read-only health exchange and authenticates the
service PID/UID with kernel `SO_PEERCRED`. An existing but stale, unresponsive,
malformed, or wrong-identity socket remains unavailable. `ready_for_verification` means an explicit
real `perflens accept-collector --authorize-host-acceptance` probe is the next step, not that sampling has already
succeeded.

The project MCP check also revalidates the configured executable. A missing,
non-executable, moved, or no-longer-trusted entry point makes configuration
incomplete and requires a fresh setup bundle.

PerfLens domain failures are Chinese-first for people. Automation must not parse
that prose: place the global `--json-errors` option before the subcommand, for
example `perflens --json-errors <command> ...` or `perflens-admin --json-errors
<command> ...`, or set `PERFLENS_JSON_ERRORS=1`. This preserves the complete
versioned `ErrorArtifact` and existing exit codes. Framework-level usage errors
that occur before command dispatch retain Typer's own format.

If the socket is missing or inaccessible, inspect the service and journal,
confirm the socket belongs to the `perflens` group, and start a new login session
after group membership changes. Do not run the Agent or MCP server as root.

Collector stderr is a versioned, bounded JSON-lines operational stream captured
by systemd. Use `journalctl -u perflens-collector.service --since today -o cat`.
Events include `collector_started`, `collection_completed`,
`request_rejected`, `collector_stopped`, and `collector_start_failed`.
Rejections carry the request ID, stable error ID, error code, stage, and
authenticated peer UID. A client invoked with `--json-errors` exposes the same
error ID and its request ID under `details` for correlation.

No event includes the target PID, command, environment, profile contents, perf
stderr, policy/spool paths, or a Python traceback, and each line is limited to
2 KiB. An `unknown` request ID means validation failed before a typed request
was available. Startup failures emit one `collector_start_failed` event and
exit nonzero; use its code and stage instead of weakening service isolation to
obtain a traceback.

Generated policies contain `policy_version = 1`. A missing version is accepted
as legacy version 1; unsupported versions are rejected before deployment or
Collector startup. Regenerate the policy with a matching PerfLens release rather
than deleting unfamiliar fields.

## Collector returns `RESOURCE_LIMIT_EXCEEDED`

A spool-quota or free-space error means the Collector could not reserve the
plan's worst-case output before starting perf. Run the read-only
`perflens-admin spool-status` command first. It compares direct regular-file
count, logical bytes, filesystem reserve, and currently reservable output with
the `max_spool_bytes`, `max_spool_artifacts`, and `min_free_bytes` policy fields.
Use `--json` for versioned machine-readable evidence. Review and archive
evidence before explicitly removing files; do not let the Agent delete
artifacts or hide disk pressure with unbounded limits.

An unsafe result means a directory, symbolic link, or another non-regular entry
was observed. Stop the Collector and inspect it manually; `spool-status` never
follows or removes such entries.

Do not use mtime-based `rm` or an Agent job to clear the spool. Use the explicit
`archive-spool --dry-run` → root-managed archive → independent copy →
`prune-archived-spool --dry-run` → authorized prune sequence. An unmanaged-entry
error means a temporary, manual, linked, or unknown file needs stopped-service
review. A source identity or SHA-256 mismatch means either copy changed; preserve
both and investigate instead of weakening validation. The archive and its parent
must remain root-managed and non-group-writable during pruning.

`perflens-admin upgrade` reads only the fixed deployed policy and replaces only
a trusted PerfLens-managed unit. Use `sudo perflens-admin upgrade --dry-run`
before execution. Alternate policies, symlinks, unknown units, and unsafe modes
are rejected before restart. If activation fails after replacement, the command
attempts to restore the old unit and reload systemd. A rollback warning requires
manual inspection of the unit, service status, and journal before retrying;
policy and spool evidence are not deleted.

`perflens-admin update-policy` requires a separate trusted, non-group-writable,
bounded UTF-8 TOML candidate. It rejects the live deployed path, unknown or
unbounded values, UID changes, fixed-spool or privilege-mode migration, symlinks, and untrusted
perf paths. Run `--dry-run` first. If restart or authenticated health checking
fails after replacement, it restores the exact prior policy and restarts again.
If rollback itself fails, stop retrying and inspect the current policy,
`systemctl status`, and journal.

Deploy and upgrade require a bounded `health` round trip, not merely an existing
socket pathname. The server authenticates the caller, and the client verifies
the responding PID/UID with kernel `SO_PEERCRED`; administrator readiness also
requires the dedicated service UID. A stale socket, wrong service identity,
incompatible protocol, unauthorized peer, malformed response, or timeout is a
real failure. Inspect service status and the journal; never bypass the handshake.

`perflens-admin undeploy` removes only a fixed unit with the PerfLens management
marker, trusted ownership, and no group/other write permission. Review rejected
legacy or manually edited units with `systemctl cat perflens-collector.service`
and migrate them explicitly; do not weaken the ownership check.

## Active perf collection is denied

PerfLens reports the bounded stderr from `perf` as `EXTERNAL_TOOL_FAILED`. Check `/proc/sys/kernel/perf_event_paranoid`, capabilities, container policy, and access to tracepoints outside PerfLens. The development host uses value `3`, which rejects unprivileged collection.

PerfLens never invokes sudo, changes sysctl, grants capabilities, mounts tracefs, or weakens host policy. Ask the system owner for an approved profile export or an explicitly configured profiling environment.

## Existing perf.data cannot be decoded

Use a `perf` build compatible with the recording host and pass its absolute path with `--perf-path`. If the binary container remains incompatible, export text on the source host with the documented field set and use `analyze-perf-script`. PerfLens does not parse the binary format directly.

## Symbols or source lines are missing

Check Build ID, matching DSOs, separate debug files, debug links, and container/build path mappings. Source resolution accepts a verified module-relative offset; it never guesses an ASLR or PIE base from a runtime address. Install `llvm-symbolizer` or `addr2line`, or keep unknown frames visible.

## MCP calls are denied

Confirm that every input and output lies under an `--allowed-root` and that the artifact root is inside one of those roots.

- JSON artifact creation needs `--allow-writes`.
- perf.data conversion and symbolizer processes need `--allow-process-execution`.
- live collection additionally needs `--allow-active-collection` and the exact per-call authorization phrase.
- PID attachment additionally needs `--allow-pid-attach` and its separate phrase.

Restart the MCP client after changing server configuration. Tool annotations are hints; these checks are independently enforced by the server.

## An output already exists

MCP artifacts never replace an existing pathname. Reusing an artifact ID is
accepted only when its stored bytes are identical; different content indicates
an ID collision or tampering and fails closed. CLI output commands may still
atomically replace a non-input destination where documented. Active collection
data always requires a new path. Choose a new output name rather than deleting
evidence automatically.

For a structured write error, inspect `details.published`. `false` means the
destination was not changed and retry is safe after fixing the cause. `true`
means complete bytes were published but directory durability or pathname
identity could not be confirmed; verify the destination before retrying so an
uncertain storage acknowledgement does not become an accidental overwrite.

## Analysis is partial

Inspect parse statistics, bounded warnings, the sampled event, weight semantics, call-graph availability, unresolved symbols, and source metadata. Individual malformed records may yield a valid `partial` artifact. Structural limit violations, mixed event semantics, or untrusted relocation data fail instead of silently approximating.

## Benchmark comparison is inconclusive

Use at least three repetitions, retain raw values, match workload and environment, and set a practical-impact threshold. A single run, environment mismatch, or overlapping approximate interval remains `insufficient_data`, `not_comparable`, or `no_material_change`; it is never promoted to a verified regression or improvement.
