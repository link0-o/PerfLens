# PerfLens product deployment

English | [简体中文](deployment.zh-CN.md)

Production Debian 13 users should prefer the split native packages documented
in [Debian packages](debian-packages.md). The wheel flow below remains useful
for development acceptance and other Linux distributions.

Deploy PerfLens as two privilege domains: ordinary-user CLI/MCP/Skill processes and a dedicated `perflens-collector` system service with only the host-approved perf capability. The Agent and MCP server must not run as root.

Ordinary users should complete [Installation and first use](../INSTALL.md) and run `perflens setup` first. This page focuses on administrator-managed Collector deployment.

For the current wheel-based deployment:

1. install the Collector runtime outside user home, for example under `/opt/perflens`;
2. run `stage-collector-assets` with the real allowed UID, Collector command, and perf path;
3. inspect the TOML and use the trusted `perflens-admin deploy` entry point;
4. add the authorized user to the `perflens` group and restart their login session;
5. review the host `perf_event_paranoid` policy;
6. run `perflens accept-collector --authorize-host-acceptance` as the ordinary user;
7. only then enable the MCP automatic-collection gates.

Example asset rendering:

```bash
perflens stage-collector-assets \
  --output-directory ./collector-assets \
  --allowed-uid 1000 \
  --collector-command /opt/perflens/bin/perflens-collector \
  --perf-path /usr/bin/perf
```

The staged policy is `collector-assets/collector.toml`. It includes bilingual
field-by-field guidance for tunable, fixed, and security-sensitive settings. Validate it without
changes, then run one explicit administrator command:

One Collector instance requires exactly one authorized ordinary UID. Collected
profiles must be group-readable by that caller; placing multiple callers in the
same `perflens` group would expose profiles across users. Policy loading, asset
staging, and one-command deployment therefore reject multiple UIDs. Do not share
this instance on a multi-user host; future support requires isolated
service/socket/spool instances per UID or an authenticated artifact-read protocol.

```bash
/opt/perflens/bin/perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml" \
  --dry-run
sudo /opt/perflens/bin/perflens-admin deploy \
  --config "$PWD/collector-assets/collector.toml"
```

Use the copy installed in an administrator-controlled `/opt/perflens` runtime
or system package, not a user-writable pipx script. The deployer accepts only a
strict data policy and runs a fixed allowlist of system commands. It installs
new or byte-identical files, starts the service, and requires a bounded,
read-only health round trip. The Collector authenticates the caller UID, while
the administrator client verifies the server PID/UID with kernel `SO_PEERCRED`
and requires the dedicated `perflens` UID. A stale or wrong-owner socket cannot
be mistaken for readiness. It then returns a versioned JSON result. It
does not alter sysctl/capabilities or run
commands from the config. The staged unit and sysusers files remain audit
copies; the deployer renders trusted packaged templates.

After login-group changes, ordinary users can run `perflens status --project
/absolute/path/to/workspace` for one read-only readiness summary. Generated
policies carry `policy_version = 1`; a missing field is treated as legacy
version 1, while unsupported versions are rejected before deployment and
Collector startup.

Long-running automatic collection is also bounded by `max_spool_bytes`,
`max_spool_artifacts`, and `min_free_bytes`. The defaults cap logical artifact
storage at 10 GiB and 1000 files while reserving 1 GiB on the spool filesystem.
The Collector reserves the plan's worst-case output before starting perf and
returns `RESOURCE_LIMIT_EXCEEDED` when a boundary cannot be met. It never
deletes or rotates old evidence automatically; an administrator must review and
archive artifacts before explicitly removing them.

Routine operators do not need to combine `find`, `du`, and `df`. Run the single
read-only command `perflens-admin spool-status` to get a Chinese summary of file
count, logical bytes, filesystem reserve, and the largest output currently
reservable. It reads `/etc/perflens/collector.toml` by default and never changes
configuration, artifacts, or collection state. Use `--json` for the complete
versioned artifact, or `--config /absolute/path/collector.toml` before the
default system policy is installed. An unsafe status means the direct spool
contains a directory, symbolic link, or another non-regular entry; the command
does not follow or remove it. A quota-short-circuited scan reports
`scan_complete = false`, so observed values are lower bounds.

This is a point-in-time inspection, not a reservation. The Collector still
rechecks capacity immediately before starting perf, and concurrent artifacts
may cause a later collection to be safely denied.

PerfLens never deletes evidence by age automatically. For an explicit,
auditable lifecycle, prepare a root-managed, non-group-writable directory on
independent storage, then run `sudo perflens-admin archive-spool --output
/absolute/archive.zip --dry-run` followed by the same command without
`--dry-run`. Defaults select managed artifacts older than seven days, keep the
newest 20, and bound one archive to 1000 files or 10 GiB.

The stored ZIP contains a versioned manifest plus source identity and SHA-256
for every `plan-<20 hex>.perf.data` or `.stat.csv` member. Archive creation
rejects unknown entries, links, directories, unsafe ownership/modes, concurrent
changes, and existing outputs; it preserves every source. After copying the ZIP
to independent storage, run `sudo perflens-admin prune-archived-spool --archive
/absolute/archive.zip --dry-run`. Only after reviewing every planned name, pass
`--authorization I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE`.

Pruning requires a root-managed archive and parent, verifies the ZIP, manifest,
archived bytes, and each source device/inode/size/mtime/owner/mode/SHA-256 before
any removal, then rechecks each source immediately before unlinking. The archive
is always preserved and repeated execution is idempotent. This is a human
administrator operation and must not be scheduled by an Agent.

To tune collection modes, duration, frequency, events, or storage quotas, do
not edit the live `/etc/perflens/collector.toml` in place. Copy it to a separate
candidate, set mode `0600`, edit the bilingual comments, and run:

```bash
perflens-admin update-policy --config "$PWD/collector.next.toml" --dry-run
sudo perflens-admin update-policy --config "$PWD/collector.next.toml"
```

The command strictly validates both policies, atomically replaces only the
fixed deployed policy, restarts the Collector, and completes the authenticated
health handshake. Byte-identical input returns `unchanged` without mutation or
restart. Activation failure restores the exact previous policy and verifies it
after another restart. This command cannot change the authorized UID or fixed
spool and never changes the unit, retained artifacts, users/groups, sysctl, or
capabilities. Candidate comments are preserved verbatim. Identity or spool
migration requires a separate stopped-service administrator procedure.

`accept-collector` starts a fixed, self-owned CPU probe and performs a real,
policy-bounded perf-stat collection of at most five seconds. It always cleans up
the probe, so users do not need to find a PID. It prints a concise Chinese pass
summary by default; `--json` emits the complete versioned acceptance artifact and
`--output` safely preserves it as a new file. It still requires
`--authorize-host-acceptance` because it is not a read-only health check. The
command refuses a false pass when perf returns only unsupported or uncounted
events: at least one finite `measured` metric is required. The advanced
`verify-collector` command remains available for an explicitly authorized
existing PID.

Production releases now ship separate `perflens` and `perflens-collector` DEBs.
They install offline and do not activate the service. Future RPM installers must
preserve the same boundaries: preserve administrator configuration, avoid
silently changing sysctl, and never grant `CAP_SYS_ADMIN` by default. Host-level
Collector plus a controlled Unix socket is preferred over a privileged container.

For upgrades, install the new wheel or system packages first, then run `sudo
perflens-admin upgrade --dry-run` and `sudo perflens-admin upgrade`. The command
reads only the fixed deployed policy, compares SHA-256 hashes of the current and
packaged units, replaces only a verified PerfLens-managed unit, and restarts the
service to load the new program. Policy and spool data are preserved. A failure
after unit replacement triggers an attempted atomic unit rollback and service
reload; the same rollback applies when the health handshake fails. Run
ordinary-user `perflens accept-collector
--authorize-host-acceptance` again after every upgrade.

After deployment and verification, the Skill can confirm and launch one exact
in-project executable as the ordinary user. PerfLens obtains that new PID and
sends only a short-lived PID plan to the Collector. This enables natural
“optimize the current project” requests without giving workload commands to the
privileged service or requiring the user to discover a PID.

Before package removal, run `sudo perflens-admin undeploy --dry-run` and then
`sudo perflens-admin undeploy`. It removes only a verified managed unit while
preserving policy, collected artifacts, and the system identity. See the
[Chinese guide](deployment.zh-CN.md) for the complete lifecycle.
