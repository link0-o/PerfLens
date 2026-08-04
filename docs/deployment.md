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
new or byte-identical files, starts the service, waits for its Unix socket, and
returns a versioned JSON result. It does not alter sysctl/capabilities or run
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

`accept-collector` starts a fixed, self-owned CPU probe and performs a real,
policy-bounded perf-stat collection of at most five seconds. It always cleans up
the probe and emits versioned acceptance evidence, so users do not need to find
a PID. It still requires `--authorize-host-acceptance` because it is not a
read-only health check. The advanced `verify-collector` command remains
available for an explicitly authorized existing PID.

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
reload. Run ordinary-user `perflens accept-collector
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
