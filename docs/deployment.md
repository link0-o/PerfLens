# PerfLens product deployment

English | [简体中文](deployment.zh-CN.md)

Production Debian 13 users should prefer the split native packages documented
in [Debian packages](debian-packages.md). The wheel flow below remains useful
for development acceptance and other Linux distributions.

Deploy PerfLens as two privilege domains: ordinary-user CLI/MCP/Skill processes and a dedicated `perflens-collector` system service with only the host-approved perf capability. The Agent and MCP server must not run as root.

After installing the DEBs, the recommended first host configuration is
`sudo perflens-admin setup`. The `0.3.0` wizard offers `cap_perfmon`,
`paranoid3_helper`, and analysis-only. Use `perflens-admin switch-mode <mode> --dry-run` before an explicit
host-level switch, then run `perflens init --update` in initialized projects. See
the [Collector privilege-mode lifecycle](collector-mode-lifecycle.md). The staged
asset flow below remains the advanced path for reviewed custom policy.

Project onboarding remains unprivileged. Plain `perflens init` activates Codex and Claude
Code; `--client opencode` opts in OpenCode, while `--client copilot` configures both local
Copilot CLI (`.mcp.json`) and VS Code Copilot Agent (`.vscode/mcp.json`). These local project
files never grant GitHub's cloud Coding Agent access to the host Collector or Docker socket.
Repeated `--client` options select a per-project set. Users may explicitly persist future-init
defaults with `perflens client-defaults`; absent `~/.config/perflens/config.toml`, the built-in
selection remains Codex plus Claude Code. Project updates preserve their recorded selection unless
the user supplies a replacement list.
Claude Code and Copilot CLI both manage the `perflens` entry in `.mcp.json`; co-selection uses one
validated ownership copy and one atomic shared update.

## Guided setup in `v0.3.0`

Release v0.3.0 implements a feature-first, privilege-second wizard. DEB
installation remains non-interactive and inactive: it does not generate policy, start services,
or edit sysctl, and only directs the administrator to run:

```bash
sudo perflens-admin setup
```

The wizard first presents two primary feature profiles:

1. `full_diagnostics` (recommended on a compatible host): `stat`, `record`, `sched`, `off_cpu`,
   and `lock`.
2. `cpu_only`: the current stable `stat` and `record` with a smaller evidence and privilege
   surface.

The wizard first performs read-only checks of the packaged Trace Helper, kernel BTF, and
`perf_event_paranoid`; it neither loads BPF nor changes the host. When the Trace prerequisites are
available, `full_diagnostics` is the default feature recommendation, with an explicit reminder
that real short acceptance is still required after deployment. Otherwise full diagnostics is
marked unavailable and `cpu_only` becomes the default; a partial deployment cannot use the full
name. At `perf_event_paranoid <= 2`, the privilege menu defaults to the smaller `cap_perfmon`
boundary. Above level 2 it marks that path blocked and defaults to the host-compatible
`paranoid3_helper` without changing the kernel policy. An unreadable policy is reported and
rechecked during deployment preflight. Feature profile answers what may be collected, while
privilege mode answers which bounded process holds privilege.

The non-interactive preflight is:

```bash
sudo perflens-admin setup \
  --feature-profile full_diagnostics \
  --mode cap_perfmon \
  --dry-run
```

Full diagnostics requires acknowledgement of trace metadata, call-path, disk, and overhead risk.
The level-3 path additionally requires both `--acknowledge-privileged-helper-risk` and
`--acknowledge-trace-risk`. The existing Rust Helper remains limited to `stat/record`; a separate
Trace Helper handles the advanced modes. These interfaces are shipped in v0.3.0; every deployed
host must still pass the explicit short real-host acceptance before relying on them.

The Trace Helper capability set is fixed by privilege mode: `CAP_BPF CAP_PERFMON` for
`cap_perfmon`, and `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN` for `paranoid3_helper` because Debian level
3 rejects tracepoint `perf_event_open` before the ordinary `CAP_PERFMON` path. `CAP_SYS_ADMIN` is
granted only to the separately acknowledged Trace Helper, never to the Python Broker, MCP, Skill,
or Agent.

The post-install profile lifecycle is transactional:

```bash
sudo perflens-admin switch-profile full_diagnostics --dry-run
sudo perflens-admin switch-profile full_diagnostics --acknowledge-trace-risk
sudo perflens-admin switch-profile cpu_only --dry-run
sudo perflens-admin switch-profile cpu_only
```

Returning to CPU-only stops the Trace Helper without deleting policy or retained evidence. Project
users still run plain `perflens init`; it discovers the deployed privilege mode and feature
profile. See the [Collector and user-space-lock roadmap](collector-capability-roadmap.md) for the implementation
and acceptance contract.

## `v0.3.1` Docker deployment boundary

Release v0.3.1 supports collection from one explicit process in a local Linux Docker Engine using
cgroup v2. Project users opt in with `perflens init --docker`; the generated project policy remains
inactive until the user authorizes one run or one bounded in-memory Agent session. See the
[v0.3.1 Docker process guide](docker-container-roadmap.md).

Docker is the `host/docker` target-runtime axis, not a third Collector privilege mode. It remains
orthogonal to `cpu_only/full_diagnostics` and `cap_perfmon/paranoid3_helper`. The v0.3.1 DEBs:

- do not install or start Docker and do not edit the `docker` group, daemon configuration, or
  Docker-socket permissions;
- do not build or pull images, enable container support, or expose the Docker socket to the
  Collector, Helpers, Agent, MCP, or Skill;
- permit only a fixed ordinary-user adapter to access the fixed local Engine, after which the
  Broker/Helper independently revalidates `/proc`, PID namespace, start time, and cgroup identity;
- deny rootful UID-0 targets until an administrator explicitly enables the dedicated
  `allow_rootful_container_targets` risk boundary; daily collection still uses no sudo;
- require `perflens init --docker`, followed by per-run confirmation or a
  `bounded_session` confirmed once at the start of the current Agent conversation. That grant is
  memory-only and bound to the exact image, command, mounts, resources, and target. Conversation
  end, MCP restart, identity/configuration change, or the default two-hour hard backstop revokes it.

Silence never means consent, and there is no permanent project grant. Each Collector child plan
remains short-lived and single-use even inside the session, and each trace remains at most ten
seconds.

An Agent client's MCP permission dialog, persistent tool allowlist, or auto-approval mode grants
only categorical access to the authorization tool. It is not consent to any resolved image,
command, target, or budget. The Skill must first show the complete authorization summary, stop and
wait for a fresh user reply, and only then call the authorization tool. Do not permanently allowlist
`authorize_docker_session` or `authorize_managed_docker_session` if the client permission dialog is
the desired confirmation surface. The call must carry the exact, non-empty `allowed_modes` set
shown in the summary. A later mode expansion requires a new summary and fresh confirmation.

Ordinary users should complete [Installation and first use](../INSTALL.md) and run `perflens init` in the selected project first. This page focuses on administrator-managed Collector deployment.

Prefer `perflens setup --prepare-collector` to generate assets and exact commands
for the detected installation layout. Native DEBs select trusted `/usr/bin`
entry points automatically; wheel/source installs select `/opt/perflens`. Use
the lower-level `stage-collector-assets --collector-command ...` flow only for
a deliberately managed custom administrator layout.

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
be mistaken for readiness. It prints a Chinese summary by default, clearly
distinguishing dry-run validation from completed deployment and showing the next
ordinary-user action. Add `--json` for the complete versioned result. It does
not alter sysctl/capabilities or run
commands from the config. The staged unit and sysusers files remain audit
copies; the deployer renders trusted packaged templates.

The service journal is a versioned JSON-lines operational stream with a 2 KiB
per-event bound. It records correlation IDs, stable codes, and stages without
target PIDs, commands, profile data, perf stderr, or local paths. See
[Troubleshooting](troubleshooting.md) and use `journalctl -u
perflens-collector.service --since today -o cat` for raw events.

After login-group changes, ordinary users can run `perflens status --project
/absolute/path/to/workspace` for one read-only readiness summary. When the
configuration, socket, and group checks pass, the command also authenticates a
bounded health response against the dedicated service UID and kernel peer
credentials. It does not run perf or write the spool. Generated
policies carry `policy_version = 1`; a missing field is treated as legacy
version 1, while unsupported versions are rejected before deployment and
Collector startup.

Request framing and collection duration have independent bounds. One
newline-delimited JSON request, including its newline, may occupy at most 64
KiB and must arrive completely within five seconds. `max_duration_seconds`
limits perf collection only and cannot expand this protocol timeout. An
incomplete slow connection receives a recoverable error and is closed so later
health and collection calls can proceed. On `SIGTERM` or `SIGINT`, the service
stops accepting connections, closes its listener, and removes the socket, so a
normal systemd stop cannot leave a false-ready socket behind.

Every accepted plan also leaves a hidden `.perflens-consumed-plan-…`
tombstone in the fixed spool. The Collector atomically creates and fsyncs this
empty mode-`0600` state before perf starts, so a failed collection or service
restart cannot make the same plan reusable. Later requests reclaim tombstones
older than `max_plan_ttl_seconds`. Status, archive, and prune operations verify
and skip valid tombstones without charging them to evidence quotas; altered
contents, ownership, modes, or links make the spool unsafe. Do not edit or
remove these files manually; request a new MCP plan when a retry is needed.

Long-running automatic collection is also bounded by `max_spool_bytes`,
`max_spool_artifacts`, and `min_free_bytes`. The defaults cap logical artifact
storage at 5 GiB and 500 files while reserving 2 GiB on the spool filesystem.
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
contains an unmanaged file, directory, symbolic link, another non-regular
entry, or a modified replay tombstone; the command does not follow or remove
it. A quota-short-circuited scan reports
`scan_complete = false`, so observed values are lower bounds.
In `paranoid3_helper` mode it inspects the actual private
`/var/lib/perflens-helper` spool; because an ordinary user cannot list that
directory, run this read-only command through `sudo` in advanced mode.

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
to independent storage, run `sudo perflens-admin verify-spool-archive --archive
/absolute/archive.zip`. Add `--verify-sources` to cross-check every source that
still exists; absent sources are reported and do not invalidate an intact
archive. This command never prunes evidence. If reclamation is intended, next
run `prune-archived-spool --dry-run`. Only after reviewing every planned name,
pass `--authorization I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE`.

The same commands support both privilege modes and derive the active spool from
the reviewed deployed policy. In `cap_perfmon` mode they require the Broker
directory, artifacts, and replay tombstones to match the dedicated `perflens`
identity. In `paranoid3_helper` mode they instead open only
`/var/lib/perflens-helper`, require the directory and tombstones to match
`root:perflens-internal`, and require published evidence to match
`root:perflens`. The manifest records the privilege mode and actual spool path,
so an archive from one mode cannot be verified or pruned as the other mode.

Pruning requires a root-managed archive and parent, verifies the ZIP, manifest,
archived bytes, and each source device/inode/size/mtime/owner/mode/SHA-256 before
any removal, then rechecks each source immediately before unlinking. The archive
is always preserved and repeated execution is idempotent. This is a human
administrator operation and must not be scheduled by an Agent.
Valid consumed-plan tombstones are verified, skipped, and preserved; they never
become ZIP members or prune targets.

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
after another restart. This command cannot change the authorized UID, fixed
spool, or privilege mode and never changes the unit, retained artifacts,
users/groups, sysctl, or capabilities. Candidate comments are preserved
verbatim. Identity, spool, or privilege-topology migration requires a reviewed
stopped-service administrator procedure.

`accept-collector` starts a fixed, self-owned CPU probe and separately verifies
hardware counting, fixed software counting, and `cpu-clock` sampling through
policy-bounded collections of at most five seconds each. It always cleans up
the probe, so users do not need to find a PID. It prints a concise Chinese pass
summary by default; `--json` emits the complete versioned acceptance artifact and
`--output` safely preserves it as a new file. It still requires
`--authorize-host-acceptance` because it is not a read-only health check. A host
with an unavailable hardware PMU passes only when software counting produces a
positive measured value and software sampling succeeds; the result then states
the reduced evidence boundary. The advanced
`verify-collector` command remains available for an explicitly authorized
existing PID. It is Chinese-first on success; automation must add `--json` for
the complete Collection Artifact, while `--output <new-file.json>` preserves it
safely.

When the active feature profile is `full_diagnostics`, the same fixed probe also creates bounded
sleep/wakeup and lock-contention activity. Acceptance then captures, deterministically analyzes,
and replay-verifies `sched`, `off_cpu`, and `lock` in order. Every mode must produce substantive
target evidence; an empty stream, missing mode, or conservation failure fails acceptance.
`partial` preserves boundary/loss limitations and is not presented as verification failure. The
packaged Trace Helper filters the authorized TGID/TIDs in kernel before userspace; PerfLens never
invokes or falls back to `perf -a` or equivalent all-CPU capture.

Production releases now ship separate `perflens` and `perflens-collector` DEBs.
They install offline and do not activate the service. Future RPM installers must
preserve the same boundaries: preserve administrator configuration, avoid
silently changing sysctl, and never grant `CAP_SYS_ADMIN` by default. Host-level
Collector plus a controlled Unix socket is preferred over a privileged container.
Only an explicit, risk-acknowledged `paranoid3_helper + full_diagnostics` selection adds the
bounded capability to the separate Trace Helper unit; it is not a package-install default.
Package completion may direct the administrator to `sudo perflens-admin setup`, but maintainer
scripts must never make that choice. Existing deployments remain CPU-only across the planned
profile migration unless an administrator explicitly opts in.

For upgrades, install the new wheel or system packages first, then run `sudo
perflens-admin upgrade --dry-run` and `sudo perflens-admin upgrade`. The command
reads only the fixed deployed policy, compares SHA-256 hashes of the current and
packaged units, and replaces only verified PerfLens-managed units. In
`paranoid3_helper` mode the Broker and Rust Helper units are upgraded and rolled
back together. If the candidate adds a Helper capability, the dry-run reports it
in `helper_capability_expansion`; the real update fails before writing until an
administrator adds `--acknowledge-privileged-helper-risk`. Policy and spool data
are preserved. A restart or health failure
restores every unit changed by that attempt before reloading the services. Run
ordinary-user `perflens accept-collector
--authorize-host-acceptance` again after every upgrade.

An existing `0.2.0` host upgraded to v0.3.0 remains `cpu_only`: package upgrade must not
create trace policy, activate the Trace Helper, or expand `allowed_modes`. After the normal CPU
acceptance, the administrator separately reviews and runs `switch-profile full_diagnostics`.
This migration rule overrides the fresh-install recommendation so upgrades never widen privilege
silently.

Planned `v0.4.0` adds native C/C++, Java, Python, and Go user-space lock adapters on top of full
diagnostics. The checked-in Runtime Lock public contracts are groundwork, not available adapters.
JDK, Go, async-profiler, and SystemTap remain optional external dependencies detected
with Chinese setup guidance; they are not downloaded or bundled in the two core DEBs. Projects
explicitly opt in with planned `perflens init --runtime-locks`, and `LD_PRELOAD`, JVM/JFR
attachment, pprof access, or probe deployment still requires explicit per-operation authorization.

For backward compatibility, a retained policy without `allow_software_fallback` is read as
`false`; package upgrade never silently expands its event policy. To opt in, review a candidate
policy that keeps all four fixed software events (including `task-clock`) in
`allowed_stat_events`, add `allow_software_fallback = true`, and apply it through the documented
`perflens-admin update-policy --dry-run` and update workflow. Until then, the Collector narrows an
MCP `auto` plan to hardware-only execution and discloses that policy boundary on successful
artifacts.

After deployment and verification, the Skill can confirm and launch one exact
in-project executable as the ordinary user. PerfLens obtains that new PID and
sends only a short-lived PID plan to the Collector. This enables natural
“optimize the current project” requests without giving workload commands to the
privileged service or requiring the user to discover a PID.

Before package removal, ordinary users first preview and run `perflens detach
--project <project>` for every configured project. This removes verified
selected-client MCP entries and unchanged managed project Skills while preserving
onboarding and evidence. Then run `sudo perflens-admin undeploy --dry-run`
and `sudo perflens-admin undeploy`. It removes only a verified managed unit while
preserving policy, collected artifacts, and the system identity. See the
[Chinese guide](deployment.zh-CN.md) for the complete lifecycle.
