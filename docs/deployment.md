# PerfLens product deployment

English | [简体中文](deployment.zh-CN.md)

Deploy PerfLens as two privilege domains: ordinary-user CLI/MCP/Skill processes and a dedicated `perflens-collector` system service with only the host-approved perf capability. The Agent and MCP server must not run as root.

Ordinary users should complete [Installation and first use](../INSTALL.md) and run `perflens setup` first. This page focuses on administrator-managed Collector deployment.

For the current wheel-based deployment:

1. install the Collector runtime outside user home, for example under `/opt/perflens`;
2. run `stage-collector-assets` with the real allowed UID, Collector command, and perf path;
3. inspect the TOML and use the trusted `perflens-admin deploy` entry point;
4. add the authorized user to the `perflens` group and restart their login session;
5. review the host `perf_event_paranoid` policy;
6. run an explicitly authorized `verify-collector` probe against an owned test PID;
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

`verify-collector` performs a real, policy-bounded perf-stat collection of at most five seconds. It requires both documented authorization tokens and an explicitly selected PID; it is not a read-only health check.

Production releases should ship separate `perflens` and `perflens-collector` packages. DEB/RPM installers must be offline-reproducible, preserve administrator configuration on upgrade, avoid silently changing sysctl, and never grant `CAP_SYS_ADMIN` by default. Host-level Collector plus a controlled Unix socket is preferred over a privileged container.

After deployment and verification, the Skill can confirm and launch one exact
in-project executable as the ordinary user. PerfLens obtains that new PID and
sends only a short-lived PID plan to the Collector. This enables natural
“optimize the current project” requests without giving workload commands to the
privileged service or requiring the user to discover a PID.

See the [Chinese guide](deployment.zh-CN.md) for complete install, verification, MCP, upgrade, and uninstall commands.
