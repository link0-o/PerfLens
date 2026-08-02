# PerfLens product deployment

English | [简体中文](deployment.zh-CN.md)

Deploy PerfLens as two privilege domains: ordinary-user CLI/MCP/Skill processes and a dedicated `perflens-collector` system service with only the host-approved perf capability. The Agent and MCP server must not run as root.

For the current wheel-based deployment:

1. install the Collector runtime outside user home, for example under `/opt/perflens`;
2. run `stage-collector-assets` with the real allowed UID, Collector command, and perf path;
3. have an administrator inspect and install the sysusers, TOML, and systemd files;
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

`verify-collector` performs a real, policy-bounded perf-stat collection of at most five seconds. It requires both documented authorization tokens and an explicitly selected PID; it is not a read-only health check.

Production releases should ship separate `perflens` and `perflens-collector` packages. DEB/RPM installers must be offline-reproducible, preserve administrator configuration on upgrade, avoid silently changing sysctl, and never grant `CAP_SYS_ADMIN` by default. Host-level Collector plus a controlled Unix socket is preferred over a privileged container.

See the [Chinese guide](deployment.zh-CN.md) for complete install, verification, MCP, upgrade, and uninstall commands.
