# PerfLens Debian packages

[简体中文](debian-packages.zh-CN.md) | English

PerfLens publishes two role-separated native packages for Debian 13 `amd64`:

- `perflens_<version>-1_amd64.deb` contains the unprivileged CLI, MCP server,
  Skill, and hash-locked runtime dependencies;
- `perflens-collector_<version>-1_all.deb` adds the optional administrator and
  Collector entry points and depends on the exact same main-package version.

For offline profile analysis, install only the main package:

```bash
sudo apt install ./perflens_0.1.1-1_amd64.deb
perflens setup --project /absolute/path/to/project
```

For automatic collection, install both packages and generate a reviewed policy:

```bash
sudo apt install \
  ./perflens_0.1.1-1_amd64.deb \
  ./perflens-collector_0.1.1-1_all.deb

perflens setup \
  --project /absolute/path/to/project \
  --prepare-collector \
  --automatic-collection
```

Package installation never enables a service, writes `/etc/perflens`, changes
sysctl/capabilities, or grants user access. After reviewing the generated policy,
an administrator explicitly runs `sudo perflens-admin deploy --config <policy>`.
After the user's new login session, `perflens status --project <project>` checks
runtime readiness and `perflens-admin spool-status` reports Collector storage
headroom. Both are read-only; add `--json` to the latter for a versioned artifact.

Before package removal, use `sudo perflens-admin undeploy`. It verifies and removes
only a trusted PerfLens-managed unit. Policy, collected artifacts, and the system
identity are preserved by default. See the Chinese guide above for the full flow.

The main package vendors dependencies selected and hashed by `uv.lock`, so install
does not access the network. Native Python extensions make it architecture and ABI
specific; the current release target is Debian 13 `amd64` with system Python 3.13.
The build normalizes permissions and timestamps and is checked for byte-for-byte
reproducibility plus extracted-package command smoke tests.
