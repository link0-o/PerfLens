# PerfLens Debian packages

[简体中文](debian-packages.zh-CN.md) | English

PerfLens publishes two role-separated native packages for Debian 13 `amd64`:

- `perflens_<version>-1_amd64.deb` contains the unprivileged CLI, MCP server,
  Skill, and hash-locked runtime dependencies;
- `perflens-collector_<version>-1_all.deb` adds the optional administrator and
  Collector entry points and depends on the exact same main-package version.

The root-managed `/usr/bin/perflens-mcp` and `/usr/bin/perflens-collector`
entry points link to the private runtime launcher. Onboarding and deployment
verify the links, targets, and parent directories, then preserve the entry-point
pathnames in Codex configuration or systemd so launcher dispatch retains the
MCP or Collector identity. Links in writable directories are rejected.

For offline profile analysis, install only the main package:

```bash
sudo apt install ./perflens_0.1.2-1_amd64.deb
cd /absolute/path/to/project
perflens init
```

For automatic collection, install both packages and generate a reviewed policy:

```bash
sudo apt install \
  ./perflens_0.1.2-1_amd64.deb \
  ./perflens-collector_0.1.2-1_all.deb

perflens setup \
  --project /absolute/path/to/project \
  --prepare-collector \
  --automatic-collection
```

`setup` validates the root-managed, non-writable native entry points and
automatically writes `/usr/bin/perflens-collector` into the unit and
`/usr/bin/perflens-admin` into both next-step guides. Users do not need to
select an installation layout. If the main native package is present without
its matching Collector package, setup stops before writing files and explains
which package is missing. `--collector-command` remains available for a
deliberately managed custom layout.

Package installation never enables a service, writes `/etc/perflens`, changes
sysctl/capabilities, or grants user access. After reviewing the generated policy,
an administrator explicitly runs `sudo perflens-admin deploy --config <policy>`.
The command prints a Chinese deployment summary by default and distinguishes a
read-only dry run from a completed authenticated deployment. Add `--json` for
the complete versioned artifact.
After the user's new login session, `perflens status --project <project>` checks
runtime readiness and `perflens-admin spool-status` reports Collector storage
headroom. Both are read-only; add `--json` to the latter for a versioned artifact.

To tune an existing policy, copy it to a mode-`0600` candidate and run
`perflens-admin update-policy --config ./collector.next.toml --dry-run`, then
repeat with `sudo` and without `--dry-run`. The command preserves the authorized
UID, fixed spool, unit, and evidence, and rolls back the policy if activation
fails.

For retention, use `archive-spool --dry-run` and `archive-spool` to create a
root-managed stored ZIP with a versioned hash manifest. Use the read-only
`verify-spool-archive`, optionally with `--verify-sources`, before reviewing
`prune-archived-spool --dry-run`; exact source deletion remains disabled until
the administrator supplies `I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE`.

To upgrade, install both matching new packages, run `sudo perflens-admin upgrade
--dry-run`, then `sudo perflens-admin upgrade`. This preserves the deployed policy
and spool, updates only a verified managed unit, restarts the new program, and
attempts to restore the old unit if activation fails. Repeat ordinary-user
`perflens accept-collector --authorize-host-acceptance` afterward.
For each still-enabled project, run `perflens init --update` after review to
refresh owned project MCP settings, onboarding, and unchanged Skills. Modified
or unverified project content is preserved and reported instead of overwritten.

Before package removal, preview and run `perflens detach --project <project>` for
every configured project, then use `sudo perflens-admin undeploy`. These remove
only verified Codex/Claude MCP entries, unchanged managed project Skills, and a
trusted managed unit. Policy, collected artifacts, onboarding files, and the
system identity are preserved. Use `--keep-skills` when Skill retention is
intentional. See the Chinese guide above for the full flow.

The main package vendors dependencies selected and hashed by `uv.lock`, so install
does not access the network. Native Python extensions make it architecture and ABI
specific; the current release target is Debian 13 `amd64` with system Python 3.13.
The build normalizes permissions and timestamps and is checked for byte-for-byte
reproducibility plus extracted-package command smoke tests.
