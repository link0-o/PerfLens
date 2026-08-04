# PerfLens installation and first use

English | [简体中文](INSTALL.zh-CN.md)

Download `perflens-0.1.1-py3-none-any.whl` for the normal CLI/MCP installation. A wheel is an installable Python package: do not extract it. The extracted `perflens/` and `.dist-info/` directories are modules and metadata, not a graphical launcher.

On Debian 13 `amd64`, the recommended alternative is
`sudo apt install ./perflens_0.1.1-1_amd64.deb`. Add the exact-version
`perflens-collector_0.1.1-1_all.deb` only for automatic collection. Package
installation does not activate a privileged service. See
[Debian packages](docs/debian-packages.md).

PerfLens requires Linux and Python 3.12 or 3.13. Install the wheel as an isolated tool:

```bash
cd ~/Downloads
pipx install ./perflens-0.1.1-py3-none-any.whl
# or
uv tool install ./perflens-0.1.1-py3-none-any.whl
```

Verify it and run the project-scoped onboarding command:

```bash
perflens --version
perflens setup --project /absolute/path/to/project
```

`setup` installs or recognizes the bundled Skill and creates `perflens-setup/` inside the selected project with a Codex MCP snippet, a read-only capability report, Chinese and English next steps, and a versioned setup artifact. It never invokes sudo, changes sysctl/capabilities, overwrites user Codex configuration, or starts the privileged Collector.

Run `perflens status --project /absolute/path/to/project` for a read-only
Chinese-first summary of onboarding, MCP, Collector, group, socket, and perf
readiness. It does not sample a target or modify the host.

Copy the complete generated MCP block into `~/.codex/config.toml`, or into
the project's `.codex/config.toml` after trusting that project. Preserve any
existing configuration, restart Codex, and confirm it with `codex mcp list`.

Existing-profile analysis needs no Collector. To stage administrator-reviewed assets for authorized live-PID collection, use a new output directory:

```bash
perflens setup \
  --project /absolute/path/to/project \
  --output-directory perflens-collector-setup \
  --prepare-collector \
  --automatic-collection
```

Review the generated policy, validate it with
`perflens-admin deploy --config <toml> --dry-run`, then have an administrator run
the same system-package command once with `sudo` and without `--dry-run`. Wheel
deployments use `/opt/perflens/bin/perflens-admin`. Use only a trusted system or
administrator-controlled copy.
See [Product deployment](docs/deployment.md) before installing those assets. A
blocked `perflens doctor` result does not prevent analysis of existing profiles.

After verification, a user may ask the Skill to optimize the current project.
The Skill confirms an exact executable and arguments; PerfLens launches it as
the ordinary MCP user, obtains that new PID internally, and submits only a
PID-bound plan to the Collector. The user does not need to discover a PID.

Automatic collection defaults to 10 seconds but is user-adjustable within the
MCP and Collector policy limits (30 seconds by default). Run the deployment
acceptance as the ordinary user with
`perflens accept-collector --authorize-host-acceptance`; its built-in probe
requires no PID, defaults to one second, and is capped at five seconds.

To tune collection policy without reinstalling, copy the deployed TOML to a
separate mode-`0600` candidate, run `perflens-admin update-policy --config
<candidate> --dry-run`, then repeat with `sudo`. It restarts, health-checks, and
rolls back on failure while preserving the authorized UID and fixed spool.

For long-term evidence retention, use the administrator archive-then-prune
workflow instead of deleting spool files by age. It creates a root-managed ZIP
with a versioned hash manifest, preserves sources, verifies both copies in dry
run, and requires a separate explicit authorization before exact-source removal.

For upgrades, install the new wheel or matching DEBs first, then run `sudo
perflens-admin upgrade --dry-run` and `sudo perflens-admin upgrade`. Policy and
spool evidence are preserved; rerun ordinary-user `accept-collector` afterward.

Uninstall a pipx installation with `pipx uninstall perflens`. Project Skill files, setup output, Collector service state, and collected artifacts are deliberately not removed automatically.
