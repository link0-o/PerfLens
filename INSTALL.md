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

`setup` installs or recognizes the bundled Skill, safely creates or updates a
marked PerfLens block in the project's `.codex/config.toml`, and creates
`perflens-setup/` with a standalone MCP snippet, capability report, bilingual
next steps, and versioned setup artifact. Other project settings are preserved;
a conflicting user-managed PerfLens table is never overwritten. Use
`--skip-codex-config` for generation only. Setup never changes user-level Codex
configuration, invokes sudo, changes sysctl/capabilities, or starts the Collector.
Its completion summary and generated guides include an exact `perflens status`
command bound to that output directory. Preserve `--setup-directory` whenever
`--output-directory` was used.

Run `perflens status --project /absolute/path/to/project` for a read-only
Chinese-first summary of onboarding, MCP, Collector, group, socket, and perf
readiness. It does not sample a target or modify the host.

Command failures are Chinese-first by default and include a stable code, error
ID, bounded technical detail, and recovery action. Automation can preserve the
complete versioned `ErrorArtifact` and unchanged exit codes by placing the
global option before the subcommand (`perflens --json-errors <command> ...` or
`perflens-admin --json-errors <command> ...`) or by setting
`PERFLENS_JSON_ERRORS=1`.

After trusting the project, restart Codex and confirm the project configuration
with `codex mcp list`; no manual MCP block copy is needed by default. `status`
checks the active project file rather than treating the standalone snippet as
proof that MCP was configured. It also revalidates that the configured
`perflens-mcp` still exists, is executable, and satisfies the onboarding entry
point trust rules.

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
the same command once with `sudo` and without `--dry-run`. Copy the exact command
from the generated guide: setup safely detects native `/usr/bin` package entry
points, while wheel/source layouts target `/opt/perflens/bin`. A native install
missing the matching Collector package fails before files are generated and
explains the missing package. Use only a trusted system or administrator-controlled
copy. Deployment prints a Chinese summary by default,
including whether the dry run changed the host, the authenticated health result,
and the next action. Add `--json` for the complete versioned artifact.
See [Product deployment](docs/deployment.md) before installing those assets. A
blocked `perflens doctor` result does not prevent analysis of existing profiles.
`doctor` is Chinese-first; use `perflens doctor --json` for the versioned stdout
artifact or `--output <new-file.json>` to preserve it safely.
After deployment and a new login, check this specific bundle with `perflens
status --project /absolute/path/to/project --setup-directory
/absolute/path/to/project/perflens-collector-setup`; the Chinese summary prints
the next recovery or real-acceptance command.

After verification, a user may ask the Skill to optimize the current project.
The Skill confirms an exact executable and arguments; PerfLens launches it as
the ordinary MCP user, obtains that new PID internally, and submits only a
PID-bound plan to the Collector. The user does not need to discover a PID.

Automatic collection defaults to 10 seconds but is user-adjustable within the
MCP and Collector policy limits (30 seconds by default). Run the deployment
acceptance as the ordinary user with
`perflens accept-collector --authorize-host-acceptance`; its built-in probe
requires no PID, defaults to one second, and is capped at five seconds. It prints
a Chinese pass summary by default; add `--json` for the complete versioned artifact
or `--output ./collector-acceptance.json` to preserve it safely.

To tune collection policy without reinstalling, copy the deployed TOML to a
separate mode-`0600` candidate, run `perflens-admin update-policy --config
<candidate> --dry-run`, then repeat with `sudo`. It restarts, health-checks, and
rolls back on failure while preserving the authorized UID and fixed spool.

For long-term evidence retention, use the administrator archive-then-prune
workflow instead of deleting spool files by age. It creates a root-managed ZIP
with a versioned hash manifest and preserves sources. Use the read-only
`verify-spool-archive`, optionally with `--verify-sources`, before the separate
prune dry-run and explicit authorization required for exact-source removal.

For upgrades, install the new wheel or matching DEBs first, then run `sudo
perflens-admin upgrade --dry-run` and `sudo perflens-admin upgrade`. Policy and
spool evidence are preserved; rerun ordinary-user `accept-collector` afterward.

Before uninstalling, run `perflens detach --project <project> --dry-run` and then
repeat without `--dry-run` for every configured project. Detach removes only a
structurally verified PerfLens-managed block from project `.codex/config.toml`;
it preserves unrelated settings and refuses unmarked or mixed-content blocks.
It never deletes the Skill, onboarding directories, results, or Collector data.
After all projects are detached, uninstall a pipx installation with `pipx
uninstall perflens`. Review preserved project files separately, and use the
administrator `undeploy` workflow for a system Collector.
