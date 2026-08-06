# PerfLens installation and first use

English | [简体中文](INSTALL.zh-CN.md)

Download `perflens-0.1.3-py3-none-any.whl` for the normal CLI/MCP installation. A wheel is an installable Python package: do not extract it. The extracted `perflens/` and `.dist-info/` directories are modules and metadata, not a graphical launcher.

On Debian 13 `amd64`, the recommended alternative is
`sudo apt install ./perflens_0.1.3-1_amd64.deb`. Add the exact-version
`perflens-collector_0.1.3-1_all.deb` only for automatic collection. Package
installation does not activate a privileged service. See
[Debian packages](docs/debian-packages.md).

Verify downloaded release files before installation. `--ignore-missing` allows
checking only the assets you downloaded, but each selected file must report
`OK`:

```bash
sha256sum --ignore-missing --check SHA256SUMS
gh attestation verify ./perflens-0.1.3-py3-none-any.whl \
  --repo link0-o/PerfLens \
  --signer-workflow link0-o/PerfLens/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

The second command requires GitHub CLI and verifies both the artifact digest
and the signing workflow identity. It also works for the DEBs, source archive,
Skill, SBOM, and `SHA256SUMS`. Do not install a file if either applicable check
fails. GitHub-generated `Source code` snapshots are not PerfLens build assets
and are outside this attestation set.

PerfLens requires Linux and Python 3.12 or 3.13. Install the wheel as an isolated tool:

```bash
cd ~/Downloads
pipx install ./perflens-0.1.3-py3-none-any.whl
# or
uv tool install ./perflens-0.1.3-py3-none-any.whl
```

Verify it and run the project-scoped onboarding command:

```bash
perflens --version
cd /absolute/path/to/project
perflens init
```

`init` activates only this project for Codex and Claude Code. It installs the
selected project Skills, creates or updates the marked PerfLens block in
`.codex/config.toml`, safely merges the Claude Code `.mcp.json`, and creates
`perflens-setup/` with standalone MCP configurations, a capability report,
bilingual next steps, and a versioned setup artifact. Other project settings
are preserved; conflicting user-managed PerfLens entries are never overwritten.
Use `--client codex`, `--client claude-code`, or `--read-only` to narrow the
activation. Projects that have not run `init` do not discover PerfLens. The
same setup directory is never overwritten implicitly. After a package upgrade
or when changing collection gates, use `perflens init --update`; it requires a
matching ownership artifact and refuses modified Skills or unverified MCP
entries. The managed setup directory is rebuilt, refuses unexpected user files,
and preserves existing staged Collector assets unless regeneration is explicit.
Detach a client before updating to a narrower client selection. The
advanced `setup` command remains available for generation-only and Collector
staging workflows. Setup never changes user-level Codex
configuration, invokes sudo, changes sysctl/capabilities, or starts the Collector.
When using a custom onboarding directory, pass the same `--setup-directory` to
init, update, and detach.
Its completion summary and generated guides include an exact `perflens status`
command bound to that output directory. Preserve `--setup-directory` whenever
`--output-directory` was used.

Default project collection allows `stat` and `record`, with MCP ceilings of 30
seconds, 99 Hz, 256 MiB, and a 120-second single-use plan lifetime. The Skill
typically starts near 10 seconds and adjusts to the workload. Existing-PID
attachment is off unless `--allow-existing-pid-attach` is supplied. Run
`perflens init --help` for repeatable mode and limit options.

Run `perflens status --project /absolute/path/to/project` for a read-only
Chinese-first summary of onboarding, MCP, Collector, group, socket, and perf
readiness. It does not sample a target or modify the host.

Human-facing help is Chinese-first too: use `perflens --help`, `perflens
<command> --help`, or `perflens-admin --help`. Stable English command and option
names remain compatible with existing scripts, while the help text explains
units, defaults, authorization, and resource boundaries.

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

The Skill normally requests about 10 seconds, adjusted to the workload; this is
not a fixed duration. The default MCP and Collector ceiling is 30 seconds. Run the deployment
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
repeat without `--dry-run` for every configured project. Detach removes verified
Codex and Claude Code MCP entries plus unchanged managed project Skills by
default. It preserves unrelated settings, onboarding directories, results, and
Collector data, and refuses user-modified or unverified content. Use
`--client codex|claude-code` to select one client, `--keep-skills` to retain
Skills, and `--setup-directory` for a non-default onboarding directory. A kept
Skill remains discoverable, so `--keep-skills` is not complete deactivation and
must not be used before narrowing a later `init --update` client selection.
After all projects are detached, uninstall a pipx installation with `pipx
uninstall perflens`. Review preserved project files separately, and use the
administrator `undeploy` workflow for a system Collector.
