# PerfLens installation and first use

English | [简体中文](INSTALL.zh-CN.md)

Download `perflens-0.1.0-py3-none-any.whl` for the normal CLI/MCP installation. A wheel is an installable Python package: do not extract it. The extracted `perflens/` and `.dist-info/` directories are modules and metadata, not a graphical launcher.

PerfLens requires Linux and Python 3.12 or 3.13. Install the wheel as an isolated tool:

```bash
cd ~/Downloads
pipx install ./perflens-0.1.0-py3-none-any.whl
# or
uv tool install ./perflens-0.1.0-py3-none-any.whl
```

Verify it and run the project-scoped onboarding command:

```bash
perflens --version
perflens setup --project /absolute/path/to/project
```

`setup` installs or recognizes the bundled Skill and creates `perflens-setup/` inside the selected project with a Codex MCP snippet, a read-only capability report, Chinese and English next steps, and a versioned setup artifact. It never invokes sudo, changes sysctl/capabilities, overwrites user Codex configuration, or starts the privileged Collector.

Copy the complete generated MCP block into `~/.codex/config.toml`, or into
the project's `.codex/config.toml` after trusting that project. Preserve any
existing configuration, restart Codex, and confirm it with `codex mcp list`.

Existing-profile analysis needs no Collector. To stage administrator-reviewed assets for authorized live-PID collection, use a new output directory:

```bash
perflens setup \
  --project /absolute/path/to/project \
  --output-directory perflens-collector-setup \
  --prepare-collector
```

See [Product deployment](docs/deployment.md) before installing those assets. A blocked `perflens doctor` result does not prevent analysis of existing profiles.

Automatic collection defaults to 10 seconds but is user-adjustable within the
MCP and Collector policy limits (30 seconds by default). The deployment
acceptance probe defaults to one second and is capped at five seconds.

Uninstall a pipx installation with `pipx uninstall perflens`. Project Skill files, setup output, Collector service state, and collected artifacts are deliberately not removed automatically.
