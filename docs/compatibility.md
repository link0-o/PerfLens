# Compatibility

[简体中文](compatibility.zh-CN.md) | English

| Component | Supported |
|---|---|
| Python | 3.12 and 3.13 |
| OS | Linux (primary); POSIX-compatible file semantics required |
| Architecture | x86_64; aarch64 tested when CI capacity exists |
| Input | FlameGraph folded stacks; supported `perf script` text; `perf.data` through system perf; PerfLens/pyperf/Google Benchmark/hyperfine JSON |
| perf | Linux perf with `script --ns -F`; tests and manual acceptance cover the 6.12.x line, while cross-version profiles should use a perf build matching the producer |
| ELF/DWARF | ELF through pyelftools 0.33; LLVM JSON provider or GNU/elfutils addr2line fallback |
| Rules | Safe YAML; packaged generic, Linux, and C++ candidate rules |
| Reports | JSON evidence bundle and Markdown |
| MCP | Official Python SDK 2.x, local stdio transport |
| Skill | Project Skill for Codex/OpenCode/local Copilot `.agents/skills` and Claude Code `.claude/skills`, validated by `skill-creator` |
| AI client config | Codex `.codex/config.toml`; Claude Code/Copilot CLI `.mcp.json`; OpenCode `.opencode/opencode.json`; VS Code Copilot Agent `.vscode/mcp.json` |
| Active collection | Release `0.3.0` supports `record/stat` and adds opt-in `sched/off_cpu/lock` through a separate Trace Helper |
| Automatic collection | Host PID plus one explicitly authorized process in a local Docker Engine; ordinary-user orchestration and a `SO_PEERCRED`-authenticated Collector remain separate |
| Collector policy | Current version 1; `cpu_only` permits `record/stat`, while `full_diagnostics` additionally permits `sched/off_cpu/lock`; missing version is accepted as legacy version 1 and unsupported versions are rejected |
| paranoid=3 Helper | The existing Rust Helper remains permanently limited to `record/stat`; v0.3.0 uses another service/protocol/socket/spool for its Trace Helper |
| Target runtime | Linux host PID, or one explicit process in a local Linux Docker Engine with cgroup v2; no remote Engine, Docker Desktop VM, Compose, or whole-container aggregation |
| Native DEB | Debian 13 `amd64`, system Python 3.13; split exact-version Collector package |
| Runtime Lock (repository v0.4.0 prerelease) | Native pthread: Debian 12/13 amd64 + glibc 2.36/2.41; Java JFR: JDK 17/21/25; CPython: 3.12/3.13 including free-threaded detection; Go pprof: 1.24-1.27 |
| Runtime Lock target | Reviewed host launch, managed/optimization Docker launch, controlled import, or explicit same-UID loopback Go pprof; no arbitrary live injection |
| Artifact schema | Existing public artifacts 1.0; Docker project policy accepts strict 1.0/1.1; Runtime Lock Evidence reads strict 1.0/1.1 and new Adapters write 1.1 |

PerfLens does not parse `perf.data` directly. Binary compatibility is delegated
to the selected system `perf`; use a matching perf build when a profile cannot
be decoded. The GNU addr2line fallback is exercised against Binutils 2.44. The
LLVM JSON provider is protocol-tested because `llvm-symbolizer` is not installed
on the development host. MCP behavior is tested in memory with the official SDK client.

The Collector Broker integration is tested end-to-end with a real Unix socket and
an executable perf test double. Manual Debian 13 host acceptance also completed
short software `stat` and `cpu-clock record` collection through the
`paranoid3_helper` when the hardware PMU produced no usable counts. That is not
a compatibility claim for every kernel, VM, PMU, LSM, or advanced trace mode;
each `full_diagnostics` deployment requires its own short real-host acceptance.

Release v0.3.1 discovers processes in an existing local container or creates a fixed-policy managed
temporary test container, binds the container identity to the host PID, captures cgroup v2 context,
and maps bounded module/source evidence. Docker remains optional and external: PerfLens does not
install Docker, and the v0.3.1 path does not build/pull images. The opt-in v0.3.2 optimization
session can run only typed, recipe-bound builds after confirmation. Rootful UID-0 targets stay disabled until an administrator
explicitly enables the dedicated policy boundary. See the [Docker process guide](docker-container-roadmap.md)
for the complete compatibility and denial matrix.

The repository v0.4.0 prerelease exposes Runtime Lock capability discovery, content-bound
sessions, strict conversion/import, deterministic analysis, independent replay verification, and
the four Adapter families listed above. It is not a compatibility promise for published v0.3.2
packages. JDK and Go tools are optional external dependencies; the native DEB supplies the fixed
pthread probe and supervisor without activating them. Docker optimization can include one reviewed
Runtime Lock scope in its existing confirmation. See the
[Runtime Lock guide](runtime-locks.md) for backend and partial/unsupported boundaries.

Run `perflens status --project /absolute/path/to/project` for a read-only summary
of onboarding files, Skill, generated MCP configuration, Collector assets,
socket access, group membership, and host perf capability. A ready status means
the system is ready for an explicit real probe. Only a successful
`perflens accept-collector --authorize-host-acceptance` proves the current
host's bounded `stat`/`record` path, and its result remains limited by the
reported event source and evidence limitations. A v0.3.0 `full_diagnostics` host must separately
pass `sched/off_cpu/lock` acceptance; CPU-path success cannot prove advanced-mode availability.

The `opencode` onboarding target generates the current direct `mcp` server map. Existing legacy
nested `mcp.servers` JSON is recognized and updated or removed without changing layout. JSONC is
preserved for reviewed manual merge because lossless comment rewriting is not supported.
