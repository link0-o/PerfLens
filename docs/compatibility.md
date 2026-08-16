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
| Skill | Project Skill for Codex `.agents/skills` and Claude Code `.claude/skills`, validated by `skill-creator` |
| AI client config | Codex project `.codex/config.toml`; Claude Code project `.mcp.json` |
| Active collection | Release `0.2.0` supports `record/stat`; pre-release v0.3.0 adds `sched/off_cpu/lock` through a separate Trace Helper and still awaits release gates |
| Automatic collection | Host-only today: ordinary-user launcher plus a host-PID-only Linux Collector Broker using `SO_PEERCRED`; systemd template provided |
| Collector policy | Current version 1; generated policy permits only `record` and `stat`; missing version is accepted as legacy version 1 and unsupported versions are rejected |
| paranoid=3 Helper | The existing Rust Helper remains permanently limited to `record/stat`; pre-release v0.3.0 uses another service/protocol/socket/spool for its Trace Helper |
| Target runtime | Current formal scope is a Linux host PID; one process in a local Docker Engine with cgroup v2 is planned for v0.3.1, not available today |
| Native DEB | Debian 13 `amd64`, system Python 3.13; split exact-version Collector package |
| Artifact schema | 1.0 |

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
there is no stable real-host claim for `sched`, `lock`, or `off_cpu` yet.

Current container compatibility means only container/build path mapping while analyzing an
existing profile. PerfLens does not yet discover Docker processes, launch containers, connect to a
remote Engine, or collect container cgroup context. v0.3.1 plans only a local Linux Docker Engine,
cgroup v2, and one explicit process, covering an existing container or a PerfLens-managed
temporary test container. See the [Docker process roadmap](docker-container-roadmap.md) for the
compatibility and denial matrix. C/C++, Java, Python, and Go user-space-lock adapters are planned
for v0.4.0.

Run `perflens status --project /absolute/path/to/project` for a read-only summary
of onboarding files, Skill, generated MCP configuration, Collector assets,
socket access, group membership, and host perf capability. A ready status means
the system is ready for an explicit real probe. Only a successful
`perflens accept-collector --authorize-host-acceptance` proves the current
host's bounded `stat`/`record` path, and its result remains limited by the
reported event source and evidence limitations. A v0.3.0 `full_diagnostics` host must separately
pass `sched/off_cpu/lock` acceptance; CPU-path success cannot prove advanced-mode availability.
