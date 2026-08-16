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
| Active collection | `record` and `stat` are supported; `sched`, `lock`, and `off_cpu` are disabled raw experimental entry points in `cap_perfmon` and lack dedicated deterministic analyzers |
| Automatic collection | Ordinary-user project launcher plus PID-only Linux Collector Broker using `SO_PEERCRED`; systemd template provided |
| Collector policy | Current version 1; generated policy permits only `record` and `stat`; missing version is accepted as legacy version 1 and unsupported versions are rejected |
| paranoid=3 Helper | `record` and `stat` only; protocol or policy rejects `sched`, `lock`, and `off_cpu` |
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

Run `perflens status --project /absolute/path/to/project` for a read-only summary
of onboarding files, Skill, generated MCP configuration, Collector assets,
socket access, group membership, and host perf capability. A ready status means
the system is ready for an explicit real probe. Only a successful
`perflens accept-collector --authorize-host-acceptance` proves the current
host's bounded `stat`/`record` path, and its result remains limited by the
reported event source and evidence limitations.
