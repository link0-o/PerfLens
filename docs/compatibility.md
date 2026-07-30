# Compatibility

| Component | Supported |
|---|---|
| Python | 3.12 and 3.13 |
| OS | Linux (primary); POSIX-compatible file semantics required |
| Architecture | x86_64; aarch64 tested when CI capacity exists |
| Input | FlameGraph folded stacks; supported `perf script` text; `perf.data` through system perf |
| perf | Linux perf with `script --ns -F`; tested locally with 6.12.90 |
| ELF/DWARF | ELF through pyelftools 0.33; LLVM JSON provider or GNU/elfutils addr2line fallback |
| Rules | Safe YAML; packaged generic, Linux, and C++ candidate rules |
| Reports | JSON evidence bundle and Markdown |
| MCP | Official Python SDK 2.x, local stdio transport |
| Skill | Repository skill under `.agents/skills`, validated by `skill-creator` |
| Artifact schema | 1.0 |

PerfLens does not parse `perf.data` directly. Binary compatibility is delegated
to the selected system `perf`; use a matching perf build when a profile cannot
be decoded. The GNU addr2line fallback is exercised against Binutils 2.44. The
LLVM JSON provider is protocol-tested because `llvm-symbolizer` is not installed
on the development host. MCP behavior is tested in memory with the official SDK client.
