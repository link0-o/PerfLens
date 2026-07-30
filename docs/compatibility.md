# Compatibility

| Component | Supported |
|---|---|
| Python | 3.12 and 3.13 |
| OS | Linux (primary); POSIX-compatible file semantics required |
| Architecture | x86_64; aarch64 tested when CI capacity exists |
| Input | FlameGraph folded stacks; supported `perf script` text; `perf.data` through system perf |
| perf | Linux perf with `script --ns -F`; tested locally with 6.12.90 |
| Artifact schema | 1.0 |

PerfLens does not parse `perf.data` directly. Binary compatibility is delegated
to the selected system `perf`; use a matching perf build when a profile cannot
be decoded. LLVM, elfutils, and MCP compatibility begins in later milestones.
