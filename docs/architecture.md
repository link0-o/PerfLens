# Architecture

[简体中文](architecture.zh-CN.md) | English

```text
CLI / MCP boundary
 ↓
Application services ─→ Contract mapper ─→ bounded artifact writer
 ↓
ProfileAdapter/ProfileStream ─→ lightweight domain aggregation
Benchmark/Metric adapters      ─→ deterministic comparison
Symbol providers               ─→ verified source resolution
Manual collection service      ─→ bounded command runner ─→ system perf
Automatic PID plan ─→ Unix socket ─→ restricted Collector ─→ fixed spool
```

The domain layer uses frozen/slotted records, integer Frame IDs, and standard
library protocols. It imports neither Pydantic nor Typer. Format adapters own
streaming parsing and frame tables. The `perf.data` adapter delegates only to
`perf script`; the runner uses no shell and enforces executable, timeout, and
output limits. The application service owns lifecycle,
fingerprinting, metadata, and conversion to versioned boundary models.

Inputs are immutable. Output is written to a temporary sibling and atomically
replaced only after serialization and `fsync` complete.

Symbolization is another adapter boundary. `pyelftools` inspects ELF identity
and debug capabilities; it is not used as a custom high-throughput DWARF
symbolizer. A per-module LLVM or addr2line process resolves verified module
offsets in batches and is reused across queries. Cache keys contain Build ID,
module offset, and resolver version. Runtime addresses never substitute for a
missing relocation model.

The rule engine and evidence builder are deterministic. They can emit only
`candidate` classifications at L1/L2; an L4 verified improvement requires a
later A/B comparison and cannot be produced by symbol-name rules.

The MCP server and repository Skill are separate orchestration boundaries.
Neither is imported by the deterministic core and neither calls an LLM API.
MCP paths, writes, process execution, active collection, and PID attachment are
independently enforced server-side.

Active collection is isolated from read-only adapters. It accepts one exact
command or PID only after explicit authorization, runs absolute executables
without a shell or sudo, monitors output size while the process runs, kills the
whole child process group on timeout or overflow, and publishes to a new path
without overwriting. `perf stat` data goes to a dedicated Metric Adapter rather
than the stack ProfileAdapter hierarchy.

Automatic collection has a second privilege boundary. The MCP server creates a
short-lived, single-use plan bound to PID owner and process start time. The optional
Collector revalidates it using Unix peer credentials and an independent immutable
policy. It accepts no shell, arbitrary command, environment, output path, or
system-wide target. The MCP server and Skill remain unprivileged.
