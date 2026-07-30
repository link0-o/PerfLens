# Architecture

```text
CLI
 ↓
Application service ─→ Contract mapper ─→ JSON artifact writer
 ↓
ProfileAdapter/ProfileStream ─→ bounded command runner (perf.data only)
 ↓
Lightweight domain aggregation
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
