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
