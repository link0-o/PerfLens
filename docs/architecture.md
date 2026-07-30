# Architecture

```text
CLI
 ↓
Application service ─→ Contract mapper ─→ JSON artifact writer
 ↓
ProfileAdapter/ProfileStream
 ↓
Lightweight domain aggregation
```

The domain layer uses frozen/slotted records, integer Frame IDs, and standard
library protocols. It imports neither Pydantic nor Typer. The folded adapter
owns format parsing and a frame table. The application service owns lifecycle,
fingerprinting, metadata, and conversion to versioned boundary models.

Inputs are immutable. Output is written to a temporary sibling and atomically
replaced only after serialization and `fsync` complete.
