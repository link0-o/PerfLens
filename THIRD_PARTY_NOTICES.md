# Third-party notices

PerfLens uses the following direct Python dependencies:

| Component | Purpose | License |
|---|---|---|
| Pydantic | Versioned boundary validation and JSON Schema | MIT |
| Typer | Stable CLI entry point | MIT |
| Hatchling | PEP 517 package build backend | MIT |
| Jinja2 | Deterministic Markdown report templates | BSD-3-Clause |
| MCP Python SDK | Typed local stdio MCP server | MIT |
| pyelftools | ELF metadata and debug-section inspection | Public domain |
| PyYAML | Safe loading of candidate classification rules | MIT |

The architecture-specific Debian Collector package also contains one Rust Helper built from the
locked `Cargo.lock` graph:

| Component | Purpose | License |
|---|---|---|
| nix | Safe Unix socket, peer credential, signal, identity, and filesystem wrappers | MIT |
| serde / serde_json | Strict private Helper protocol serialization | MIT OR Apache-2.0 |
| sha2 | Streaming SHA-256 verification for Helper artifacts | MIT OR Apache-2.0 |

Transitive Rust components and accepted licenses are checked by `cargo deny`; published source
archives include `Cargo.lock` and `deny.toml` for exact review.

Development-only dependencies are recorded in `uv.lock`. Their licenses are
not incorporated into distributed runtime artifacts. FlameGraph folded stack
syntax is implemented as an interoperability format; no FlameGraph source code
is copied or distributed.
