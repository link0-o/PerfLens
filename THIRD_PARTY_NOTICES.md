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

Development-only dependencies are recorded in `uv.lock`. Their licenses are
not incorporated into distributed runtime artifacts. FlameGraph folded stack
syntax is implemented as an interoperability format; no FlameGraph source code
is copied or distributed.
