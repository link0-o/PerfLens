# Third-party notices

PerfLens Milestone 0–1 uses the following direct Python dependencies:

| Component | Purpose | License |
|---|---|---|
| Pydantic | Versioned boundary validation and JSON Schema | MIT |
| Typer | Stable CLI entry point | MIT |
| Hatchling | PEP 517 package build backend | MIT |

Development-only dependencies are recorded in `uv.lock`. Their licenses are
not incorporated into distributed runtime artifacts. FlameGraph folded stack
syntax is implemented as an interoperability format; no FlameGraph source code
is copied or distributed.
