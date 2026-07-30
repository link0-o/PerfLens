# Build vs. reuse decisions

## Milestones 0–5

| Capability | Decision | Rationale and boundary |
|---|---|---|
| Boundary validation and JSON Schema | Reuse Pydantic 2 | Mature validation/schema behavior. Imported only by `perflens.contracts`, never by parsing or aggregation hot paths. MIT; replaceable at the contract mapper. |
| CLI | Reuse Typer | Stable typed CLI and help generation. Confined to `perflens.cli`. MIT; application services do not depend on it. |
| Packaging | Reuse Hatchling | Standards-based PEP 517 builds with small configuration surface. Build-time only. MIT. |
| Folded parsing | Build thin adapter | The standard is a small line-oriented interchange syntax. Pulling in a renderer would add unrelated code; no FlameGraph layout/rendering is reimplemented. |
| Hotspot aggregation | Build | Self/inclusive semantics, deterministic IDs, limits, and evidence-oriented output are PerfLens domain logic. |
| JSON serialization | Reuse Python stdlib | Deterministic `sort_keys` output needs no additional runtime dependency. |
| Testing | Reuse pytest and Hypothesis | Mature example and property testing. Development-only. |
| Lint/type/security | Reuse Ruff, Pyright, pip-audit | Mature, replaceable development tools with no Core imports. |
| ELF metadata | Reuse pyelftools | Reads ELF headers, notes, sections, Build IDs, and debug links. PerfLens does not implement ELF/DWARF parsing. |
| Address symbolization | Reuse LLVM symbolizer / addr2line | Long-lived Provider processes handle DWARF, demangling, and inline expansion. PerfLens owns only bounded protocol adaptation and caching. |
| Rule documents | Reuse PyYAML safe loader | Rules are data, validated into strict typed boundary models before regex compilation. |
| Markdown reports | Reuse Jinja2 | A deterministic packaged template renders evidence; it performs no reasoning. |
| MCP protocol | Reuse official MCP Python SDK 2.x | Added now for Milestone 6; MCP remains outside Analysis Core. |

No third-party implementation is copied. Runtime dependencies are version
bounded and locked in `uv.lock`. Dependency upgrades require schema and golden
tests before changing supported ranges.
