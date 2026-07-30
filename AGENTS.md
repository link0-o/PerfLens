# Repository Goals

PerfLens is a general Linux performance-analysis toolkit.
It must not depend on any specific application, database, RPC framework,
or previous user project.

# Architecture Boundaries

- Keep deterministic analysis separate from LLM reasoning.
- Do not build a custom agent framework.
- Do not add an LLM API dependency in the MVP.
- Do not add a Web UI in the MVP.
- Do not directly parse perf.data binary formats.
- Use adapters for all external tools.
- Keep Pydantic and CLI dependencies outside hot-path domain code.

# Safety

- Never use `shell=True`.
- Validate and canonicalize every user-provided path.
- Keep read-only tools separate from process-execution tools.
- Never attach to a running process without explicit authorization.
- Never require root by default.
- Preserve bounded raw diagnostics when parsing fails.
- Never overwrite a source profile.

# Quality

- All public artifact models require `schema_version`.
- New parsers require fixtures and golden tests.
- New MCP tools require typed schemas and tests.
- Run lint, type checking, unit tests, integration tests, and package smoke tests.
- Do not enter the next milestone until current acceptance tests pass.
- Keep parsers streaming and diagnostics bounded.
- Do not special-case fixtures or expected symbols.
