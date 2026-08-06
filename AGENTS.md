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
- Treat automatic collection as a plan -> policy -> broker -> artifact workflow.
- Keep the MCP server and Skill unprivileged; privilege belongs only to the optional Collector.
- Keep the CLI, MCP, Skill, deterministic analysis, policy planning, and public Collector Broker
  in Python. Implement the optional `paranoid=3` execution Helper as a small Rust binary; do not
  rewrite unrelated Python components in Rust.
- Keep the public Python Broker and the privileged Rust Helper as separate processes, Unix sockets,
  service users, policies, and systemd units. The Helper socket must never be exposed to ordinary
  client users.
- Support two explicit Collector privilege modes: the default `cap_perfmon` mode and the opt-in
  `paranoid3_helper` mode. Installing packages must not select or activate the latter automatically.

# Safety

- Never use `shell=True`.
- Validate and canonicalize every user-provided path.
- Keep read-only tools separate from process-execution tools.
- Never attach to a running process without explicit authorization.
- Never require root by default.
- Never let the Agent, Skill, or MCP server invoke sudo, modify sysctl/capabilities, or start a
  privileged Collector.
- Never run the Python Broker as root and never grant it `CAP_SYS_ADMIN`.
- Never run the Rust Helper with an unrestricted root capability set. Debian `paranoid=3`
  compatibility may grant only the capabilities explicitly required by the reviewed systemd unit,
  and only after an administrator selects `paranoid3_helper` and acknowledges the risk.
- The privileged Collector must accept typed PID plans only: no shell, arbitrary command,
  arbitrary environment, arbitrary output path, or system-wide target.
- The Rust Helper must independently revalidate peer UID, protocol version, request expiry,
  single-use identity, PID owner/start time, mode, event allowlist, duration, frequency, output
  limit, concurrency, and fixed spool policy. Trusting validation performed only by Python is a
  security defect.
- The Rust Helper may execute only the configured, root-owned absolute `perf` path. It must derive
  every argument and artifact name from validated typed fields, use `execve`/equivalent without a
  shell, accept no workload command, and never launch user code with Helper privileges.
- Keep unsafe Rust isolated, documented, and minimal. New `unsafe` blocks require a safety comment,
  focused tests, and review of the affected syscall and lifetime invariants.
- PerfLens may detect and explain `perf_event_paranoid`, but it must never modify sysctl. The
  installer may offer deployment choices, not silently weaken host policy.
- Authenticate local Collector peers, bind plans to PID owner/start time, make plans short-lived
  and single-use, enforce an independent immutable policy, and write only to a fixed spool.
- Never launch a user-provided workload with Collector privileges.
- Preserve bounded raw diagnostics when parsing fails.
- Never overwrite a source profile.

# Quality

- All public artifact models require `schema_version`.
- New parsers require fixtures and golden tests.
- New MCP tools require typed schemas and tests.
- New Collector protocol or policy fields require denial-path tests and an end-to-end Unix-socket
  integration test.
- The Python/Rust private protocol requires a checked-in JSON Schema, shared valid/invalid golden
  fixtures, strict unknown-field rejection on both sides, bounded frames, and cross-language
  conformance tests.
- Rust code must pass pinned stable `cargo fmt --check`, `cargo clippy --all-targets --all-features
  -- -D warnings`, `cargo test --locked`, and dependency/license audit in CI. Release builds use the
  checked-in `Cargo.lock`; ordinary Python wheel builds must not require a Rust toolchain.
- Privileged-mode changes require tests for unauthorized peer access, PID reuse, cross-UID denial,
  replay, expired plans, arbitrary fields/paths/commands, spool escape, limits, worker failure,
  deploy/upgrade/rollback/undeploy, and package non-activation.
- Run lint, type checking, unit tests, integration tests, and package smoke tests.
- Do not enter the next milestone until current acceptance tests pass.
- Keep parsers streaming and diagnostics bounded.
- Do not special-case fixtures or expected symbols.
