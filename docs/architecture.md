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
Ordinary-user project launcher ─→ new PID ─┐
Automatic PID plan ─→ Unix socket ─→ restricted Collector ─→ fixed spool
Explicit admin deploy ─→ versioned TOML ─→ perflens-admin ─→ systemd
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
system-wide target. Before starting perf it also reserves against cumulative
spool bytes, artifact count, and a filesystem free-space floor. Exhaustion
denies the new collection without deleting old evidence. The MCP server and
Skill remain unprivileged.

Single-use semantics do not depend on process memory. Before perf starts, the
Collector locks the fixed spool and atomically creates a mode-`0600`, empty
consumed-plan tombstone, then syncs both file and directory. The tombstone
survives failed collection and service restart. Valid tombstones are excluded
from evidence quotas and archives, expire within the policy TTL bound, and any
unsafe tombstone makes collection and administrator evidence operations fail
closed.

For a confirmed current-project workload, an ordinary-user coordinator launches
one in-project executable, captures the new PID, and uses the same PID-plan path.
The Collector never receives or starts the workload command. `perflens-admin` is
an explicitly invoked administrator boundary that accepts a versioned data-only
policy; the MCP server, Skill, and Agent never invoke it.

The bounded Collector protocol has one state-producing operation: `collect_pid`
requires a short-lived, single-use plan bound to PID, UID, and process start
time. Its separate `health` operation is read-only, peer-authenticated, does not
run perf or write the spool, and is required by deploy/upgrade readiness checks.
The server authenticates the caller; the client verifies the responding PID/UID
with kernel `SO_PEERCRED`, and administrator readiness requires the dedicated
service UID. A socket pathname alone is never treated as a healthy service.

`perflens status` is a separate read-only diagnostic boundary. It summarizes
onboarding files, Skill, active project MCP configuration against the selected
setup, staged assets, socket access, current
login-group membership, and host perf conditions without sampling a target.
Project MCP readiness additionally requires the configured executable to pass
fresh existence, execute-permission, and trusted-entry-point validation.
After its configuration and access prerequisites pass, it also performs one
500 ms-bounded `health` round trip and requires the dedicated service UID plus
kernel `SO_PEERCRED` identity before reporting `ready_for_verification`.

Native Debian distribution preserves the same boundary: the main `perflens`
package exposes only ordinary-user CLI/MCP entry points, while the exact-version
`perflens-collector` package adds administrator and Collector entry points.
Neither package activates a service during installation. Explicit undeployment
removes only a trusted unit carrying the packaged management marker.

Native command entry points may share the private runtime launcher, but Codex
configuration and the systemd unit preserve the verified
`/usr/bin/perflens-mcp` and `/usr/bin/perflens-collector` pathnames so launcher
dispatch retains the requested identity. A symlink pathname is preserved only
when its direct parent and resolved target satisfy the corresponding ownership
and non-writable checks.
