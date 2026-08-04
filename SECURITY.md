# Security policy

[简体中文](SECURITY.zh-CN.md) | English

## Supported versions

Only the latest released minor version receives security fixes during the
pre-1.0 period.

## Reporting

Report suspected vulnerabilities privately to the project maintainers. Do not
include profile data, source code, binary contents, credentials, or complete
local paths in public issues.

PerfLens runs locally, never requires root, canonicalizes user paths, bounds
input and diagnostic data, writes artifacts atomically, and never invokes a
shell. Active collection is disabled by default, requires explicit per-call
authorization, never overwrites an existing output, and adds independent
server gates for process execution, collection, and PID attachment. PerfLens
never invokes sudo or changes host perf/sysctl policy.

The optional automatic Collector is a separate privilege boundary. MCP creates
short-lived, single-use plans bound to PID identity; the Collector authenticates the
Unix peer, applies an independent policy, accepts PID targets only, and writes to a
fixed spool. It reserves against cumulative spool bytes, artifact count, and a
filesystem free-space floor without deleting existing evidence. Policy bypass,
cross-UID collection, command execution, spool escape, or quota bypass should be
reported as a security vulnerability.

Each Collector instance supports exactly one authorized ordinary UID. Adding
multiple callers to the shared `perflens` group would expose group-readable
profiles across users and is deliberately rejected.

## Build and release supply chain

External GitHub Actions are pinned to full commit SHAs and checkouts do not
persist credentials. CI and release-build jobs receive read-only repository
permission. The only `contents: write` job does not check out or run repository
code; it downloads the verified same-run bundle with a pinned official Action
and invokes `gh release create`. A regression test enforces these boundaries.
Dependabot proposes weekly Action-pin and uv-lock updates for review; it does
not auto-merge them. Published wheel and source distributions are independently
rebuilt with the source commit timestamp and must be byte-for-byte identical.
