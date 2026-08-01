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
