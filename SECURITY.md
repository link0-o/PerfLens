# Security policy

## Supported versions

Only the latest released minor version receives security fixes during the
pre-1.0 period.

## Reporting

Report suspected vulnerabilities privately to the project maintainers. Do not
include profile data, source code, binary contents, credentials, or complete
local paths in public issues.

PerfLens runs locally, never requires root for supported Milestone 1 commands,
canonicalizes user paths, bounds input and diagnostic data, writes artifacts
atomically, and never invokes a shell.
