# Troubleshooting

[简体中文](troubleshooting.zh-CN.md) | English

## Active perf collection is denied

PerfLens reports the bounded stderr from `perf` as `EXTERNAL_TOOL_FAILED`. Check `/proc/sys/kernel/perf_event_paranoid`, capabilities, container policy, and access to tracepoints outside PerfLens. The development host uses value `3`, which rejects unprivileged collection.

PerfLens never invokes sudo, changes sysctl, grants capabilities, mounts tracefs, or weakens host policy. Ask the system owner for an approved profile export or an explicitly configured profiling environment.

## Existing perf.data cannot be decoded

Use a `perf` build compatible with the recording host and pass its absolute path with `--perf-path`. If the binary container remains incompatible, export text on the source host with the documented field set and use `analyze-perf-script`. PerfLens does not parse the binary format directly.

## Symbols or source lines are missing

Check Build ID, matching DSOs, separate debug files, debug links, and container/build path mappings. Source resolution accepts a verified module-relative offset; it never guesses an ASLR or PIE base from a runtime address. Install `llvm-symbolizer` or `addr2line`, or keep unknown frames visible.

## MCP calls are denied

Confirm that every input and output lies under an `--allowed-root` and that the artifact root is inside one of those roots.

- JSON artifact creation needs `--allow-writes`.
- perf.data conversion and symbolizer processes need `--allow-process-execution`.
- live collection additionally needs `--allow-active-collection` and the exact per-call authorization phrase.
- PID attachment additionally needs `--allow-pid-attach` and its separate phrase.

Restart the MCP client after changing server configuration. Tool annotations are hints; these checks are independently enforced by the server.

## An output already exists

Analysis artifacts may be atomically replaced only when they are not the source profile. Active collection data and its metadata are stricter: they always require new paths and never overwrite existing files. Choose a new output name rather than deleting evidence automatically.

## Analysis is partial

Inspect parse statistics, bounded warnings, the sampled event, weight semantics, call-graph availability, unresolved symbols, and source metadata. Individual malformed records may yield a valid `partial` artifact. Structural limit violations, mixed event semantics, or untrusted relocation data fail instead of silently approximating.

## Benchmark comparison is inconclusive

Use at least three repetitions, retain raw values, match workload and environment, and set a practical-impact threshold. A single run, environment mismatch, or overlapping approximate interval remains `insufficient_data`, `not_comparable`, or `no_material_change`; it is never promoted to a verified regression or improvement.
