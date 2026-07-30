# Limitations

Folded text cannot recover process, thread, CPU, event, DSO, address, timestamp,
or source information absent from that format. `perf script` and `perf.data`
can preserve those fields, but their completeness depends on the recording and
available symbols. Unknown data remains unknown. Results identify weighted
hotspots and call paths; they do not establish causality or elapsed time.

Exact aggregation is bounded. If configured cardinality limits are exceeded,
analysis fails with a recoverable resource-limit error; no approximation or
silent truncation is used.

PerfLens delegates `perf.data` decoding to the selected system `perf`. The
adapter is read-only and bounded, but cross-host profiles may still require a
matching perf version, DSOs, debug files, build IDs, or mount namespace data.
This development host has `perf_event_paranoid=3`, so live recording is not
part of the local acceptance evidence; adapter integration uses an executable
test double and real `perf script` syntax fixtures.

Symbolization requires a verified module offset and a matching module or debug
file. PerfLens does not guess PIE/ASLR relocation from a runtime address. The
LLVM provider is protocol-tested locally; the installed GNU addr2line fallback
is also exercised with PIE, shared-library, stripped, and separate-debug-file
fixtures.

Classification uses generic symbol/DSO rules. A match is always a low/medium
confidence candidate, never a confirmed root cause. On-CPU data cannot by
itself confirm wait time, I/O latency, allocation behavior, or correctness of a
proposed optimization.
