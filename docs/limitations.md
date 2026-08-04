# Limitations

[简体中文](limitations.zh-CN.md) | English

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
This development host has `perf_event_paranoid=3`, so real unprivileged active
collection is rejected by the kernel. The failure path is exercised with real
perf 6.12.90 and leaves no output; successful record/stat/sched/lock/off-CPU
integration uses an executable test double. PerfLens never requests sudo or
changes perf security policy.

The privileged Collector accepts PID targets only. For a confirmed current-project
workload, an ordinary-user coordinator may launch one in-project executable, obtain
its PID internally, and submit the same PID-only plan. The Collector never receives
or launches that command. Interactive programs, arbitrary environments, system-wide
sampling, and daemonizing workloads without a foreground mode remain unsupported.
The Unix-socket plan/peer/policy/spool path is integration-tested with an executable
perf test double; successful privileged sampling still requires an
administrator-approved host configuration and a real acceptance run.

Symbolization requires a verified module offset and a matching module or debug
file. PerfLens does not guess PIE/ASLR relocation from a runtime address. The
LLVM provider is protocol-tested locally; the installed GNU addr2line fallback
is also exercised with PIE, shared-library, stripped, and separate-debug-file
fixtures.

Classification uses generic symbol/DSO rules. A match is always a low/medium
confidence candidate, never a confirmed root cause. On-CPU data cannot by
itself confirm wait time, I/O latency, allocation behavior, or correctness of a
proposed optimization.

Profile comparisons describe relative selected-event distributions and do not
prove an absolute-time regression. Benchmark comparison uses an approximate
normal 95% interval for repeated means, a practical-impact threshold, and
environment checks; it does not claim a verified improvement without matched
correctness-preserving A/B evidence.

The `off_cpu` collector records `sched:sched_switch` stack evidence. It does
not yet reconstruct duration-attributed blocked intervals, so its output alone
cannot confirm off-CPU wait time.
