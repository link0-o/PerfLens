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
An ordinary MCP process is rejected by the kernel under
`perf_event_paranoid=3`; that does not prove an installed Collector is blocked.
Manual Debian 13 acceptance has completed software `stat` and `cpu-clock
record` through the `paranoid3_helper`, while correctly reporting that the
hardware PMU produced no usable counts. Automated coverage uses a real Unix
socket and executable perf test doubles for success and denial paths. This is
not a compatibility claim for every kernel, VM, PMU, LSM, or advanced trace
mode. PerfLens never requests sudo or changes perf security policy.

The privileged Collector accepts PID targets only. For a confirmed current-project
workload, an ordinary-user coordinator may launch one in-project executable, obtain
its PID internally, and submit the same PID-only plan. The Collector never receives
or launches that command. Interactive programs, arbitrary environments, system-wide
sampling, and daemonizing workloads without a foreground mode remain unsupported.
The Unix-socket plan/peer/policy/spool path is integration-tested with an executable
perf test double; each host still requires an administrator-approved
configuration and a real acceptance run by an authorized ordinary user.

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

Release `0.3.0` formally enables `stat` and `record` and offers the opt-in `full_diagnostics`
profile with a separate Trace Helper, target filtering, dedicated deterministic analysis, and
consistency verification for `sched`, `off_cpu`, and `lock`. Even after
verification, lost, truncated, boundary-censored, or unpaired evidence remains `partial`; a futex
is only a user-space-lock candidate, and owner or hold time is unavailable without genuine source
evidence. See the [Collector and user-space-lock roadmap](collector-capability-roadmap.md).

Release v0.3.1 Docker collection is limited to one explicit process in a local Linux Docker Engine
with cgroup v2. It does not silently expand into whole-container or multi-process aggregation,
remote Engines, Docker Desktop VMs, Compose, Kubernetes, automatic image build/pull, or arbitrary
Docker arguments. Existing-container sessions bind one concrete process incarnation; managed
temporary containers use only a local immutable image and a fixed project recipe. cgroup deltas
describe the whole container and must not be reported as target-process-exclusive values. Symbol
or source evidence becomes `partial` when the verified container root/module snapshot cannot be
preserved. See the [v0.3.1 Docker guide](docker-container-roadmap.md). The C/C++, Java, Python, and
Go user-space-lock adapters remain planned for v0.4.0; their public contract groundwork does not
make those adapters available.

The v0.3.2 release candidate adds an opt-in bounded optimization session with typed, recipe-bound
baseline/candidate builds. Preview does not build or pull, the session never accepts arbitrary
Docker options or source paths, and only an Artifact-verified matched A/B may claim a Verified
Improvement. Offline tiers accept only `RUN --network=none`; the administrator-network tier admits
only `none` or `default`. See [Known issues](known-issues.md) and the
[v0.3.2 optimization guide](docker-optimization-roadmap.md).
