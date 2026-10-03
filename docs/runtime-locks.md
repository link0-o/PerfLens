# PerfLens v0.4.0 Runtime Lock workflow

[简体中文](runtime-locks.zh-CN.md) | English

Status: **implemented in v0.4.0; not part of v0.3.2 packages**.
The fixed-runtime host matrix and Docker single-confirmation path have passed functional
acceptance. Exact evidence, Native fixture overhead, local source/package gates, and remote
CI/publication are distinguished in the
[v0.4.0 readiness record](v0.4.0-release-readiness.md).

Runtime Lock is a deterministic evidence pipeline for language-level waiting and contention. It
does not treat every futex as a language lock, does not infer an owner or hold interval that the
source did not provide, and does not make sampled or cumulative profiles look like exact events.

## Enable a project

```bash
cd /absolute/path/to/project
perflens init --runtime-locks

# Combine it with the managed/optimization Docker policy when needed:
perflens init --docker --runtime-locks
```

Initialization writes `perflens-setup/runtime-locks.toml` and updates the project-local MCP and
Skill integration. It performs capability discovery only. It does not instrument or attach a
process, import evidence, start a workload, access pprof, or grant authority. `perflens init
--update` preserves the reviewed policy and does not enlarge adapters, target scopes, import roots,
or budgets.

The default policy bounds a session to six workloads, 1,200 active seconds, a 3,600-second hard
expiry, 64 MiB per raw/public artifact, 512 MiB total evidence, one concurrent Adapter, 30 seconds
per normal collection, and a three-second/20,000-event exact-mode ceiling. These values are
ceilings, not instructions to consume every run or Adapter.

## Authorization and evidence flow

The MCP workflow is:

```text
inspect_runtime_lock_capability
  -> preview_runtime_lock_session
  -> show the exact target, Adapter, semantics, payload, tools, paths, and budgets
  -> wait for one fresh user confirmation
  -> authorize_runtime_lock_session
  -> collect_runtime_lock_evidence
     -> verify_runtime_lock_analysis with the Run-bound Analysis + Verification IDs
  OR import_runtime_lock_evidence
     -> analyze_runtime_lock_evidence -> verify_runtime_lock_analysis
  -> bounded hotspot/call-path queries and optional comparison/diagnosis
  -> revoke_runtime_lock_session
```

Active collection creates its Run, Analysis, Verification, and private-source replay receipt as
one fail-closed pipeline. Reverification must pass both IDs retained by that Run so the stored
receipt is revalidated after private cleanup. Do not re-analyze the collected public Evidence as
if it were a fresh import: public Evidence alone cannot recreate a private-source receipt. Pass
the same Run-bound Verification ID when building an optional diagnosis bundle.

The successful standalone `collect_runtime_lock_evidence` reference exposes the immutable Run Finalization ID/content
digest and the settled Session Artifact ID/revision. Read that small Finalization Artifact and
verify that it reports `outcome=completed` and binds the returned Run before revoking the Session.
Revocation then creates a later terminal Session revision with `settlement_finalization_id=null`:
that field describes only whether this exact revision settled an operation and does not erase or
invalidate the preceding Run Finalization. Reports must use the collection-returned Finalization
ID instead of treating the terminal null as evidence that no marker exists. Evidence
`quality.status` and Run `quality_status` are separate contract layers and must be reported
separately.

Preview and authorization are content-bound to the project policy, target/workload identity,
Adapter payload and tools, measurement semantics, import roots, and budgets. Authorization is kept
in the current MCP process; persisted Artifacts contain only a receipt digest. An MCP permission
popup or client allowlist is categorical tool access, not consent to a resolved target.

Each host Adapter/workload still has its own exact Preview and Session. When the user explicitly
requests a bounded acceptance matrix, an Agent may create all independent Previews first, display
every child ID/hash and exact scope plus the planned collection settings, execution order,
aggregate ceilings, and failure policy, then wait once for one fresh confirmation covering that
whole displayed set. After that reply it must authorize every child immediately and collect them
sequentially. This is one human confirmation over several independent authorization calls, not an
atomic batch or a single Session. An expired/changed Preview or authorization failure stops the
batch; replacement Previews must all be displayed and freshly confirmed together. Client tool
permission prompts remain a separate client concern.

Capability inspection and Preview are read-only. They never permit an Agent to launch or
smoke-test the workload directly, even without profiler flags; only the authorized native
collection tool may start it.

The stable target model is deliberately narrow:

- a host workload launched under the reviewed Runtime Lock session;
- a PerfLens managed temporary container or Docker optimization baseline/candidate;
- controlled import from an authorized project-relative root;
- for Go only, an explicitly authorized same-UID local process whose literal-loopback pprof socket
  and PID identity can be bound.

PerfLens does not inject into an arbitrary running process or arbitrary existing container. Native,
CPython, and Java active collection is launch-time only. There is no live JVM attach or stable
eBPF/uprobe path in v0.4.0.

For host CPython, authorization binds the canonical interpreter, package bootstrap, and a
non-group-writable Runtime Home directory identity. The unprivileged supervisor receives those as
already-open descriptors and constructs its fixed `PYTHONHOME=/proc/self/fd/<n>` itself. This
supports safely installed relocatable CPython distributions without accepting an Agent-supplied
environment or falling back to pathname execution. A replaced or writable Runtime Home is
`unavailable`; controlled import and offline analysis remain usable.

For an independently installed target such as CPython 3.13 free-threaded, the MCP may stay on a
regular supported Python. An operator can set
`--runtime-lock-cpython-interpreter /absolute/path/to/python3.13t` at MCP startup.
The chosen file must be an absolute, non-symlink, trusted-owner executable with safe mode;
its Runtime Home must also pass the existing owner/mode check. A fixed `-I -S` stdlib query
runs through the hashed executable descriptor and binds the target version, ABI, free-threaded
state, interpreter bytes, and Runtime Home into the Adapter capability and Preview.
This startup option never executes a project workload and cannot be supplied per tool call.
Changing it requires a new MCP process and fresh Preview/authorization.

## Evidence semantics

Runtime Lock Evidence schema 1.1 represents OS threads, Java platform/virtual threads, Go
goroutines, and process aggregates. One Evidence Artifact has exactly one of these semantics:

- `exact`: visible events are exact within the bounded observation surface;
- `thresholded`: only events meeting the configured duration threshold are present;
- `sampled`: observations are sampled and are not exact contention counts;
- `cumulative`: a runtime Profile reports aggregates rather than an event log.

Different JFR thresholds and Go mutex/block profiles remain separate Evidence Artifacts. The
Analyzer aggregates by opaque lock ID, execution context, call path, wait result, and lock kind,
while preserving omitted counts and weights. A lock ID is stable only inside one Artifact and is
derived without exposing its source address. Exact owner and hold-time fields require genuine,
pairable source evidence.
JFR Evidence publishes `quality.lost_source_bytes`, including an explicit zero, because
`jdk.DataLoss.amount` is measured in bytes and must not be misrepresented as an event count.

Every public call-path frame sequence is normalized as root/caller to leaf/callee, independent of
the source runtime's native serialization order. For Go pprof, `profile_kind` is an exact Preview
field (`mutex` or `block`), is included in the content-bound authorization summary, must match the
collection request, and is persisted in the Run. A missing or different value is rejected before
the workload is launched.

The independent verifier replays conversion when the private source is available, validates source
and normalized digests, event pairing and time order, target/context isolation, pagination, and
count/time conservation. `partial` is a usable but explicitly limited quality result; it is never
automatically upgraded to a root cause or Verified Improvement.

## Adapter matrix

| Adapter | v0.4.0 boundary | Important limits |
|---|---|---|
| Native pthread | Debian 12/13 amd64, glibc 2.36/2.41, dynamically linked pthread mutex/rwlock/condition; launch-time fixed `LD_PRELOAD`; thresholded 1 us and bounded exact modes | Static/musl/setuid/file-cap targets, inline/custom atomics, spinlocks, and invisible fast paths are partial or unsupported; no live uprobe/eBPF |
| Java JFR | Target matrix JDK 17/21/25; launch-time JFR; fixed `balanced` 10 ms or `deep` 1 ms configuration; `JavaMonitorEnter`, `JavaMonitorWait`, `ThreadPark`, and metadata-discovered virtual-thread events | No live attach; the matching JDK `jfr print --json` performs bounded conversion; threshold omission is not “no wait”; absent acquire/release pairs forbid owner/hold claims; JDK 17/21/25 have real local functional evidence, with disclosed partial thread coverage in the JDK 17 Run |
| CPython threading | CPython 3.12/3.13 public `threading.Lock`, `RLock`, `Condition`, and `Semaphore`; ordinary-user launch bootstrap; thresholded 10 us and bounded exact modes | Does not impersonate every `_thread` or C-extension lock; GIL/internal/application locks stay separate; free-threaded 3.13 forbids traditional-GIL conclusions. A real 3.13.5 free-threaded host Run passed correctness and replay with declared partial public-threading visibility; it is not full release validation |
| Go pprof | Target matrix Go 1.24-1.27 fixed `go tool pprof -raw`; private file mutex/block profiles; same-UID literal-loopback host pprof when explicitly enabled | Docker defaults to the file backend and opens no network; PerfLens does not enable runtime profile rates or modify source; mutex/block remain separate cumulative Evidence without fabricated TID, owner, or lock object; the fixed Go 1.24.4/1.25.14/1.26.8/1.27.1 releases have matching raw Goldens and current-source Adapter capability `available`; other patch releases remain `partial` until separately reviewed. Cumulative Evidence stays `partial` even for available versions; fixed-Go rebuilt-package host functional acceptance passed; see the readiness record for Native fixture overhead and local/publication gates |
| Generic NDJSON | Strict schema 1.0/1.1 controlled import with bounded streaming and replay | Import source must declare its exact/thresholded/sampled/cumulative meaning, clocks, visibility, loss, owner and hold provenance; malformed, cross-target, out-of-order, or non-conserving input is rejected |

JDK, Go, async-profiler, DTrace/SystemTap, and other runtime tools are optional external
dependencies. PerfLens detects them; the two core DEBs do not download or bundle those runtimes.
The Java Adapter resolves `java` from the MCP server's `PATH`, then pins `java`, `jfr`, and the
runtime payload to that same trusted JDK root. Select JDK 17, 21, or 25 by starting the client with
the intended JDK first on `PATH`; `JAVA_HOME` alone does not select it. A project built for Java 17
can be captured with its JDK 17 runtime instead of being forced onto JDK 21. The fixed Temurin
17.0.20.1 host path passed; short-lived-thread coverage remains explicitly partial at the Run layer.
For active Go conversion, the Adapter requires a trusted root-owned go binary
and a prebuilt root-owned pprof executable at the Go tool directory reported
by go env GOTOOLDIR. Some Go archives omit the prebuilt tool. An administrator
must build it from the matching fixed Go source and install it with mode 0755.
PerfLens deliberately does not use go tool pprof's on-demand build or a
user-writable cache as an identity-pinned collection tool.
The main native DEB carries the fixed, root-owned, capability-free pthread probe and Runtime Lock
supervisor. Neither is activated by package installation.

After successful Java conversion, replay, publication, and identity-safe cleanup, the private JFR
recording and JSON transcript are removed. If conversion, replay, or safe cleanup instead ends as
`adapter_output_invalid`, PerfLens intentionally retains both bounded files as owner-only private
diagnostics. Their bytes are charged to the Session evidence budget and inventoried on MCP restart;
no public Evidence or successful Run is published from that failure. These hidden files are
diagnostic quarantine, not public Artifacts and not an unbounded leak. Operators must not archive
them as public evidence and should remove them only through a deliberate, identity-aware cleanup
after the owning MCP process has stopped.

## Docker optimization integration

In v0.4.0, a Docker optimization Preview may extend the v0.3.2 workflow
with one reviewed Runtime Lock Adapter and semantics. When it does, the one Docker optimization
confirmation also authorizes that bounded Runtime Lock scope; PerfLens does not create a second
hidden authorization. Runtime Lock budget is checked before container creation and charged only to
the same single-use workload lease. Published v0.3.2 packages cannot request this extension.

An embedded Run has `authorization_kind=docker_optimization`; its `docker_optimization_binding`
binds the charged parent Session, Build, Container Run, and Measurement. It does not create a
standalone host Run Finalization. Verify those content-bound artifacts and the later terminal
parent state. Page the immutable `session_artifact_id`, not `session_id`. Runtime Lock evidence
accounting conservatively charges the public Evidence and capture/raw/normalized representations,
in addition to the separate perf charge; it is not merely the captured NDJSON file size.

When `collect_docker_optimization_workload` omits `workload_timeout_seconds`, an embedded Runtime
Lock capture uses the selected semantics' authorized duration limit, capped at the ordinary
60-second default. Without Runtime Lock, the default remains 60 seconds. An explicitly supplied
timeout above the selected Runtime Lock window is rejected before a workload lease is issued.
The timeout is an upper bound on workload execution, not a promise to keep a shorter workload
running for the entire window.

`preview_docker_optimization_session` accepts an optional `runtime_lock_semantics` object that maps
each requested Adapter to one exact measurement semantics, for example
`{"native_pthread":"exact"}`. The selected binding and threshold are content-bound in the Preview.
Omitting the object preserves the policy-derived compatibility default; callers that require a
specific semantics should always provide it and verify the returned scope before confirmation.

Baseline and candidate comparisons bind the exact Build content digest, recipe, Builder/network
policy, platform, immutable context, Container Run and Measurement, runtime/tool/payload identity,
and resource comparison. A changed candidate image digest is valid Treatment only when the mutable
manifest changed under the same fixed environment. Runtime Lock evidence alone can produce a
candidate or `no_material_change`; final `verified_improvement` still requires the outer Docker A/B
correctness, Benchmark, perf-event-source, resource-transfer, and deterministic replay gates.

Any post-processing or persistence failure makes Runtime Lock unavailable for the parent session
and prevents misleading continuation. Identity replacement, policy/tool/payload changes, budget
exhaustion, revocation, or expiry fail closed and are not retried unchanged.

The parent `state` is the authorization state. `runtime_lock_status` is a retained projection of
the embedded Runtime Lock scope/result (`active`, `partial`, `unavailable`, or `exhausted`), not a
second authority flag. A terminal parent Artifact may therefore be `state=revoked` while retaining
`runtime_lock_status=active` from its last successful embedded result. Every operation rejects the
non-active parent state; reports must read both fields and must not describe the retained substatus
as live permission.

## Offline CLI

The CLI can handle controlled evidence without launching a target:

```bash
perflens import-runtime-lock-evidence \
  --input ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-evidence.json

perflens analyze-runtime-lock-evidence \
  --input ./runtime-lock-evidence.json \
  --output ./runtime-lock-analysis.json

perflens verify-runtime-lock-analysis \
  --analysis ./runtime-lock-analysis.json \
  --evidence ./runtime-lock-evidence.json \
  --source ./perflens-runtime-locks/input.ndjson \
  --output ./runtime-lock-verification.json
```

Outputs are append-only and redacted. They do not persist private raw paths, authorization tokens,
source contents, raw lock addresses, environment variables, or credentials.
