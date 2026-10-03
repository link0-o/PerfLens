# PerfLens known issues

[简体中文](known-issues.zh-CN.md) | English

This document records reproduced issues and their bounded workarounds, including
resolved issues. Do not weaken deployment safety checks to work around them.

The 2026-10-04 source-release closeout and current gate results are tracked in the
[v0.4.0 readiness record](v0.4.0-release-readiness.md). Dated candidate entries below retain their
original scope; they are not all open defects. The final dependency audit replaced PyJWT 2.13.0
with 2.15.1 in the lockfile and passed without advisory suppression. Docker embedded Runtime Lock
uses its charged parent binding, not a standalone host Run Finalization; absence of the latter
is not a publication failure.

Maintainers changing Collector, Helper, Gate, or Docker optimization state must also follow the
[v0.3.2 Docker optimization regression playbook](v0.3.2-regression-playbook.md). It turns the
2026-08-26 fixes into permanent ordering, invariants, forbidden shortcuts, and test gates.

## KI-2026-09-22: a fast perf exit could hide its buffered control ACK (resolved in candidate source)

- Affected scope: PID collection using perf's acknowledged control FD, including short-lived
  Collector-backed workloads.
- Symptom: a full-suite run and a repeated startup-diagnostic test intermittently reported that
  perf exited before collection readiness, even though the child had written its final `ack`.
- Root cause: the acknowledgement reader called `process.poll()` before reading the socket. If the
  child wrote the ACK and exited before the reader was scheduled, the kernel still held valid ACK
  bytes but the exit status won the race and those bytes were never consumed.
- Fix: the reader now drains the bounded socket first. It checks process exit only after a polling
  read times out; EOF, malformed ACK, missing ACK, and the shared handshake deadline retain their
  existing fail-closed behavior. A complete newline-terminated ACK read at the boundary is handled
  before deciding whether an incomplete response exceeded the deadline.
- Regression coverage: a deterministic test places an ACK in the socket after a child has already
  exited. The old implementation fails that test; the candidate passes it, the full 18-test
  collection file, and 50 consecutive executions of the formerly intermittent diagnostic case.
- Package status: the ACK-fix DEBs built on 2026-09-22 passed subsequent installed-host Native and
  Docker embedded Native functional acceptance. The old `/tmp` build directories have since expired;
  their Artifact IDs and package hashes remain in the readiness record. The later Docker
  timeout-default fix was absent from those DEBs; its separate rebuilt package passed on 2026-09-27.

## KI-2026-09-27: omitted Docker Runtime Lock timeout exceeded the authorized window (package-accepted)

- Affected scope: `collect_docker_optimization_workload` with an embedded Runtime Lock Adapter.
- Root cause: omitting `workload_timeout_seconds` selected the generic 60-second default even when
  the chosen exact or non-exact Runtime Lock window was shorter. The server correctly rejected
  that mismatch before issuing a workload lease.
- Fix: an omitted timeout now uses the selected window, capped at 60 seconds. The generic
  non-Runtime-Lock default remains 60 seconds; explicit over-limit values still fail before a
  lease. This changes no Preview, budget, or collection authority.
- Regression: in-memory MCP cases select exact Native/CPython and non-exact Java/Go bindings;
  omission reserves the bound 3 or 30 seconds, while explicit 60 seconds is denied without a
  workload attempt. The rebuilt package passed a fresh real-host Native exact and Docker embedded
  Native exact run with the Docker timeout omitted: complete Evidence, zero loss/truncation, and
  ten passed Verification checks on each path. Other Adapter defaults remain source-test evidence.

## Source-audit findings at `5a799ac` (2026-09-18; fixed in candidate source)

These three defects were reproduced with isolated fake workloads and temporary artifacts.
The initial audit changed documentation only. Subsequent candidate-source fixes now cover all
three defects with regression tests; `5a799ac` itself does not contain these fixes. Fresh installed
package acceptance remains separate from source-level regression results. Later rebuilt-package
acceptance confirmed native MCP injection, structured errors, and the bounded Docker path; the
positive paging path passed, while deliberate Artifact-corruption rejection remains source-test
evidence because the host acceptance did not tamper with installed evidence.

### Docker public Artifact paging skips content validation

- Affected scope: `read_artifact_page` admits eight Docker Build/optimization types that are
  missing from the validated snapshot dispatch in `ArtifactStore.read_page`: capability, recipe,
  context, Preview, Session, Build, Iteration, and Disposition. `container-target` is already on
  the validated path and is not affected by this omission.
- Reproduction: change `DockerBuildArtifact.image_size_bytes` without changing `content_sha256`.
  The typed Build loader rejects the digest mismatch, but the MCP paging tool returns the changed
  value successfully. All eight types also accept a stored document with the wrong model schema.
- Impact: an Agent reading an altered or corrupted artifact through paging does not receive the
  integrity failure that typed consumers receive. This is an evidence-integrity gap, not a
  demonstrated privilege escalation or automatic authorization expansion.
- Fix: all eight types now validate their schema, embedded ID, and content digest on the same byte
  snapshot returned by paging. Iteration and Disposition reuse their typed loaders' cross-artifact
  replay checks without reopening the requested file. Regressions cover valid reads, wrong schemas,
  swapped IDs, digest corruption, linked Build corruption, and replacement after the snapshot read.
  A page read is still not evidence of performance improvement or a substitute for analysis replay.

### Outer Docker optimization accounting still includes setup and finalization

- Affected scope: `collect_docker_optimization_workload` success and failure settlement. Its
  timer starts before internal session authorization and ends after managed collection returns.
  The inner managed-session timer was repaired; the outer session does not reuse that result.
- Reproduction: a fake 1.25-second active workload with three seconds of setup and five seconds
  of finalization, under a 30-second reservation, charges two seconds internally but ten seconds
  to the parent optimization session. No real workload is needed to reproduce it.
- Impact: the parent active-time budget can be exhausted early. Capping whole-call time at the
  reservation prevents one overrun error but does not make the accounting correct.
- Fix: the inner managed collector records its Gate-relative charge for the parent before
  settlement, including failure paths; the outer session no longer uses a whole-call timer.
  Regressions cover success, pre-release/authorization failure (zero active seconds but one
  charged attempt), post-release/post-exit failure, and timeout capped at the existing reservation.
  Failures still stop the session, and temporary accounting state is removed after each call.
  The successful three-second real-host case alone cannot distinguish the old and new formulas.

### MCP tool failures discard structured domain error fields

- Affected scope: `PerfLensError` exceptions escaping a tool registered by `create_server`.
  `PerfLensError.__str__` returns only the message; without a PerfLens transport adapter, the
  installed MCP SDK wraps that string as a tool error.
- Reproduction: a synthetic optimization failure after lease issuance retains its stage,
  charged-attempt flag, no-retry flag, and suggested actions in the domain exception. Through
  the real in-memory MCP client the result is `is_error=true`, `structured_content=None`, and
  message text only. This is reproducible without Claude Code, not merely a client display issue.
- Impact: clients cannot reliably report the exact failure stage or recover the structured
  accounting/recovery instructions from that response. Backend denial and charged-attempt
  enforcement remain intact.
- Fix: a transport adapter now returns the versioned `ErrorArtifact` as both structured content
  and JSON text with `is_error=true`, preserving the error ID, code, stage, recovery flags, bounded
  actions, and allowlisted scalar details. Private diagnostics are omitted and truncation is
  disclosed. Real MCP client tests cover every domain error code, unchanged success schemas,
  charged/no-retry fields, output bounds, and unchanged cancellation/SDK-error behavior.
  See [MCP error responses](mcp-and-skill.md#mcp-error-responses). A failed authorized call still
  requires stopping; missing retry metadata is never permission to retry or change evidence mode.

## KI-2026-09-22: post-exit publication latency could exhaust a managed Docker deadline (resolved and package-accepted)

- Affected scope: a short managed Docker workload, especially an exact Runtime Lock capture whose
  `workload_timeout_seconds` equals its evidence window.
- Symptom: the identity-pinned cgroup monitor can observe that the container has already ended,
  while Collector result publication and module capture finish only after the authorized deadline.
  The server then rejects the run before Docker exit-status confirmation, or charges the
  post-exit tail to the parent optimization session. A later plain-`stat` acceptance charged four
  seconds for a benchmark whose own window and cgroup CPU use were both about two seconds; that
  charge did not prove that the workload itself needed more than the three-second exact window.
- Root cause: the monitor retained only a Boolean lifecycle-removal marker. The MCP path therefore
  had no trusted exit timestamp until `docker container wait` returned, even though cgroup removal
  had already proved that the identity-bound target could no longer execute.
- Fix: the monitor now records the first monotonic timestamp at which the pinned cgroup path is
  verified removed. The server validates that timestamp against Gate release, current monotonic
  time, and the authorized workload deadline, uses it for both inner and parent accounting, and
  derives the persisted wall-clock finish from the same interval. Once target exit is proven,
  Docker receives a separate bounded 15-second administrative window only to publish the exit
  status. Without that proof, the original precise remaining workload deadline still applies.
- Safety boundary: this does not extend workload execution authority. A missing timestamp keeps
  the strict old path; a non-finite, out-of-order, future, or post-deadline observation fails
  closed. The observation comes only from the already identity-pinned cgroup reader, and the
  administrative window cannot run user workload code.
- Regression coverage: unit tests cover final-read and background removal timestamps, absent and
  invalid observations, post-deadline exit, the unchanged fallback deadline, parent accounting,
  and the MCP managed-workload branch that uses the post-exit confirmation window.
- Installed-package acceptance: on 2026-09-22, Container Run
  `container-run-8aea9a2a463c237d5692` exited zero and was removed. Embedded Runtime Lock Run
  `runtime-lock-run-5cfa2d491c9f0a11bf31` completed within the exact three-second workload and
  three-second evidence bounds, with 7,808 events, zero loss/truncation, and a verified ten-check
  private-source replay. Parent Session `docker-optimization-session-20383e2d45920e51fa9c`
  charged three workload-active seconds and three Runtime Lock seconds before explicit revocation.

## KI-2026-09-19: Claude Code stdio negotiation intermittently omitted all tools (resolved and package-accepted)

- Affected scope: local stdio clients that first send a 2026-07-28 `server/discover` probe and then
  fall back to the legacy `initialize` handshake on the same server process. The failure was
  reproduced with Claude Code 2.1.276 and 2.1.278; successful connections from the same version
  made the defect intermittent.
- Symptom: the session contains no `mcp__perflens__*` tools and no project-bound `perflens-mcp`
  child. The server log reports MCP error `-32022`: the connection is already serving 2026-07-28
  and will not accept `initialize`. A separate `claude mcp list` probe can still report Connected,
  because it starts a different short-lived connection.
- Root cause: MCP SDK 2 selects the connection era from the first request. Once the modern discovery
  envelope selects 2026-07-28, a later legacy handshake is correctly rejected. Project trust state
  observed after that failure is not sufficient evidence that trust caused the missing tools.
- Fix: the PerfLens stdio boundary now presents only an opening enveloped `server/discover` as an
  unsupported legacy method probe. The client receives method-not-found and can complete its
  fallback handshake on the same process. Other opening requests are untouched, so a client that
  starts directly with a 2026-07-28 tool request retains the modern path. HTTP transports are not
  changed.
- Safety boundary: negotiation does not authorize a tool, persist an authorization, widen a path,
  or change Docker/Runtime Lock policy. Missing native tools remains a hard stop; shell-launched
  replacement servers and custom JSON-RPC bridges remain forbidden.
- Regression coverage: a real subprocess stdio client in `auto` mode negotiates 2025-11-25 after
  discovery fallback and lists the Runtime Lock/paging tools; a version-pinned 2026-07-28 client
  lists the same tools without downgrade. Fresh rebuilt-package Claude Code acceptance on
  2026-09-20 and 2026-09-22 loaded the project-bound native tools; this release blocker is closed.

## KI-2026-09-15: Benchmark capture rejected its own managed scratch layout (resolved)

- Affected scope: a managed Docker workload with `benchmark_output`, including Docker
  optimization sessions that also capture Runtime Lock Evidence.
- Symptom: the workload exits successfully and the Broker can persist a complete Collection, but
  finalization fails with `Managed Docker scratch root identity or permissions are unsafe` before
  the Container Run, Benchmark, Measurement, and Docker Runtime Lock Run are published.
- Root cause: the managed coordinator, Docker mount validator, and Runtime Lock capture contract
  all create and require an exact `0733` scratch leaf beneath a private `0700` per-run directory.
  The older Benchmark reader independently required the leaf itself to be `0700`, making every
  real managed Benchmark path reject the directory created by PerfLens.
- Fix: Benchmark capture now validates the same two-level layout: invoking-user ownership and
  exact `0700` mode on the enclosing run directory, plus invoking-user ownership and exact `0733`
  mode on the scratch leaf. The output owner is independently bound to the verified container
  target's host UID, which also preserves mapped-UID support.
- Safety boundary: no created directory became more permissive. Output remains a canonical,
  non-symlink regular file with one link, bounded size, stable identity, the exact target owner,
  and no group/other write bits. The workload lease remains charged and non-retryable on any
  failure.
- Regression coverage: the real `0700`/`0733` layout succeeds; a `0700` scratch leaf, a non-private
  parent, or an output-owner mismatch fails closed; the MCP server passes the verified target host
  UID into Benchmark capture.

## KI-2026-09-15: managed wait and inner-session time accounting (resolved)

- Affected scope: managed Docker collection, including a Docker optimization Preview that also
  binds Runtime Lock, when the fixed workload duration is close to
  `workload_timeout_seconds`.
- Symptoms: the Collector can publish a complete short `stat` Collection after releasing the
  Gate, but the following container wait can fail with `External tool exceeded its execution
  timeout`. After that deadline was corrected, a later real-host run reached Docker wait,
  Runtime Lock capture, Benchmark capture, resource capture, and cleanup, then failed settlement
  with `Docker run exceeded its reserved resource budget`.
- Root cause: two clocks still used the whole tool call. The original wait deadline rounded
  container setup plus collection up to an integer second before subtracting it from the workload
  timeout. The internal managed-session settlement independently rounded setup, workload, and
  post-exit finalization together, so a valid three-second lease could be charged more than three
  seconds even after the workload had exited.
- Fix: the workload deadline now starts immediately before the authenticated Gate release. The
  Collector observation interval still consumes that workload window, but pre-release setup does
  not. The Docker wait receives the precise fractional remainder, and a real expiry is reported as
  a `docker_workload` / `container_wait` failure. Inner managed-session settlement records the
  workload-exit monotonic timestamp and charges only the Gate-to-exit interval; setup and post-exit
  Benchmark/Runtime Lock finalization are excluded, and integer rounding cannot exceed the already
  reserved lease.
- Safety boundary: this does not enlarge the authorized duration or add an automatic retry. A
  separate precise Docker-wait deadline still enforces the authorized duration. A failure after
  lease issuance remains charged and ends the optimization workflow exactly as before.
- Regression coverage: tests preserve a `1.959`-second remainder after `1.041` seconds of a
  three-second Gate-relative window, pass that fractional value through the managed coordinator,
  reject non-finite/out-of-range values, retain the typed Docker-wait timeout stage, exclude a
  long post-exit finalization interval from accounting, and cap an in-flight failure at its
  reserved integer lease.

The original fix applied to the wait deadline and inner managed session only. The subsequent
source-audit fix described above extends consistent accounting to the outer optimization session.

## KI-2026-08-26: the automatic PMU probe could release a fast Docker workload (resolved)

- Affected scope: managed Docker `stat`/`record` with `event_source=auto`, especially an A/B pair
  whose optimized candidate exits much faster than its baseline.
- Symptom: the slower baseline can collect successfully, while the faster candidate repeatedly
  fails the formal profile's disabled-event binding handshake. The failed calls still consume
  workload-run budget because the lease is reserved before container startup.
- Root cause: the short hardware-availability probe received the same Gate-ready callback as the
  selected formal profile. It therefore released PID 1 during the probe. A slow baseline remained
  alive long enough for the formal fallback profile to attach; a fast candidate could exit first.
- Fix: both Collector implementations keep the package Gate blocked throughout the PMU probe.
  Only the selected formal hardware/software profile may report readiness. Because the blocked
  Gate legitimately executes no user work, a zero count remains insufficient even when perf
  reports scheduling runtime: it cannot prove that a virtual PMU will produce useful evidence.
  `auto` therefore falls back conservatively; explicit `hardware_required` remains available when
  hardware evidence is mandatory.
- Failure semantics: any optimization collection failure after workload-lease issuance charges
  exactly one attempt, releases unused time/evidence reservations, and blocks additional build or
  collection operations in that Session. A validation rejection before lease issuance is not
  charged but remains non-repeatable unchanged. Neither case can consume the build/test retry or
  switch evidence mode. If a candidate
  already exists but no A/B Iteration could be created, the typed finalizer records a
  `not_evaluated` retain/restore Disposition instead of accepting a Build ID as an Iteration ID.
- Regression coverage: Python and Rust prove that the probe produces no ready notification, a
  scheduled zero probe remains insufficient, the formal profile releases Gate once,
  failed attempts are charged, unchanged retries are rejected, and an unevaluated candidate can be
  retained only with fresh explicit consent.

## KI-2026-08-26: perf readiness could fail intermittently after the control-command fix (resolved)

- Affected scope: PID `stat` and `record` readiness through either Collector privilege mode. The
  Rust Helper used one fixed five-second ACK read, while the Python `cap_perfmon` runner waited for
  the control callback before draining perf's bounded diagnostics.
- Symptom: a Docker optimization baseline could build correctly, then fail before Gate release with
  a disabled-event binding-handshake error; an unchanged retry could later pass. No workload or
  Collection evidence was released by the failed attempt.
- Causes: slow but live perf startup was indistinguishable from early child exit, control-channel
  closure, or an invalid ACK. The Python path could additionally back-pressure a verbose perf child
  on its stderr pipe. Finally, `event_source=auto` could treat a generic control failure as a PMU
  execution failure and attempt software fallback, obscuring the infrastructure fault.
- Fix: `disable → identity revalidation → enable` now shares one eight-second, liveness-aware
  startup deadline in Python and Rust. The Python runner drains bounded stdout/stderr while the
  control callback is pending. Live deadline expiry returns `EXTERNAL_TOOL_TIMEOUT`; early exit,
  channel closure, and malformed ACK remain distinct `EXTERNAL_TOOL_FAILED` failures, all at the
  `perf_control` stage. Control-stage failures are never reclassified as PMU fallback and never
  release the workload Gate. A later bounded-shutdown control failure retains the same stage and
  likewise cannot trigger a software re-collection.
- Regression coverage: a live startup beyond the former five-second guess succeeds; diagnostic
  pipe pressure cannot deadlock readiness; the two control phases cannot each claim a fresh
  timeout; child/control failure is attempted once and produces no readiness notification or
  software fallback.

This repair does not add an automatic retry. A real control failure still consumes the authorized
attempt, stops before workload release, and must be reported with its precise stage. Deploy matching
main and Collector packages, restart the services, and perform a fresh authorized acceptance.

## KI-2026-08-26: unsupported perf control ping blocked PID collection (resolved)

- Affected scope: PID `stat` and `record` collection through either the Python `cap_perfmon`
  Collector or the privileged Rust Helper when the installed perf does not implement an
  undocumented `ping` control command.
- Symptom: Docker optimization can build its baseline, but its first collection fails before the
  Gate releases the workload. The privileged path reports
  `Privileged perf did not complete its disabled-event binding handshake`; no Collection evidence
  is published.
- Cause: current perf documents `enable` and `disable` for both `stat --control` and
  `record --control`, but PerfLens sent `ping` as its initial non-enabling barrier. Test doubles
  incorrectly accepted that unsupported command, hiding the real-tool incompatibility.
- Fix: perf still starts with `-D -1`, then PerfLens sends an idempotent `disable` and requires its
  bounded ACK. Only after that barrier does it revalidate the PID/UID/start time and container
  identity, send `enable`, and release the workload. Invalid ACKs, timeouts, identity changes, and
  extra frames continue to fail closed.
- Regression coverage: Python and Rust test doubles now accept only the documented
  `disable → enable` sequence, including Linux perf's NUL-delimited ACK framing and the
  identity-change rejection before enable.

This was a perf control-command compatibility defect, not a Docker authorization, image,
Benchmark, `perf_event_paranoid`, or PMU fallback failure. Deploy matching repaired main and
Collector packages and restart the managed services; do not bypass the Broker or weaken host
policy.

## KI-2026-08-26: `local_only` did not reject every per-`RUN` network override (resolved)

- Affected scope: v0.3.2 Docker optimization with `network_tier = "local_only"` or
  `pinned_pull` and a Dockerfile containing an explicit `RUN --network=default` (or another
  non-`none` per-instruction value).
- Expected boundary: after any allowed pinned pull, the build itself has no network.
- Fix: Dockerfile validation now rejects malformed and unrecognized per-`RUN` overrides. The
  `local_only` and `pinned_pull` tiers admit only `RUN --network=none`; the administrator-pinned
  network tier admits only `none` or `default`. The outer Buildx network remains independently
  derived from the authorized tier.
- Regression coverage: offline-tier rejection includes `default`, `host`, and custom values;
  pinned offline and administrator-network positive paths are also exercised.

## KI-2026-08-26: Claude Code and Copilot could not be selected together atomically (resolved)

- Scope: one `perflens init` or saved client default containing both `claude-code` and `copilot`.
- Cause: Claude Code and Copilot CLI both use the project `.mcp.json`, while onboarding prepared
  two independent update plans from the same pre-update identity.
- Fix: onboarding now requires identical generated and recorded ownership copies, creates one
  atomic shared plan, applies it once, and records both clients. Detach preserves the shared entry
  while either client remains and removes it once when both are selected for removal.

## KI-2026-08-26: group-write validation assumed a private same-numbered group (resolved)

- Scope: v0.3.2 build-context files or directories with group-write permission whose numeric GID
  equals the invoking numeric UID.
- Fix: numeric UID/GID equality is no longer a trust claim. A group-writable entry is accepted only
  when account and group databases prove it is the invoking user's primary group, no other account
  uses it as a primary group, and no different supplementary member is listed. Missing or
  ambiguous identity data fails closed; world-writable entries remain forbidden.

## KI-2026-08-26: expired optimization state was not synchronously reclaimed (resolved)

- Fix: production runtimes schedule a bounded expiry timer, every later runtime interaction also
  prunes expired state, and MCP connection shutdown revokes active authority and releases private
  Buildx state, snapshots, and only identity-verified temporary images. Explicit revocation remains
  idempotent. A process crash can still leave proven session objects for manual review; global
  Docker prune remains forbidden.

## KI-2026-08-26: generated optimization template overstated edit enforcement (resolved)

- Scope: the schema-1.1 `[optimization]` comments generated by `perflens init --docker`.
- Fix: the generated bilingual template now says that only `mutable_paths` changes are admitted
  into candidate build snapshots. It explicitly assigns editor/write enforcement to the client
  sandbox and retains the prohibition on commit, push, tag, and release authority.

## KI-2026-08-15: advanced trace entry points were easy to mistake for stable analyzers (resolved)

- Scope: public mode types and the `cap_perfmon` Python Broker can construct raw `sched`, `lock`,
  and `off_cpu` perf evidence, while old documentation grouped all five modes together.
- Historical boundary: generated policy enabled only `record` and `stat`; `paranoid3_helper`
  rejected the other three, and no typed scheduler-delay, lock or paired off-CPU artifact existed.
- Risk: enabling a raw mode may expose metadata about non-target tasks, produce kernel/perf-version
  dependent evidence, or tempt an Agent to infer precise waiting time that was never reconstructed.
- Resolution: v0.3.0 added a separate Trace Helper, target filtering, deterministic
  `sched/off_cpu/lock` evidence and analysis, verification artifacts, and the explicit
  `full_diagnostics` profile. The existing privileged stat/record Helper remains limited to
  `record/stat`. Lost, truncated, censored, or unpaired trace evidence still reports `partial`,
  and futex evidence still cannot invent user-space lock owner or hold time. See the
  [capability roadmap](collector-capability-roadmap.md).

## KI-2026-08-15: raw perf evidence lacked end-to-end Agent projection replay (resolved)

- Risk: a correct raw-file SHA-256 alone does not prove that later typed metrics, hotspots, paths,
  and Diagnosis content still project that file. Review also found two concrete distortion paths:
  dropping an unreadable callchain position could transfer Self weight to its caller; and a formal
  zero-count hardware stat result could occupy the final path before `auto` software fallback.
- Fix: Collection verification uses one no-follow descriptor snapshot for identity, size, and hash;
  stat reparses the retained CSV and requires exact typed-metric equality. Analysis binds converter
  provenance, source Collection, all Agent-visible content, and derived conservation. Record event
  provenance must match the conversion transcript. Fixed `cpu_core/` and `cpu_atom/` hybrid-PMU
  expansion is safely canonicalized for matching while raw metric identity remains intact. An
  unreadable callchain position remains a
  bounded `unknown` Frame. Formal hardware output is validated while temporary and published only
  when usable, leaving `auto` able to spend the remaining authorized duration on software events.
- Agent gate: MCP load and paging validate Analysis, Collection, and Diagnosis artifacts. A
  Diagnosis binds its source Analysis digest and is safely reusable. Matched A/B rejects different
  event sources, weight semantics, or converter identities.
- General boundary: these controls live in the shared CSV, perf-script, aggregation, and Artifact
  layers rather than a Python-specific branch. C/C++, Rust, Go, CPython, and Java/JIT traverse the
  same gate; only their external symbol quality differs. Fixtures cover representative formats but
  are not live-host certification of every compiler, JDK, or perf version.
- Remaining limit: hashes are not signatures against a malicious file owner and cannot prove the
  kernel PMU or perf itself correct. PerfLens still does not parse perf.data directly, and unfrozen
  JIT/Build-ID sidecars cannot promise cross-host/time replay. Unknown formats become `partial`
  evidence with forbidden conclusions.

## KI-2026-08-14: Frame/annotation precedence, Python perf maps, and duplicate paths (resolved)

- Symptom: a valid CPython `-X perf` recording could parse every sample but still report hundreds
  of `Callchain frame has no hexadecimal IP` warnings for lines such as
  `python3.13[offset]` and `[JIT] tid N[offset]`. Public call paths could also contain many rows
  with identical displayed symbols and DSOs because exact instruction addresses differed.
- Cause: with `srcline` enabled, perf emits those bracketed lines and standalone
  `file:line (inlined)` lines as annotations for the preceding frame; they are not frames. Internal
  call paths used exact Frame identity while the public contract intentionally exposes only
  `(symbol, DSO)`. An early fix tested source-like annotations before complete Frames, so a valid
  native parent-with-source immediately after a leaf-without-source could also be swallowed.
- Fix: the parser now accepts only an annotation whose offset matches the immediately preceding
  frame and whose label matches its DSO or JIT thread. Strict standalone source annotations enrich
  only that preceding frame. It also recognizes CPython's documented `py::function:filename`
  perf-map name. Public paths aggregate by their displayed `(symbol, DSO)` sequence, source
  locations are projected onto hotspots with a fixed bound, and `has_source_lines` requires a real
  line number. A complete hexadecimal-IP Frame now always takes precedence over annotation rules.
- General regression boundary: goldens cover C/C++ templates, inline frames and parenthesized DSOs;
  Rust hash merging; Go methods; Java/JIT and Python perf maps; and ordinary native parent frames.
  For `perf.data`, Java/JIT without a frozen transcript or sidecar still forbids cross-time replay.
  Fixture coverage is not misrepresented as real-host acceptance of every JVM/runtime version.
- Reporting boundary: PerfLens paths are root/caller to leaf/callee. Missing DWARF lines and
  unresolved native frames remain visible limitations; the fix does not invent a deeper Python
  stack than perf recorded.
- Captured-evidence acceptance: reprocessing the originally reported 272-sample CPython
  `perf.data` aggregates all 591 Frame lines, classifies 589 address and two source annotations,
  and reports zero malformed records. The hundreds of false no-hex-IP warnings disappear; one
  genuine native Frame-without-DSO warning remains. CPU-clock weight is now labeled nanoseconds,
  while content/fingerprint/conservation/source-SHA checks pass. Quality correctly stays `partial`
  because the JIT sidecar was not frozen and 5.88% of Self weight is unresolved.

Typed stat reporting was tightened at the same time: `running_percent` is perf event scheduling
coverage, not process CPU utilization. Low context-switch, migration, or page-fault counts do not
prove that I/O wait, contention, allocation churn, or memory pressure is absent. Sampled perf
periods are no longer all labeled `event_count`: CPU/task clock periods are nanoseconds,
cycles/instructions use their native units, and unfamiliar events remain generic rather than being
guessed.

The `perf stat` CSV adapter also no longer hides invalid UTF-8 with replacement decoding: invalid
bytes fail the evidence closed so an event identity cannot change silently. A malformed CSV row
emits a bounded warning without destroying later valid metrics, and warning overflow is explicitly
marked as truncated. This repair is independent of the target language.

Source locations are now collected only while accepted samples enter aggregation. A record rejected
for stack depth or another parse rule cannot attach its location to a same-named valid hotspot.
Per-hotspot locations remain bounded; truncation is explicit on both Hotspot and EvidenceQuality,
which gates any claim that the location list is complete.

The same repair makes dedicated-Helper-UID evidence analyzable. Even when an authorized ordinary
user can read an artifact in `/var/lib/perflens-helper`, `perf script` adds its own current-user/root
ownership refusal. The adapter now fixes `--force` only after path, size, and SHA-256 validation;
it grants no OS permission, broadens no allowed root, and accepts no Agent-provided perf option.

The same change adds an Analysis content digest, Collection-to-input hash binding, before/after
source identity checks, and `verify-analysis`. A future mismatch in Frames, weights, percentages,
or event provenance therefore fails closed before Agent use; valid but incomplete evidence remains
`partial` with explicit forbidden conclusions.

## KI-2026-08-14: cap_perfmon PID binding and project launch had timing windows (resolved)

- Original gap 1: the `cap_perfmon` Python Broker checked PID owner/start time before spawning
  perf, leaving a numeric-PID reuse window before attachment. The Rust Helper already had a
  disabled-event barrier, but the default mode did not have an equivalent post-bind check.
- Original gap 2: the project launcher released the workload after a fixed 200ms delay. That was a
  timing guess: attachment could be slower, while a short program could finish before collection.
- Fix: both paths start PID perf events disabled with `-D -1`, wait for a bounded control ACK,
  revalidate the plan-bound PID/UID/start time, and only then enable events. The initial repair used
  `ping`; current code uses the documented idempotent `disable` after KI-2026-08-26. Identity
  changes, invalid ACKs, timeouts, and extra frames fail closed without publishing partial evidence.
- Project handshake: public Broker protocol `1.1` and private Python/Rust Helper protocol `1.2`
  stream a request/plan/PID-bound readiness frame. The ordinary-user bootstrap execs the approved
  project program only after authenticating that frame.
- With `event_source=auto`, the hardware availability probe keeps the bootstrap/Gate paused and
  never emits the ready frame. Zero, unsupported, and not-counted rows conservatively select
  software; `hardware_required` is the explicit path when hardware evidence is mandatory. The
  selected formal profile alone emits readiness. Probe time remains within the original
  authorization and is capped at 250ms.
- MCP registers the blocking project runner as a synchronous tool so the SDK executes it in a
  worker thread instead of blocking the async session. The launcher now gives already-completed
  short workloads a bounded natural-exit/reap window, and its integration test uses the bootstrap
  command identity rather than fixed sleeps. This removes the load-sensitive 10-second CI timeout
  without raising the global timeout.

No project command, arguments, or environment cross into the Collector, and this adds no root,
sudo, sysctl, or cross-UID authority. The old Broker and Helper do not negotiate with the new
protocol; upgrade both matching packages and run `sudo perflens-admin upgrade` to restart them.

## KI-2026-08-14: separate debug files were selected by path existence alone (resolved)

- Original behavior: ELF inspection listed `.gnu_debuglink` and Build-ID candidate paths, but
  resolver selection checked only that a file existed. A mismatched or replaced debug file could
  therefore produce incorrect source attribution.
- Fix: GNU debuglink candidates must match the CRC32 stored in the ELF, and Build-ID directory
  candidates must carry the same Build ID. The identity is checked again immediately before
  `addr2line`/`llvm-symbolizer`; mismatch falls back to the verified original DSO, or fails
  explicitly if that DSO also changed.
- Boundary: GNU debuglink CRC32 is a compatibility checksum, not a cryptographic publisher
  signature, and a Build ID is not a signature either. These checks prevent mismatching and common
  replacement errors; release provenance still requires supply-chain verification.

## KI-2026-08-12: record succeeded but analysis required a missing CPU field (resolved)

- Confirmed affected scope: withdrawn same-version `v0.2.0` packages using the `cap_perfmon`
  Python path or `paranoid3_helper` after a software `cpu-clock` fallback. The fix covers both
  software and hardware record; text profiles were not affected.
- Symptom: the Collection reported a successful, multi-megabyte record artifact, but
  `analyze_collection` returned `EXTERNAL_TOOL_FAILED`. The underlying `perf script` said that
  samples did not have the CPU attribute set and that it could not print the `cpu` field.
- Cause: fixed record commands in both Collector paths did not consistently include
  `--sample-cpu`, while the PerfLens perf-script
  adapter requested a per-sample CPU field.
- New-recording fix: Python Collector and Helper hardware/software record commands now include
  fixed `--sample-cpu`. Every perf argument is still derived from the typed plan; arbitrary perf
  options are not exposed.
- Existing-artifact compatibility: only after matching that exact perf error, the analyzer retries
  without the CPU field and emits `MISSING_SAMPLE_CPU`. Hotspots, call paths, and source attribution
  remain available, but per-CPU distribution does not. Unrelated perf-script errors remain visible.

This was a mismatch between capture and conversion fields, not a
`perf_event_paranoid=3` or VMware fallback failure. Replacement `v0.2.0` packages preserve CPU
identity in new recordings; affected existing artifacts do not need to be deleted.

## KI-2026-08-12: project authorization was easy to omit and an Agent escaped its scope (resolved)

- Previous symptom: after the user confirmed a project workload, an Agent omitted the fixed
  authorization value from `collect_project_workload`. The server correctly denied the call, but
  the Agent then tried shell/background execution, direct perf, an existing-PID plan, Callgrind,
  or parameter sweeps.
- Boundary: one project-workload authorization covers only the confirmed executable, arguments,
  mode, and limits. It does not authorize shell/`timeout` wrappers, direct perf, existing-PID
  attachment, Callgrind, parameter sweeps, changed arguments, or extra correctness commands.
  `PID attachment is disabled by server policy` is the expected result when that separate feature
  is not enabled; it is not a Collector failure.
- Fix: the MCP input Schema now constrains `authorization` to the sole fixed value
  `I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`. Server instructions, error guidance, and the Skill
  require correcting that field inside the approved scope and retrying only the same tool. They
  explicitly prohibit switching execution channels as a workaround.
- Provenance: `inspect_collection_capabilities` describes the ordinary MCP process. A local
  `blocked` result under `perf_event_paranoid=3` does not prove the independent Collector is
  blocked and is not the fallback cause. The Collection's `actual_event_source`, `fallback_used`,
  and `fallback_reason` are authoritative; a common VMware result is
  `hardware_probe_produced_no_usable_counts`.
- Reporting: Callgrind `Ir` is an instruction-reference share produced by simulation or
  instrumentation, not a PerfLens `cpu-clock` record self-CPU percentage. Reports must name the
  tool and unit before combining those observations as candidate evidence.

The user does not need to memorize or repeat the fixed token. The Agent supplies it after the user
explicitly approves the exact workload. If the corrected tool call still fails, preserve and report
the error instead of widening execution scope.

## KL-2026-08-09: zero hardware-PMU counts on some VMware/hybrid hosts (automatic fallback available)

Some VMware guests on Intel hybrid hosts expose PMU devices but still return
zero `cycles`/`instructions`, `not supported`, `not counted`, or `ENOMEM` while
software events work. This is commonly a virtual-PMU/host-hypervisor
compatibility boundary, not insufficient guest CPU capacity, and root alone
does not repair it.

`record` and `stat` now default to `event_source=auto`. A fixed, same-PID probe
of at most 250ms selects hardware evidence when useful, otherwise stat uses
fixed software events and record uses `cpu-clock`. Results expose the actual
source, fallback reason, and limitations. Software fallback still supports CPU
time, scheduling activity, page faults, on-CPU hotspots, call paths, source
attribution, FlameGraphs, and same-source A/B validation. It does not support
IPC, hardware cache-miss, branch-miss, or other microarchitectural claims.

Use `hardware_required` when those counters are mandatory, or `software_only`
to pin comparable A/B runs on a host with a known-broken PMU. Never compare a
hardware baseline directly with a software candidate as equivalent evidence.

## KI-2026-08-10: Helper stat succeeded but record could not synthesize target mappings (resolved)

- Affected scope: the withdrawn native `v0.2.0` `paranoid3_helper` packages whose Helper unit
  bounded root to `CAP_PERFMON` and `CAP_SYS_ADMIN`. The default `cap_perfmon` mode and
  unprivileged components were not changed.
- Symptom: explicit `verify-collector --event-source software_only` stat collection succeeded,
  but `accept-collector` failed during its software `record` step with
  `EXTERNAL_TOOL_FAILED`. Running the equivalent `perf record` in a transient unit failed with the
  two-capability set but captured samples after adding `CAP_SYS_PTRACE`.
- Cause: `CAP_PERFMON` authorizes performance-event access, while this attached `perf record`
  workflow also needs ptrace-equivalent access to inspect the already-authorized target's mappings
  and synthesize usable sampling metadata. A successful stat-only probe did not exercise that path.
- Fix: the replacement same-version Helper unit has an exact ceiling of `CAP_PERFMON`,
  `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE`. The typed PID protocol, target UID/start-time checks,
  expiry, replay protection, event/duration/output bounds, and fixed spool remain unchanged.
  No capability is added to the Agent, Skill, MCP server, or Python Broker.
- Upgrade safety: `perflens-admin upgrade --dry-run` reports `CAP_SYS_PTRACE` in
  `helper_capability_expansion`. The real upgrade fails before writing or restarting until the
  administrator supplies `--acknowledge-privileged-helper-risk`.

Install the replacement packages, then run:

```bash
sudo perflens-admin upgrade --dry-run
sudo perflens-admin upgrade --acknowledge-privileged-helper-risk
perflens accept-collector --authorize-host-acceptance
```

The legacy `--acknowledge-cap-sys-admin-risk` option remains accepted, but new guides use the
capability-neutral name because the acknowledged boundary now includes both `CAP_SYS_ADMIN` and
`CAP_SYS_PTRACE`.

## KI-2026-08-10: Helper rejected Linux perf's NUL-terminated control ACK (resolved)

- Affected scope: the withdrawn native `v0.2.0` `paranoid3_helper` packages. The default
  `cap_perfmon` mode does not use this private Helper protocol.
- Symptom: service health and policy validation passed, but `accept-collector` or an explicit
  `verify-collector --event-source software_only` immediately returned `EXTERNAL_TOOL_FAILED`.
  Only the consumed-plan marker appeared in the Helper spool; no performance artifact was
  published.
- Cause: the control-fd documentation calls the completion response `ack\n`, while the Linux 6.12
  implementation writes the C-string size and therefore emits `ack\n\0`. The old line reader left
  the NUL buffered after the first ACK, read the next response as `\0ack\n`, and failed closed.
  Test doubles emitted only `ack\n`, so they did not reproduce the real framing.
- Fix: the replacement `v0.2.0` uses a strict, 16-byte-bounded binary ACK parser. It permits only
  implementation-produced leading NUL bytes before the documented ACK and rejects every other or
  oversized response. That repair still used `ping`; current code uses an acknowledged idempotent
  `disable` after KI-2026-08-26, preserving PID owner/start-time revalidation before events are
  enabled.
- Regression coverage: perf test doubles now emit the real `ack\n\0` response for every command,
  including the NUL carried into the following frame.

This was a Helper protocol compatibility defect, not a `perf_event_paranoid=3`, software-policy,
or VMware PMU fallback failure. Install the replacement same-version packages, run
`sudo perflens-admin upgrade`, and repeat ordinary-user acceptance. Do not weaken sysctl or grant
privilege to the Agent, MCP server, or Python Broker.

## KI-2026-08-07: withdrawn v0.2.0 Helper unit failed during systemd USER setup (resolved)

- Affected scope: the withdrawn initial native v0.2.0 `perflens-collector` DEB when Debian 13
  selected `paranoid3_helper`; the default `cap_perfmon` mode was not affected.
- Symptom: deployment health validation failed and the journal reported
  `Failed to drop keep capabilities flag` followed by `Failed at step USER`. The Broker could then
  fail its NAMESPACE step because the Helper runtime directory did not exist.
- Cause: the Helper unit set `keep-caps-locked` before systemd finished USER setup, while systemd
  still needed to clear `PR_SET_KEEPCAPS`; the kernel correctly denied the locked transition.
- Fix: the replacement `v0.2.0` artifacts remove the conflicting secure-bit lock. This USER-stage
  fix itself did not widen capabilities; the final replacement unit's separately documented record
  fix uses the explicit three-capability boundary above. No Agent, MCP, or Python Broker capability
  boundary is widened.

The failed deployment rolls back its new policy, units, and sockets. Do not edit the installed
package or weaken the unit manually; install the replacement `v0.2.0` artifacts and deploy the
reviewed policy again.

## KI-2026-08-07: bounded Helper collection treated expected SIGINT as failure (resolved)

- Affected scope: the withdrawn initial `v0.2.0` `paranoid3_helper` implementation.
- Symptom: deployment and the authenticated health handshake succeeded, but
  `perflens accept-collector --authorize-host-acceptance` returned `EXTERNAL_TOOL_FAILED` with
  `Privileged perf returned a non-zero result`.
- Cause: after disabling the events at the requested duration boundary, the Helper sent SIGINT so
  an attached `perf` process would flush and close its artifact. Linux reports that expected exit
  as signal 2/status 130, which the Helper incorrectly treated as an external failure.
- Fix: the replacement `v0.2.0` accepts SIGINT only when this Helper successfully sent it in the
  bounded shutdown path. An early SIGINT, any other signal, an ordinary non-zero exit, a control
  failure, or an empty/unsafe artifact still fails closed.

This fix does not make unavailable performance counters measurable. If acceptance proceeds to
`PROFILE_PARSE_FAILED` and every metric is `not_supported` or `not_counted`, check the host PMU. In
particular, a virtual machine may require virtual CPU performance counters to be enabled by its
hypervisor.

## KL-2026-08-07: Rust Helper private-spool archival was not supported (resolved)

- Affected scope: the withdrawn initial `v0.2.0` implementation of `paranoid3_helper`.
- Fix status: resolved in the replacement `v0.2.0` artifacts.
- Previous behavior: archive, verification, and prune commands explicitly returned
  `UNSUPPORTED_FORMAT` instead of inspecting the wrong spool.
- Fix: the lifecycle now selects the active spool from the reviewed privilege mode and separately
  verifies Helper directory/tombstone ownership (`root:perflens-internal`) and artifact ownership
  (`root:perflens`). The manifest binds the archive to its privilege mode and spool path.

Installations using the withdrawn artifacts should install the replacement v0.2.0 packages before
attempting Helper spool cleanup. Do not manually delete unknown evidence or loosen directory
permissions.

## KI-2026-08-06: native DEB upgrade can retain stale Python bytecode

- Affected path: an in-place native DEB upgrade from `v0.1.2` to `v0.1.3`.
- Fix status: fixed on the development branch for the next release.
- Symptom: `dpkg-query` reports `0.1.3-1` while a PerfLens entry point still reports `0.1.2`.
- Cause: reproducible packages fix Python source mtimes, allowing an old same-path `.pyc` to remain
  timestamp/size-valid when the older package did not remove it during configure.

The development fix makes the native launcher ignore inline package caches and disables bytecode
writes before importing PerfLens. The main package `postinst` also removes only legacy `.pyc/.pyo`
files and empty cache directories below fixed `/usr/lib/perflens` during `configure`.

Affected `v0.1.3` systems can use this bounded workaround:

```bash
dpkg-query -W -f='${Package} ${Version}\n' perflens perflens-collector
sudo find /usr/lib/perflens -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
sudo find /usr/lib/perflens -depth -type d -name '__pycache__' -empty -delete
hash -r
perflens --version
```

Do not delete the whole `/usr/lib/perflens` package runtime.

## KI-2026-08-05: `umask 0002` makes staged Collector policy undeployable

- Affected version: `v0.1.2`.
- Fixed in: `v0.1.3`.
- Status: resolved; the bounded workaround remains valid for `v0.1.2`.
- Scope: a new `collector.toml` produced by `perflens init --prepare-collector`
  or `perflens setup --prepare-collector`.
- Not affected: a policy already installed at `/etc/perflens/collector.toml`,
  existing-profile analysis, and read-only use without the Collector.

### Symptom and cause

On a host with `umask 0002`, the generated policy can have mode `0664`.
`perflens-admin deploy --dry-run` then correctly fails with
`PATH_SAFETY_VIOLATION` because the policy is group-writable. The `v0.1.2`
asset generator relies on the process umask instead of explicitly setting the
final policy mode. The deployer's ownership, type, size, and non-writable checks
must not be weakened.

### `v0.1.3` fix

The staging directory is now explicitly `0700`, `collector.toml` is `0600`, and
the systemd/sysusers templates are `0644`, independent of the caller's umask.
All deployer safety checks remain in place. After upgrading, run
`perflens init --update --prepare-collector` to regenerate assets; an unchanged
v0.1.2 Skill is also safely migrated to the shorter `perflens` directory name.

### `v0.1.2` workaround

Run as the ordinary user who generated the configuration:

```bash
chmod 600 "$PWD/perflens-setup/collector-assets/collector.toml"
stat -c '%a %U:%G %n' \
  "$PWD/perflens-setup/collector-assets/collector.toml"

perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml" \
  --dry-run

sudo perflens-admin deploy \
  --config "$PWD/perflens-setup/collector-assets/collector.toml"
```

Confirm mode `600` before deployment. Do not use `sudo` to bypass the mode
correction. This is a one-time host deployment for the authorized Linux user;
other projects only need their project-level `perflens init`.

### Fix acceptance

`v0.1.3` explicitly sets staged `collector.toml` to `0600`, tests generation
under `umask 0002` and `0000`, proves that the unmodified generated policy passes
deployment validation, and preserves every current deployer safety check.
