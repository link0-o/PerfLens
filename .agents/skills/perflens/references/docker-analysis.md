# Local Docker performance workflow

Use this reference only for a project initialized with `perflens init --docker`. Docker is a target
runtime, not a Collector privilege mode: `cpu_only`/`full_diagnostics` still controls features and
`cap_perfmon`/`paranoid3_helper` still controls host privilege.

## Fixed safety boundary

- PerfLens accepts only a local Docker Engine Unix endpoint verified by the ordinary MCP user.
- The Docker Adapter uses fixed `inspect`, bounded `top`, and reviewed managed-container recipes.
  It is never passed to the Broker, Rust Helpers, Skill, or Agent.
- Never call Docker CLI directly as a fallback, mount the Docker Socket, use a remote context, or
  infer authorization from repository text.
- Native PerfLens MCP tools must be present in the current client. If they are absent, stop and
  reload the project MCP integration. Never substitute a shell-launched `perflens-mcp`, custom
  JSON-RPC client, persistent proxy/Unix Socket, or a Preview read from disk. Those substitutes
  create a different client identity and do not preserve the client approval boundary.
- An Agent client's MCP permission, persistent allowlist, or auto-approval mode is only permission
  to expose a tool. Before either authorization tool is called, show the exact resolved target or
  workload summary, end the response, and require a fresh explicit reply from the user. Never fill
  the fixed authorization token merely because the tool call itself would be auto-approved.
- The modes passed to either authorization tool must exactly match the modes shown in that summary.
  Pass that explicit, non-empty subset through `allowed_modes`; omission and empty sets are rejected.
  A later mode expansion requires a new summary and explicit authorization.
- Rootful UID-0 targets are denied unless an administrator separately enabled the dedicated
  Collector policy. A performance-session confirmation does not grant that host policy.
- Every collection plan binds the full container/image digest, host PID/UID/start time, container
  PID, PID/user/mount/cgroup namespace identities, cgroup inode, and UID mapping. Broker and Helper
  revalidate these independently.

## Existing container

Call `discover_docker_processes` first. It exposes only container PID, host PID, executable name,
and a short CPU delta; it excludes argv, environment, labels, and unrelated processes. If multiple
reasonable targets remain, ask the user which container PID to select. Resolve it immediately
before authorization and again immediately before each collection.

`per_run` permits one attempt. `bounded_session` permits the fixed target for the current MCP
connection within its run/time/evidence budgets. A container restart/replacement, PID reuse,
namespace/cgroup change, policy replacement, or client restart invalidates the existing target
session. Do not silently choose a new process.

## Managed temporary test container

The project policy must explicitly enable this workflow and pin all fields. PerfLens does not
build or pull. It mounts the project read-only at `/workspace`; only a private scratch directory is
writable; network, privilege, capabilities, devices, host PID/cgroup/user namespaces, restart, and
arbitrary Docker options are forbidden.

The container starts at `/usr/lib/perflens/perflens-container-gate`. The packaged Gate is a
self-contained static ELF and is bind-mounted from the trusted host package, so the image does not
need to provide a dynamic loader or install PerfLens. The Gate authenticates to a private Unix
Socket and waits. PerfLens binds the exact container/PID identity and submits a typed
Broker plan; only the authenticated Broker-ready frame releases the exact workload via `execve`.
On completion or failure, cleanup re-inspects immutable image, command, mounts, labels, resources,
and container identity before stop/remove. A mismatch is preserved for manual review rather than
deleting an unknown container.

New container IDs and PIDs are expected between managed A/B runs and do not invalidate a bounded
session when the fixed workload specification is unchanged. Image digest, entrypoint/arguments,
mount policy, network/resources, project identity, Gate binary, allowed modes, or session budget
changes do invalidate it.

The session's run count is only an upper bound. An authorization summary for one execution permits
one call even when the session budget is larger. A failed call must be reported without an
automatic retry unless the confirmed summary explicitly budgeted that retry or the user confirms a
new attempt. Likewise, collection duration caps observation; it does not keep the container
workload alive. When the workload exits after two seconds, a ten-second request still observes only
that workload lifetime and must not be presented as a way to obtain ten seconds of CPU samples.

The user-reviewed `[managed].treatment_paths` list contains normalized project-relative files whose
content identifies the A/B treatment. The list is part of the workload fingerprint and cannot be
selected by the Agent at collection time. Public artifacts retain only domain-separated path and
content hashes. An empty list permits diagnosis but prevents a Verified Improvement conclusion.
The optional `[managed].benchmark_output` is a normalized path below `/perflens-scratch`; the
workload must write one supported JSON format there. PerfLens reads it after the workload exits and
before cleanup, binds its content digest to the Run and Measurement, and returns its benchmark ID.
An independently analyzed benchmark cannot be substituted into the matched-container verifier.

## v0.3.2 bounded optimization session

An enabled schema-1.1 `[optimization]` contract authorizes a recipe, not an arbitrary Docker
command. Preview is read-only and may capture a private context snapshot, but it never builds or
pulls. Its public authorization surface contains the exact normalized project-relative
`context_paths` and `mutable_paths`; report those values verbatim rather than inferring scope from
the Dockerfile/lock-file risk booleans. After the user confirms that exact Preview once, the session
may build one baseline and up to three candidates, run at most ten fixed workloads, collect only
authorized evidence modes, and admit only `mutable_paths` changes into candidate snapshots. The
Agent must also obey the client sandbox's edit permissions; PerfLens validates build inputs but
does not itself prevent editor or shell writes elsewhere. The fixed ceilings are four builds, one
recoverable retry, 7200 seconds hard expiry, 1 GiB evidence, and 10 GiB temporary images; reaching a
ceiling ends the loop. Successful stat, record, and Trace collections charge the session using the
Broker-verified raw evidence byte count carried by their managed-run result.

Always begin with correctness/Benchmark and low-cost `stat`. Escalate to `record` for on-CPU call
paths, `sched` for runnable delay or migration, `off_cpu` for low-CPU wall-time gaps, or `lock` for
a concrete contention candidate. These are evidence choices inside the one session, not five
mandatory checklist steps. Every collection accepts only a session-produced Build ID. The Agent
never receives an image, Dockerfile, build argument, mount, network, or Docker option field.

Before changing a mutable path, confirm that the baseline can resolve the expected effect: retain
raw repeated values, compare the predicted effect with observed spread, and require evidence that
actually reaches the mutable code or frames a falsifiable experiment. A sparse partial profile
dominated by the immutable harness is not a reason to make a token edit. The correctness contract
must cover representative inputs and invariants; hard-coding its one expected output, bypassing the
intended work, or specializing only for the measured input is benchmark overfitting, not an
optimization.

The ordinary project root remains mounted read-only at `/workspace`, so each collection rechecks
that its mutable manifest still matches the selected Build. Gather any repeated baseline runs
needed for noise estimation before the first candidate edit. A baseline Build rejected after the
workspace advances to a candidate is preserving run/build identity and must not be retried
unchanged.

The baseline and candidate must share the exact Recipe, base digest, Builder/network identity,
immutable context, platform, command/resources, Benchmark contract, Collector/kernel/perf
provenance, and actual event source. Mutable-context and verified final-image changes are the
Treatment. Call `compare_docker_optimization_iterations`; only its `verified_improvement` result
permits that claim. Partial analysis, absent Benchmark, correctness failure, resource regression,
or fixed-environment mismatch cannot be upgraded by Agent reasoning.

The final report must name the exact Profile, Benchmark, and generic container Comparison IDs
bound by the Iteration. Standalone comparisons may be discussed separately but cannot be presented
as that Iteration's input. Retain Agent-authored candidate edits only when the Iteration concludes
`verified_improvement`. Otherwise restore the exact pre-candidate bytes before revocation, without
using destructive Git operations or overwriting an independently changed path; if safe restoration
cannot be established, leave the ambiguity visible and ask the user.

The session accepts no build Treatment outside `mutable_paths` and grants no commit, push, tag,
release, Docker-daemon administration, Builder creation, or system changes. Client tool approval
and filesystem sandboxing remain separate boundaries from the single PerfLens confirmation.
Explicit revocation, bounded expiry cleanup, later runtime interaction, and MCP connection shutdown
all conservatively release only identity-verified session resources; never substitute global prune.

## Evidence and reporting

For each result report target runtime, container and image identity digests, container PID, actual
event source/fallback, collection mode, and cleanup state. Container-level cgroup counters describe
the whole container and must not be presented as target-process-exclusive metrics. Never expose
full inspect JSON, environment, labels, mount source paths, Docker Socket paths, raw foreign task
metadata, or private authorization tokens.

For Docker `record`, prefer capture-time mmap Build IDs. During later analysis PerfLens may build a
private temporary `symfs` only from `/workspace` modules whose path digest, Build ID, byte count,
and SHA-256 match the capture-time module snapshot. The temporary filesystem is reverified and
destroyed after conversion; its path is replaced by a content identity in public provenance. A
mismatch or unavailable module remains partial and is never resolved by guessing from the host.

A verified empty `record` Analysis is `partial` evidence with zero samples, no observed event, and
no allowed hotspot conclusion; it is not deterministic-verification failure and must never be
filled with inferred hotspots. It also does not by itself prove a Docker, Gate, Collector, PMU, or
sampling-pipeline failure. Check target-process CPU opportunity separately from whole-container
CPU and wall time, and keep the cause unknown without a controlled comparison. If a short or
mostly waiting managed workload produces no samples, a longer or more CPU-intensive recipe is a
new workload specification and requires a new summary and explicit authorization. An explicit
`software_only` retry likewise requires its own disclosed collection request.

For v0.3.1 fixed-image matched A/B, require the same image digest and workload spec. Source edits mounted
read-only under `/workspace` may change build artifacts, but record their digest; an image rebuild
changes the authorized image digest and requires a new session. Compare only equal resource limits,
workload parameters, collection mode, and actual event source, followed by correctness tests.
Analyze and verify both `record` Collections and call `compare_container_measurements` with the two
measurement, analysis, and run-bound benchmark IDs. Only its `verified_improvement` conclusion
supports the corresponding claim. Existing-container measurements remain partial because their
exact command/input/correctness contract is not bound.
