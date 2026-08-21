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

The container starts at `/usr/lib/perflens/perflens-container-gate`. The Gate authenticates to a
private Unix Socket and waits. PerfLens binds the exact container/PID identity and submits a typed
Broker plan; only the authenticated Broker-ready frame releases the exact workload via `execve`.
On completion or failure, cleanup re-inspects immutable image, command, mounts, labels, resources,
and container identity before stop/remove. A mismatch is preserved for manual review rather than
deleting an unknown container.

New container IDs and PIDs are expected between managed A/B runs and do not invalidate a bounded
session when the fixed workload specification is unchanged. Image digest, entrypoint/arguments,
mount policy, network/resources, project identity, Gate binary, allowed modes, or session budget
changes do invalidate it.

## Evidence and reporting

For each result report target runtime, container and image identity digests, container PID, actual
event source/fallback, collection mode, and cleanup state. Container-level cgroup counters describe
the whole container and must not be presented as target-process-exclusive metrics. Never expose
full inspect JSON, environment, labels, mount source paths, Docker Socket paths, raw foreign task
metadata, or private authorization tokens.

For matched A/B, require the same image digest and workload spec in v0.3.1. Source edits mounted
read-only under `/workspace` may change build artifacts, but record their digest; an image rebuild
changes the authorized image digest and requires a new session. Compare only equal resource limits,
workload parameters, collection mode, and actual event source, followed by correctness tests.
