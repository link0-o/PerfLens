# PerfLens v0.3.1 Docker process collection and analysis guide

[Implementation audit contract](v0.3.1-execution-contract.md)

The bounded build-and-optimize extension is specified separately in the
[v0.3.2 Docker optimization contract](docker-optimization-roadmap.md).

[简体中文](docker-container-roadmap.zh-CN.md) | English

Status: **implemented release candidate; automated gates passed, real-host Docker acceptance pending**

Last audited: 2026-08-22 against the v0.3.1 source and package candidate

Target release: `v0.3.1`

This document is the v0.3.1 design, implementation, use, and release contract. The current source
and local package candidate implement active discovery, authorization, managed launch, collection,
analysis, and matched comparison for the bounded Docker scope below. A host still must pass the
explicit local-Docker acceptance before its installation can claim that the runtime is usable.

The release sequence is fixed as follows:

- `v0.3.0`: complete the host `stat/record/sched/off_cpu/lock` loop;
- `v0.3.1`: add collection, analysis, and container resource context for one explicit process in a
  local Docker container;
- `v0.4.0`: complete the C/C++, Java, Python, and Go user-space lock adapters.

The checked-in Runtime Lock public contracts are groundwork for v0.4.0. They do not mean that the
four runtime adapters are available and do not change the v0.3.1 Docker boundary.

## 1. Decision summary

1. **Docker is a target runtime, not a third Collector privilege mode.**
   `cpu_only/full_diagnostics` selects evidence capability,
   `cap_perfmon/paranoid3_helper` selects the privilege implementation, and `host/docker` selects
   where the target runs.
2. **v0.3.1 supports only a local Linux Docker Engine, cgroup v2, and one explicit process.** A
   container target never silently expands into all PIDs or system-wide collection.
3. **Both existing containers and PerfLens-managed temporary test containers are supported.** A
   managed container uses only a local image pinned by immutable digest; it never builds or pulls.
4. **The Collector remains on the host.** perf always attaches to the host PID. The container PID
   exists only for user interaction, identity binding, and reporting.
5. **The Docker socket is never given to the Collector, Helper, Agent, or Skill.** A fixed
   ordinary-user adapter performs reviewed Docker operations, while the Broker and Helpers
   independently revalidate Linux kernel identity.
6. **Same-host-UID is the default.** Rootful container UID 0 is denied until an administrator
   acknowledges a dedicated container cross-UID risk. Generic cross-UID collection stays disabled.
7. **Authorization is never permanent.** The product offers per-run confirmation and a bounded
   authorization for one Agent conversation. Silence, timeout, or an uncertain session boundary
   fails closed.

## 2. Capability scope

### 2.1 Stable target

v0.3.1 completes these paths:

- attach to one explicit process in an existing running Docker container;
- start a PerfLens-managed temporary test container and bind collection before the workload's
  first instruction;
- run `stat` and `record`, plus `sched`, `off_cpu`, and `lock` when `full_diagnostics` is deployed;
- read container cgroup v2 resource context before and after collection;
- perform bounded Build ID, symbol, and source-path resolution for container modules;
- include a container environment fingerprint in matched A/B and diagnosis bundles;
- let the Skill handle natural requests such as “Use PerfLens to deeply optimize the current
  project's container workload.”

The three configuration axes remain independent:

```text
feature profile: cpu_only | full_diagnostics
privilege mode:  cap_perfmon | paranoid3_helper
target runtime:  host | docker
```

Selecting Docker does not change the feature profile, privilege mode, sysctl, or capabilities.

### 2.2 Explicit exclusions

v0.3.1 does not support:

- whole-container or cgroup-wide multi-process perf aggregation;
- arbitrary `docker run`, `docker exec`, Docker CLI arguments, or Engine API requests;
- Docker Compose, Swarm, Podman, containerd, CRI, or Kubernetes orchestration;
- remote Docker contexts, SSH/TCP endpoints, or Docker Desktop VMs;
- automatic image build, pull, push, or deletion;
- `--privileged`, `--pid=host`, or joining another container's PID namespace;
- mounting the Docker socket, host root, arbitrary devices, arbitrary capabilities, or arbitrary
  host directories;
- container networking diagnosis, GPU profiling, cross-container traces, or distributed APM;
- installing perf, debug packages, agents, or other dependencies inside a container.

Container cgroup metrics are environmental context; they are not a perf profile of every process
in the container.

## 3. User workflows

### 3.1 Project initialization

The project initialization interface is:

```bash
cd /absolute/project/path
perflens init --docker
```

It creates project-scoped integration and `perflens-setup/container-workload.toml`. It does not
start Docker, build an image, change Docker group membership, or deploy system services. The
configuration declares at least:

- existing-container attach or managed-temporary-container workflow;
- immutable digest of a local image;
- absolute in-container entry point, argv, and working directory;
- a fixed read-only project mount at `/workspace`;
- a PerfLens-managed writable scratch directory;
- container user, CPU, memory, PID, and network policy;
- preferred authorization mode;
- correctness checks and benchmark-output expectations.

Project configuration may persist preferences but never permanent execution authorization.

### 3.2 Existing-container attach

The user supplies a container name or ID; the container PID is optional. The fixed Docker adapter
first performs bounded, read-only discovery as the ordinary user:

1. a fixed-format `docker container inspect` resolves the full container ID, image ID, running
   state, and init host PID;
2. fixed `docker container top` arguments return candidate host PIDs belonging to the container;
3. `/proc/<pid>/status` supplies `NSpid`, `/proc/<pid>/ns/*` pins namespace inodes, and
   `/proc/<pid>/stat` start time plus the cgroup v2 inode bind the process incarnation;
4. a short CPU-delta observation returns only container PID, executable name, and CPU delta to the
   Agent;
5. one unique or clearly dominant candidate may be recommended automatically; multiple plausible
   candidates appear in the single authorization summary for user confirmation.

A container restart, PID reuse, target exit, namespace/cgroup change, or a container name resolving
to a different full ID invalidates the target and authorization immediately.

This authorization identifies one concrete service instance. Its full container ID, container
start identity, target PID/start time, and namespace/cgroup identity form the session target. A
material identity change may mean that this is no longer the service the user approved, so the
authorization cannot migrate automatically.

Existing containers default to `per_run` because they may host production or shared state.
PerfLens never pauses, restarts, stops, or removes them.

### 3.3 Managed temporary container

The managed workflow uses only a local image pinned by digest. A typed
`ContainerWorkloadSpecArtifact` derives every Docker argument; no user-provided Docker argument
string crosses the boundary.

Managed temporary-container authorization binds the stable `ContainerWorkloadSpecArtifact`, not
one run's container ID or PID. The stable template includes at least the project root and read-only
mount scope, image digest, entry point, argv, working directory, network and resource limits,
permitted collection modes, session budgets, and cleanup policy.

Every A/B run may create a new container instance with a new full container ID, host PID,
container PID, start time, namespace inode, and cgroup inode. These are expected managed-workflow
lifecycle changes and do not by themselves end `bounded_session`. PerfLens must prove that the
current session created the instance from the same WorkloadSpec, revalidate every Linux identity,
and derive a separate short-lived, single-use PID plan for that run.

The default sandbox is:

- project root mounted read-only at `/workspace`;
- writable files restricted to a private per-session scratch directory;
- `network=none` by default;
- privileged mode, host PID/network, devices, extra capabilities, and Docker socket forbidden;
- host paths outside the project root forbidden;
- fixed CPU, memory, and PID limits;
- a foreground workload that does not daemonize away from the bound PID.

To capture startup, PerfLens mounts a packaged, static Container Gate read-only as the temporary
container entry point. The Gate uses a bounded retry for the fixed private control socket, then
waits. After Docker creates the container, PerfLens first authenticates the live Gate with
`SO_PEERCRED` and its exact READY frame, then resolves and twice revalidates that pinned process's
Linux identity. The Collector completes its disabled-event attachment before the ordinary-user
coordinator permits the Gate to `execve` the exact workload. The Collector and Helpers receive
only a PID plan, never a Docker command, image, entry point, or environment.

At completion, PerfLens may stop and remove only a container whose full ID, session nonce, creation
receipt, and managed labels all match. Any uncertainty preserves the container and reports a manual
cleanup command; it never guesses or removes a user-owned container.

Without automatic image builds, changed code enters the same toolchain image through the read-only
`/workspace` mount and private scratch. Interpreted workloads can run directly. Compiled workloads
can write build output to scratch from the fixed container command or use host-produced artifacts
inside the project root. A project that requires rebuilding its image must do so through the user
or CI outside the optimization session. Editing source under `/workspace` does not end the
session, and each generated build artifact records its digest. Rebuilding an image changes its
digest and currently requires new authorization. A future in-session build capability needs a
separate fixed-build-recipe authorization; arbitrary image changes cannot inherit authorization.

## 4. Authorization model

### 4.1 `per_run`

Before each workload, PerfLens displays the target container, process, image, command, mounts,
network, resource limits, collection modes, and cleanup action. One explicit confirmation creates
one single-use plan. This is the default recommendation for existing containers.

### 4.2 `bounded_session`

The user-facing meaning of `bounded_session` is: **confirm once at the start of the current Agent
conversation, then do not ask again during that conversation.** It is the default recommendation
for deep optimization in managed temporary containers.

The confirmation must be a fresh user reply after the exact resolved session summary is shown.
An MCP permission prompt, persistent tool allowlist, Agent auto-approval mode, initial natural-
language optimization request, or authorization literal supplied by the model is not this consent.

```text
natural-language optimization request
      ↓
read-only project/image/command/capability resolution
      ↓
one immediate, complete session authorization summary
      ↓
explicit user approval
      ↓
in-memory session token
      ↓
stat → record/trace → edit → matched A/B
```

MCP and Agent clients do not necessarily expose a trusted, common conversation ID or a reliable
“conversation ended” event. PerfLens therefore creates an in-memory random session ID instead of
trusting a UI label. It binds:

- invoking UID, project root, and client connection identity;
- fixed image digest, entry point, argv, working directory, and mounts;
- existing container full ID and start identity, or the managed workload-spec digest;
- network, container user, and resource limits;
- permitted `stat/record/sched/off_cpu/lock` modes;
- per-collection duration, frequency, output, and spool limits;
- creation time, hard expiry, and cumulative budgets.

The default cumulative budget permits at most six workload executions and at most twenty minutes
of active workload runtime; each trace remains at most ten seconds. Administrators may only make
these values stricter. The two-hour value is an absolute token-lifetime backstop when a client
cannot report conversation end; it never replaces the six-run/twenty-minute execution budget.

The token remains only in memory and is never written to project configuration, artifacts, logs, or
disk caches. Every workload execution and collection still derives a separate short-lived,
single-use child plan. No repeated prompt does not mean plan reuse.

The session expires on the first of:

- an explicit Agent conversation or client-connection end;
- MCP exit, restart, or connection-identity change;
- the typed `revoke_docker_session` MCP call on the same client connection;
- a project-root identity or read-only mount-scope, image-digest, command, network, resource, or
  authorization-scope change;
- an administrator policy, feature-profile, or privilege-mode change;
- for an existing container, a full-container-ID, container-start, target-process-start,
  namespace, or cgroup identity change;
- for a managed temporary container, failure to prove that the current session created the new
  instance from the same `ContainerWorkloadSpecArtifact`, or any failed instance-identity check;
- exhaustion of administrator policy for cumulative executions, collection time, evidence bytes,
  or concurrency;
- the default two-hour hard backstop.

A new container ID and PID on each managed run are not expiry conditions. PID reuse or an instance
identity mismatch fails the current single-use collection plan immediately, after which PerfLens
resolves the current container again. It may issue a new single-use plan only when the new identity
still belongs to the same session and WorkloadSpec; otherwise the session expires.

The hard backstop covers clients that cannot report conversation end reliably; it does not cause
periodic prompts during a normal conversation. Reaching any bound stops the session. A new session
is created only if the user explicitly asks to continue and authorizes it again; no-response to an
automatic prompt is never consent.

### 4.3 Permanent authorization is forbidden

Projects may persist workload configuration and preferred authorization mode, not a permanent
permission to execute. Code and branches change, image tags move, container names are reused,
Agents can select the wrong target, repository content can contain prompt injection, Docker
argument validation may fail, and profiling can disturb production workloads.

The Docker daemon can create containers that mount host filesystems, so daemon control carries
strong host authority. PerfLens never interprets no response or a timeout as approval. See
[Docker Engine security](https://docs.docker.com/engine/security/).

## 5. Docker and privilege boundaries

### 5.1 Fixed Docker adapter

PerfLens does not add the Docker Python SDK and does not pass a socket file descriptor to an Agent.
The adapter accepts only an absolute Docker CLI whose owner, non-writable parents, resolved target,
and version pass checks. It clears endpoint, context, plugin, and TLS-related environment variables.

Existing-container discovery permits only fixed-template `container inspect` and fixed-field
`container top`. Managed containers additionally permit `create/start/wait/inspect/remove`, but all
arguments derive from strict artifacts. Arbitrary subcommands, format templates, `ps_args`, socket
paths, and environments are rejected.

Only two local Unix-socket classes are supported: an administrator-reviewed rootful socket and the
current user's fixed Rootless socket. Socket/parent inode, owner, mode, and peer identity are pinned
before and after operations. `DOCKER_HOST`, custom contexts, TCP, SSH, and symlink replacement are
unsupported.

Docker inspect/top is discovery evidence, not final authorization. Docker's API can report
container information and host PIDs, but Linux kernel identity must prove the final target. See the
[Docker process API](https://docs.docker.com/reference/api/engine/version/v1.47/).

### 5.2 Rootless, same UID, and rootful

Rootless Docker maps container root to the host user running the daemon, while userns-remap may map
it to a high subordinate UID. PerfLens authorizes the observed host UID and never guesses from the
UID shown inside the container. See
[Docker UID/GID mapping](https://docs.docker.com/engine/security/rootless/uid-gid-mapping/).

The default allows:

- Rootless Docker targets whose host UID equals the invoking UID;
- rootful Docker targets explicitly running as the invoking host UID.

Rootful UID 0 is denied by default. An administrator may enable the implemented
`allow_rootful_container_targets = true` policy with a separate risk acknowledgement. It applies
only to fully verified Docker targets, does not enable generic `allow_other_target_uids`, and does
not require sudo for every later collection.

Rootful `stat/record` executes through the bounded Rust Helper, which independently validates the
request peer, plan, target PID/UID, start time, PID/user/mount namespaces, and cgroup. The Python
Broker receives neither root nor `CAP_SYS_PTRACE`. Advanced trace remains in the independent Trace
Helper. The existing Helper mode set stays limited to `stat/record`; it never receives Docker
commands or a Docker socket.

## 6. Target identity and protocol

v0.3.1 adds these versioned public artifacts:

- `DockerRuntimeCapabilityArtifact`: Docker CLI, endpoint class, daemon mode, cgroup version,
  Rootless/rootful state, and capability;
- `ContainerTargetArtifact`: immutable container/image digests, container PID, host PID/UID/start
  time, and namespace/cgroup binding;
- `ContainerProcessInventoryArtifact`: bounded, sanitized candidates and short CPU deltas;
- `ContainerResourceContextArtifact`: before/after cgroup snapshots, deltas, scope, and limits;
- `ContainerWorkloadSpecArtifact`: fixed image, workload, mounts, network, user, and resources;
- `ContainerOptimizationSessionArtifact`: authorization mode, bound digest, budgets, and expiry;
- `ContainerRunArtifact`: managed-container lifecycle, target PID, exit status, and Collection ID;
- `ContainerModuleSnapshotArtifact` and `ContainerSymbolContextArtifact`: bounded module identity,
  Build ID, mapping quality, and privacy-preserving source context;
- `ContainerMeasurementArtifact` and `ContainerMatchedComparisonArtifact`: Collection/cgroup/run/
  benchmark bindings and a conservative matched A/B conclusion.

Collection Plan/Artifact gains a backward-compatible version with an optional container-target
digest; old Host-PID artifacts remain readable as Host targets. Broker, stat/record Helper, and
Trace Helper protocols each add a strict container-target union. Old peers handle only Host-PID
plans and must explicitly reject a container plan rather than ignore new fields.

A private receipt retains the full container ID, socket identity, and raw cgroup path required for
revalidation. Public artifacts contain only:

- container and image identity digests;
- container PID and target host PID/UID/start time;
- namespace/cgroup inodes or non-correlatable digests;
- Docker adapter path, version, hash, and fixed recipe ID;
- cgroup snapshots and evidence quality;
- allowed and forbidden conclusions.

Full inspect responses, environment variables, Docker labels, secrets, mount source paths, socket
paths, out-of-target argv, and raw cgroup paths are forbidden in public artifacts, errors, and logs.

The Broker and every privileged Helper recheck host PID, UID, `/proc/<pid>/stat` start time,
`NSpid`, namespace inodes, and cgroup identity before collection and again after perf exits. Linux
`/proc` exposes namespace-level IDs such as `NSpid`, while cgroup v2 provides process membership and
resource interfaces. See the [Linux `/proc` documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
and [cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## 7. Collection, resources, and symbolization

### 7.1 perf and trace

perf always uses the revalidated host PID:

- `stat/record` reuse hardware-first collection, software fallback, and evidence limitations;
- `sched/off_cpu/lock` reuse the v0.3.0 in-kernel target-filtered Trace Helper;
- `perf -a`, all CPUs, a whole cgroup, or all container PIDs are never implicit fallbacks;
- perf need not exist inside the container, and PerfLens installs nothing there.

### 7.2 cgroup v2 context

PerfLens takes before/after read-only snapshots through an inode-pinned container cgroup directory,
including at least:

- `cpu.stat`, `cpu.max`, and `cpuset.cpus.effective`;
- `memory.current`, `memory.max`, `memory.events`, and available memory pressure;
- `io.stat` and available I/O pressure;
- `pids.current` and `pids.max`.

Parsing is bounded by file, line, field, device, and total-byte limits. The cgroup v2 documentation
notes that `cgroup.procs` can contain duplicates or PID reuse during a read, so membership never
rests on one text snapshot; it is combined with process incarnation, namespace, and cgroup inode.

These counters cover the whole container. A report may state that throttling or memory events were
observed, but cannot present container totals as target-process-exclusive cost or infer code root
cause from correlation alone.

### 7.3 Container symbols and source

`record` analysis remains based on Build IDs and validated module-relative offsets. For modules in
the container rootfs:

1. pin the target mount namespace and `/proc/<host-pid>/root` directory identity;
2. open only modules referenced by perf mappings, never enumerate or export the whole rootfs;
3. bound module count, per-file/total bytes, symbol queries, and debug files;
4. map in-container source paths to the user-authorized workspace through the existing
   SourceLocator;
5. mark evidence `partial` on target exit or file-identity change and never guess a module from a
   path or address.

Public evidence retains only module Build ID, content digest, container-path digest, and workspace
mapping result. Container secrets, configuration, and unrelated files are excluded.

## 8. Analysis and A/B quality

The diagnosis report discloses:

- Docker target kind, image identity digest, and container user mapping;
- container-PID to host-PID binding status;
- actual event source, fallback, and PMU limitations;
- cgroup limits, interval deltas, and their container-wide scope;
- module/source resolution coverage;
- container restart, target exit, event loss, and resource truncation;
- allowed and forbidden conclusions.

A matched A/B requires the same:

- image and Container Gate digests;
- entry point, argv, working directory, mount layout, and network mode;
- container user, CPU, cpuset, memory, I/O, and PID limits;
- host kernel, perf, Collector profile, event source, and sampling configuration;
- workload parameters, input digest, and correctness assertions.

Different temporary container IDs do not make a comparison invalid when the environment
fingerprint matches. Source or build-artifact digest can be the treatment under comparison. Only a
correctness-preserving, environment-matched before/after measurement with an absolute metric may
be called a `Verified Improvement`.

## 9. CLI, MCP, and Skill experience

The stable CLI entry point is project initialization:

```bash
perflens init --docker
```

It writes `perflens-setup/container-workload.toml`; project users review and edit that fixed policy
before asking an Agent to collect. Session state is deliberately owned by the long-lived MCP
connection, so authorization and revocation are MCP tools rather than misleading one-shot CLI
commands that could not reach another process's in-memory token. The implemented typed tools are:

- `inspect_docker_capability`, `discover_docker_processes`, and `resolve_docker_target` for bounded
  read-only discovery;
- `authorize_docker_session` or `authorize_managed_docker_session` for explicit `per_run` or
  `bounded_session` authorization;
- `collect_docker_target` or `collect_managed_docker_workload` for the authorized workflow;
- `revoke_docker_session` for same-connection revocation;
- existing analysis tools plus `compare_container_measurements` for verified projection and A/B.

`perflens init` never enables Docker execution silently. Typed MCP tools separately gate:

- container capability/process discovery;
- existing-container attachment;
- managed temporary-container launch;
- optimization-session creation and revocation;
- collection, analysis, and sanitized artifact reads.

Docker identity read access does not authorize container execution, and existing-container attach
does not authorize managed launch. The Skill follows:

```text
inspect project and Docker capability
      ↓
resolve exact container workload or existing target
      ↓
produce one authorization summary
      ↓
stat
 ├─ CPU-bound → record
 ├─ runnable anomaly → sched
 ├─ long wall time with low CPU → off_cpu
 └─ contention candidate → lock
      ↓
edit + correctness checks + matched A/B
```

Even the words “deeply optimize” cannot let the Agent expand image, command, mounts, network,
target, duration, or privilege beyond the intersection of the conversation authorization and
administrator policy.

## 10. Implemented milestones

The implementation landed as independent, reversible commits in this order:

1. public contracts and schemas for Docker capability, target, resource, workload, session, and run;
2. fixed inspect/top adapter, socket identity pinning, and bounded sanitized parsing;
3. `/proc`, `NSpid`, namespace, cgroup v2, and PID-reuse target resolver;
4. cgroup v2 snapshots, deltas, quality model, and verifier;
5. existing-container single-PID plan → policy → broker → artifact path;
6. static Container Gate, managed launcher, and failure-safe cleanup;
7. `per_run`, conversation-scoped `bounded_session`, in-memory token, revocation, and hard limits;
8. rootful-container policy, independent Helper checks, and risk acknowledgement;
9. container module/Build ID/source mapping and diagnosis bundles;
10. CLI, MCP, Skill routing, and matched A/B;
11. DEB, upgrade/removal, real-Docker matrix, and bilingual release documentation.

Each milestone passed focused normal, denial, lint, type, and protocol checks before the next one.
Docker execution was exposed to MCP only after identity and artifact contracts were stable.

## 11. Tests and release gates

### 11.1 Deterministic and security tests

At minimum:

- malformed, oversized, unknown-field, non-UTF-8 inspect/top output; tool and socket replacement;
- Docker name reuse, full-ID change, restart, PID reuse, target exit, and dynamic threads;
- every NSpid, namespace, cgroup, UID, and start-time mismatch;
- unacknowledged rootful target, generic cross UID, host PID namespace, and shared PID namespace;
- arbitrary Docker command/argument, remote endpoint, build/pull, privileged mode, device,
  capability, socket, and host-path mount denial;
- cross-project/client/user/container session replay, MCP restart, revocation, hard expiry, and
  budget exhaustion;
- no environment, label, mount source, socket path, or out-of-target argv in public artifacts,
  errors, or logs;
- cgroup fields, deltas, overflow, reset, truncation, and container-wide scope;
- module/rootfs symlink, target exit, Build ID mismatch, and source-path escape;
- cleanup only for a container created by the current session; uncertain identity never removes.

### 11.2 Real environment matrix

Before release, Debian 12/13, cgroup v2, and systemd/cgroupfs drivers cover:

- Rootless Docker;
- rootful Docker with a process running as the invoking host UID;
- administrator-acknowledged rootful UID 0;
- existing and managed temporary containers;
- interpreted and compiled Python/C/C++ workloads;
- `stat/record` and all three `full_diagnostics` trace modes;
- hardware PMU and software-event fallback;
- CPU quota/throttling, cpuset, memory events, I/O, and PID limits;
- startup, short processes, dynamic threads, restart, and failed cleanup;
- container module symbols, workspace source mapping, and matched A/B.

### 11.3 Packaging and upgrades

Both DEBs remain independent of Docker. They do not install or start Docker, create Docker config,
add users to a Docker group, enable project Docker integration, or allow rootful targets. A
`0.3.0 → 0.3.1` upgrade preserves Host targets and Collector policy; the administrator and project
user enable Docker and rootful boundaries separately and explicitly.

v0.3.1 may claim stable Docker process support only after contracts, parsing, Broker/Helper denial
paths, both workflows, conversation authorization, cgroup context, symbols, the real-Docker matrix,
and package upgrade/removal tests all pass. A missing core workflow requires a narrower claim or a
delayed release; “Docker support” must not hide a partial implementation.
