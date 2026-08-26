# PerfLens v0.3.2 bounded Docker optimization contract

[简体中文](docker-optimization-roadmap.zh-CN.md)

Status: the v0.3.2 release-candidate interfaces are implemented, but the open security and
multi-client findings in [Known issues](known-issues.md) prevent a release-ready claim. Contracts,
context capture, the typed Build Adapter, one-confirmation session tools, Build-bound collection,
deterministic A/B comparison, and Agent policy exist. Full rootless/rootful Docker and installed-host
acceptance also remain release gates. Release v0.3.1 fixed-image collection remains supported.

## Outcome and boundary

`bounded_optimization_session` is one user-confirmed, connection-scoped authorization for an
Agent to build a baseline, collect evidence, admit changes only from reviewed project paths into
build snapshots, build up to three candidates, and perform matched A/B validation. Filesystem
write permission remains a client-sandbox boundary, not a capability enforced by PerfLens. The
session is not permanent approval and never authorizes
commit, push, tags, releases, arbitrary Docker arguments, or access outside the declared project
context.

The session is a Docker target workflow, not a Collector privilege mode. The existing
`cpu_only/full_diagnostics` feature profile and `cap_perfmon/paranoid3_helper` privilege mode still
determine which perf evidence is available. The v0.4.0 runtime-lock adapters are outside v0.3.2.

## Project contract

`perflens init --docker` writes `container-workload.toml` schema 1.1 with `[optimization]` disabled.
Schema 1.0 remains a strict, supported fixed-image input. Update mode preserves an existing user
policy and never enables builds, network, or additional paths.

An enabled optimization contract binds:

- explicit `context_paths` and their `mutable_paths` subset;
- a project-relative Dockerfile, target, Linux platform, fixed build arguments, and exact base
  image digest;
- one network tier and optional administrator Builder policy identity;
- the existing fixed entrypoint, argv, UID/GID, resource limits, Benchmark output/format/name, and
  correctness contract;
- at most three candidate rounds, four builds, ten workload runs, and one recoverable retry.

Dockerfiles and dependency lock files are immutable unless explicitly listed in `mutable_paths`.
That exception is high risk and must be shown in the authorization preview. An empty Benchmark is
valid for v0.3.1-style diagnosis but cannot authorize automated optimization or produce a Verified
Improvement.

The package supplies a root-owned, read-only, empty Docker configuration as its trust anchor.
Because Buildx must persist Builder-selection state, every Preview creates an empty runtime
configuration below a randomized, user-private `0700` directory. It never copies the user's Docker
configuration, credentials, or Context, and has its inode, owner, and mode revalidated before
every command. Explicit revocation removes private runtime state immediately when safe; expired
Preview/session state is reclaimed by a bounded timer and by any later interaction. MCP connection
shutdown revokes active authority and performs the same identity-verified cleanup. A process crash
may still leave proven session objects for manual review; global Docker pruning remains forbidden.

## Implemented typed interfaces (host acceptance still required)

The v0.3.2 implementation exposes these MCP tools:

- `inspect_docker_optimization_capability`;
- `preview_docker_optimization_session`;
- `authorize_docker_optimization_session`;
- `build_docker_optimization_candidate`;
- `collect_docker_optimization_workload`;
- `compare_docker_optimization_iterations`;
- `revoke_docker_optimization_session`.

It persists versioned `DockerBuildCapabilityArtifact`, `DockerBuildRecipeArtifact`,
`DockerBuildContextArtifact`, `DockerBuildArtifact`, `DockerOptimizationSessionArtifact`, and
`DockerOptimizationIterationArtifact` values. Confirmation tokens remain only in MCP memory;
public artifacts retain a receipt digest, budgets, state, identities, and evidence hashes, never a
token, credential, absolute host path, Docker endpoint path, or source contents.

## Build snapshot and adapter

The typed Build Adapter is the only component allowed to issue fixed Docker/Buildx operations.
The Agent, Skill, public Broker, and perf Helpers do not receive the Docker socket or arbitrary
Docker arguments. Before and after every operation the adapter revalidates the CLI, Buildx plugin,
local Unix endpoint, and selected Builder identity.

Every build consumes a private immutable tar snapshot derived only from `context_paths`. The
snapshot records relative name, regular-file/directory/symlink type, mode, size, and SHA-256. It
rejects absolute or escaping paths, escaping or absolute symlinks, sockets, devices, FIFOs, Git
metadata, credential directories, and file identity changes during capture. A relative symlink is
allowed only when its final target is also captured. Changes to immutable entries invalidate the
session; changes to mutable entries become the candidate Treatment.

The adapter obtains the result through private IID and metadata files, then independently verifies
the final digest, platform, image size, session labels, Recipe digest, Context digest, and build
provenance. Exporter identity accepts Buildx's documented config-digest/descriptor projection and
its legacy image-digest-only projection; every present digest must be well formed and contradictory
config or manifest claims are rejected. Failures retain only a bounded digest projection, never raw
metadata. Cleanup removes only identities proven to have been created by this session and not
referenced by pre-existing tags or other containers. Global image or cache pruning is forbidden.

## Network tiers

1. `local_only` is the default. The exact base digest must already exist; pull is false and build
   networking is none. Dockerfile validation admits only `RUN --network=none` in this tier and
   rejects malformed, `default`, `host`, or custom per-instruction overrides.
2. `pinned_pull` may fetch only a complete digest from an administrator registry allowlist after
   confirmation. The build itself has no network, so it has the same `RUN --network=none` rule.
3. `admin_builder_network` may use only a predeployed, root-owned, identity-pinned
   `docker-container` BuildKit Builder. Its image, network, proxy/CNI settings, registry scope, and
   Buildx source policy are administrator inputs; PerfLens never creates or mutates the Builder.
   Dockerfile `RUN --network` may be `none` or `default`, but no other value.

For `local_only`, the configured digest may be a local image ID rather than a registry
`RepoDigest`. BuildKit must not resolve that value through a registry. The typed adapter therefore
creates an unpredictable session-private tag for the already verified local image, replaces only
the validated external `FROM` references in an unlinked derived Context, and leaves the authorized
Dockerfile and Context snapshot unchanged. It revalidates the tag identity, requires Buildx
provenance materials to bind the configured digest, and removes only the tag it proved it created.
A pre-existing, replaced, or otherwise ambiguous tag is never overwritten or removed.

Remote Docker contexts, host networking, insecure/device entitlements, secret or SSH mounts,
extra build contexts, arbitrary cache import/export, host mounts, tag-only base images, remote
`ADD`, and remote custom frontends are always rejected. A/B runs with network access must bind the
same Builder/network policy and resolved provenance.

## Authorization, budgets, and Agent choices

The preview exposes the exact normalized project-relative `context_paths` and `mutable_paths`, and
hashes them with the current Recipe, Context, Benchmark, Collector policy, Builder policy, and all
limits. This is the informed-consent surface: the Agent must not replace the returned path lists
with an inference such as “no mutable paths.” If no result image exists, the preview says that a
baseline build will occur after confirmation; no build or pull happens during preview.
Authorization requires the exact preview digest and fixed confirmation token, creates an in-memory
lease bound to the client connection, and prevents replay.

The Agent selects evidence instead of running every mode mechanically: begin with the cheapest
correctness/Benchmark and `stat` evidence, then use `record`, `sched`, `off_cpu`, or `lock` only when
the observed problem warrants it. A security rejection, identity change, or correctness failure is
not retried unchanged. A recoverable build or test failure may consume the session's single retry.

Fixed ceilings are three candidates, four builds, ten workloads, 900 seconds per build, 3600
seconds total build time, 1800 seconds workload activity, a 7200-second hard expiry, 1 GiB evidence,
10 GiB temporary images, and concurrency one. Record is limited to 30 seconds at 99 Hz; each Trace
observation is limited to 10 seconds. Reaching any limit ends useful work and cannot silently create
a new session. Every successful stat, record, or Trace result carries the Broker-verified raw
evidence byte count into the optimization session; the reserved maximum is replaced by that actual
positive count instead of being silently released to zero.

## Matched A/B and Verified Improvement

The invariant set includes the base digest, Builder/network identity, immutable Dockerfile recipe,
target/platform/build arguments, command, resources, Benchmark contract, Collector policy, kernel,
perf version, and actual event source. Treatment includes mutable-path hashes, executable hashes
and Build IDs, and the final candidate image digest. Different final digests produced by the same
authorized Recipe are expected and do not invalidate the session.

`Verified Improvement` requires passing correctness, matching Benchmark target and parameters,
matching environment and event source, the configured metric threshold, evidence consistent with
the hypothesis, no unacceptable CPU/memory/I/O/throttling transfer, and deterministic hash,
conservation, and replay verification. Partial evidence, a missing Benchmark, correctness failure,
or any invariant mismatch can produce only a candidate conclusion.

## Implementation and release gates

Implementation is split into independently reviewed commits: version/config contract; build
artifacts and snapshot; Build Adapter; session/MCP; matched A/B plus Agent integration; and final
package/host/Docker acceptance. Each stage needs normal, denial, boundary, lint, type, schema, and
relevant Python/Rust protocol tests before the next begins.

The local candidate has passed Python 3.12/3.13, the 85% coverage gate, reproducible wheel/sdist
and DEB builds, package smoke, schema/protocol checks, and the Rust format, Clippy, test, audit, and
deny gates. The 2026-08-26 source audit findings are resolved with denial-path regression tests.
Stable release still requires installed-host non-activation/upgrade/rollback/removal, v0.3.1 host
and fixed-Docker regression, and real rootless/rootful Docker acceptance. PerfLens does not create
the v0.3.2 tag as part of the optimization session or this implementation contract.
