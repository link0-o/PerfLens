# Artifact schema compatibility

[简体中文](schema-migrations.zh-CN.md) | English

Artifacts use semantic schema versions.

- Patch changes clarify documentation or relax compatible validation.
- Minor changes add optional fields and require old-artifact compatibility tests.
- Major changes alter semantics and require an explicit migration utility.

Schema `1.0` has no predecessors. Readers reject unsupported major versions.
Deterministic fields and aggregation semantics participate in the analysis
fingerprint; changing them invalidates cached output.

Runtime status schema `1.0` may include optional Collector health, service
identity, policy, allowed-mode, and spool fields. Readers preserve defaults for
older status artifacts that predate the authenticated health handshake.

Setup schema `1.0` may include optional Codex/Claude project configuration
paths, install states, and project Skill fingerprints. Readers treat older
setup artifacts as generation-only onboarding with no recorded Skill ownership.

Project detach results use the independent `ProjectDetachmentArtifact` schema
`1.0`. It may record selected clients, Skill removal policy, Codex/Claude and
Skill states, exact removed paths, and known preserved paths. Older payloads
default to the original Codex-only, Skill-preserving behavior.

Collector TOML policies use an independent integer `policy_version`. Generated
policies currently write version `1`; a missing field is read as legacy version
1 for compatibility, while unsupported versions are rejected before deployment
or Collector startup. Future policy changes must add compatibility and denial
tests in both boundaries.

Public Collection, Plan, Capability, and Collector Acceptance artifacts remain
schema `1.0`; the new event-source, software-fallback, and PMU-acceptance fields
have compatible defaults. An older Collection without provenance reads as
`actual_event_source=unknown` and must not be inferred to contain hardware
evidence.

Collector Acceptance `hardware_collection_id` identifies every safely
published hardware attempt, including a retained zero-count artifact. Consumers
must use `hardware_pmu_status` and `hardware_pmu_reason` to decide whether that
attempt was usable; a non-null ID is evidence linkage, not a statement that the
PMU worked. The public contract is checked in as
`schemas/collector-acceptance.schema.json`.

The private Python-Broker/Rust-Helper protocol moves from `1.0` to `1.1` because
requests now bind fixed event-source/fallback policy and responses return the
actual source and evidence events. It is not a user artifact and has no
cross-version negotiation: packages upgrade and restart Broker and Helper
together, and a mismatch fails closed.
