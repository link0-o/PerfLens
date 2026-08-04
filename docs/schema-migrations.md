# Artifact schema compatibility

[简体中文](schema-migrations.zh-CN.md) | English

Artifacts use semantic schema versions.

- Patch changes clarify documentation or relax compatible validation.
- Minor changes add optional fields and require old-artifact compatibility tests.
- Major changes alter semantics and require an explicit migration utility.

Schema `1.0` has no predecessors. Readers reject unsupported major versions.
Deterministic fields and aggregation semantics participate in the analysis
fingerprint; changing them invalidates cached output.

Collector TOML policies use an independent integer `policy_version`. Generated
policies currently write version `1`; a missing field is read as legacy version
1 for compatibility, while unsupported versions are rejected before deployment
or Collector startup. Future policy changes must add compatibility and denial
tests in both boundaries.
