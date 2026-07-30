# Artifact schema compatibility

Artifacts use semantic schema versions.

- Patch changes clarify documentation or relax compatible validation.
- Minor changes add optional fields and require old-artifact compatibility tests.
- Major changes alter semantics and require an explicit migration utility.

Schema `1.0` has no predecessors. Readers reject unsupported major versions.
Deterministic fields and aggregation semantics participate in the analysis
fingerprint; changing them invalidates cached output.
