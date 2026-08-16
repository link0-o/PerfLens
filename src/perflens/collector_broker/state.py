"""Names and metadata rules for Collector-owned spool state."""

from __future__ import annotations

import os
import re
import stat

_PLAN_ID = re.compile(r"^plan-[a-f0-9]{20}$")
_COLLECTION_ARTIFACT = re.compile(r"^plan-[a-f0-9]{20}\.(?:stat\.csv|perf\.data)$")
_TRACE_EVIDENCE_ARTIFACT = re.compile(r"^trace-evidence-[a-f0-9]{16,64}\.json$")
_REPLAY_MARKER = re.compile(r"^\.perflens-consumed-(plan-[a-f0-9]{20})$")


def collection_artifact_name(name: str) -> bool:
    """Return whether a spool basename is a Collector collection artifact."""
    return _COLLECTION_ARTIFACT.fullmatch(name) is not None


def trace_evidence_artifact_name(name: str) -> bool:
    """Return whether a spool basename is a public normalized Trace artifact."""
    return _TRACE_EVIDENCE_ARTIFACT.fullmatch(name) is not None


def replay_marker_name(plan_id: str) -> str:
    """Return the fixed hidden marker basename for one validated plan ID."""
    if _PLAN_ID.fullmatch(plan_id) is None:
        raise ValueError("Collector replay marker requires a valid plan ID")
    return f".perflens-consumed-{plan_id}"


def replay_marker(name: str) -> bool:
    """Return whether a spool basename is reserved for replay prevention."""
    return _REPLAY_MARKER.fullmatch(name) is not None


def safe_replay_marker_metadata(
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
) -> bool:
    """Validate one empty, service-owned, private replay marker."""
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == expected_uid
        and metadata.st_gid == expected_gid
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_nlink == 1
        and metadata.st_size == 0
    )
