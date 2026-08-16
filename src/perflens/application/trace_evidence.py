"""Deterministic identity and integrity checks for normalized trace evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.trace import (
    FutexWaitEvent,
    FutexWakeEvent,
    LockReleasedEvent,
    LockWaitEndedEvent,
    LockWaitEvent,
    SchedMigrateEvent,
    SchedSwitchEvent,
    SchedWakeupEvent,
    TraceCaptureManifest,
    TraceConversionManifest,
    TraceEvent,
    TraceEvidenceArtifact,
    TraceRawArtifactReference,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_EVIDENCE_FINGERPRINT_DOMAIN = "perflens.trace-evidence.v1"


@dataclass(frozen=True, slots=True)
class VerifiedPrivateRawSnapshot:
    """Sanitized result of re-hashing one private raw file through a safe descriptor."""

    collection_id: str
    mode: Literal["sched", "off_cpu", "lock"]
    collection_artifact_sha256: str
    output_sha256: str
    output_bytes: int
    capture_fingerprint: str


def verify_private_raw_snapshot(
    source: TraceRawArtifactReference,
    raw_path: Path,
    *,
    max_input_bytes: int,
    expected_owner_uid: int,
    expected_owner_gid: int,
    expected_mode: int,
) -> VerifiedPrivateRawSnapshot:
    """Re-hash a private source without copying its path into a public object or error."""
    if isinstance(max_input_bytes, bool) or max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    if (
        isinstance(expected_owner_uid, bool)
        or isinstance(expected_owner_gid, bool)
        or expected_owner_uid < 0
        or expected_owner_gid < 0
    ):
        raise ValueError("expected private raw owner identities must be non-negative")
    if expected_mode not in {0o600, 0o640}:
        raise ValueError("expected private raw mode must be exactly 0600 or 0640")
    if source.capture.capture_fingerprint != compute_trace_capture_fingerprint(source.capture):
        raise _private_raw_error(source, "trace capture manifest fingerprint mismatch")
    descriptor = -1
    try:
        preliminary = raw_path.stat(follow_symlinks=False)
        descriptor = os.open(
            raw_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != source.output_bytes
            or before.st_size > max_input_bytes
            or before.st_uid != expected_owner_uid
            or before.st_gid != expected_owner_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
            or _raw_file_identity(preliminary) != _raw_file_identity(before)
        ):
            raise _private_raw_error(source, "private raw identity or permissions are unsafe")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, min(1 << 20, max_input_bytes + 1 - total)):
            total += len(chunk)
            if total > max_input_bytes:
                raise _private_raw_error(source, "private raw input exceeds its verification limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = raw_path.stat(follow_symlinks=False)
    except PerfLensError:
        raise
    except OSError:
        # The originating OSError commonly embeds the private spool path.  Suppress the
        # exception chain so neither structured errors nor ordinary tracebacks disclose it.
        raise _private_raw_error(source, "private raw input cannot be opened safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if _raw_file_identity(before) != _raw_file_identity(after) or _raw_file_identity(
        after
    ) != _raw_file_identity(current):
        raise _private_raw_error(source, "private raw input changed while it was read")
    if total != source.output_bytes or digest.hexdigest() != source.output_sha256:
        raise _private_raw_error(source, "private raw size or SHA-256 differs from its receipt")
    return VerifiedPrivateRawSnapshot(
        collection_id=source.collection_id,
        mode=source.mode,
        collection_artifact_sha256=source.collection_artifact_sha256,
        output_sha256=source.output_sha256,
        output_bytes=source.output_bytes,
        capture_fingerprint=source.capture.capture_fingerprint,
    )


def canonical_trace_json_sha256(payload: object) -> str:
    """Hash one JSON-compatible value using the public contract encoding."""
    encoded = json.dumps(
        _json_value(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_trace_conversion_fingerprint(manifest: TraceConversionManifest) -> str:
    """Bind every public conversion field except the digest itself."""
    return contract_content_sha256(manifest, exclude={"conversion_fingerprint"})


def compute_trace_capture_fingerprint(manifest: TraceCaptureManifest) -> str:
    """Bind the private producer identity, scope, compatibility, and event formats."""
    return contract_content_sha256(manifest, exclude={"capture_fingerprint"})


def normalized_trace_ndjson(events: Sequence[TraceEvent]) -> bytes:
    """Serialize normalized events in their canonical, hashable NDJSON form."""
    lines = (
        json.dumps(
            event.model_dump(mode="json", exclude_none=True),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        for event in events
    )
    text = "".join(f"{line}\n" for line in lines)
    return text.encode("utf-8")


def normalized_trace_ndjson_identity(events: Sequence[TraceEvent]) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    for event in events:
        line = (
            json.dumps(
                event.model_dump(mode="json", exclude_none=True),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
        digest.update(line)
        byte_count += len(line)
    return digest.hexdigest(), byte_count


def compute_trace_evidence_fingerprint(evidence: TraceEvidenceArtifact) -> str:
    """Bind raw identity, target scope, conversion, normalized data, and limits."""
    material = {
        "domain": _EVIDENCE_FINGERPRINT_DOMAIN,
        "schema_version": evidence.schema_version,
        "mode": evidence.mode,
        "source": evidence.source,
        "target": evidence.target,
        "conversion_fingerprint": compute_trace_conversion_fingerprint(evidence.conversion),
        "clock": evidence.clock,
        "observation_window": evidence.observation_window,
        "quality": evidence.quality,
        "limits": evidence.limits,
        "normalized_ndjson_sha256": evidence.normalized_ndjson_sha256,
        "normalized_ndjson_bytes": evidence.normalized_ndjson_bytes,
        "input_line_count": evidence.input_line_count,
        "diagnostic_count": evidence.diagnostic_count,
        "allowed_conclusions": evidence.allowed_conclusions,
        "forbidden_conclusions": evidence.forbidden_conclusions,
    }
    return canonical_trace_json_sha256(material)


def compute_trace_evidence_content_sha256(evidence: TraceEvidenceArtifact) -> str:
    """Bind every Agent-visible evidence field except the digest itself."""
    return contract_content_sha256(evidence, exclude={"content_sha256"})


def trace_evidence_invariant_failures(
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    """Return bounded deterministic failures, including checks bypassed by model_copy."""
    failures: list[str] = []
    if evidence.input_sha256 != evidence.source.output_sha256:
        failures.append("input SHA-256 differs from the private raw receipt")
    if evidence.input_bytes != evidence.source.output_bytes:
        failures.append("input byte count differs from the private raw receipt")
    if evidence.mode != evidence.source.mode:
        failures.append("evidence mode differs from the private raw receipt")
    expected_recipe = {
        "sched": "sched-v1",
        "off_cpu": "off-cpu-v1",
        "lock": "lock-v1",
    }[evidence.mode]
    if evidence.conversion.recipe_id != expected_recipe:
        failures.append("conversion recipe differs from the evidence mode")
    expected_capture = compute_trace_capture_fingerprint(evidence.source.capture)
    if evidence.source.capture.capture_fingerprint != expected_capture:
        failures.append("capture manifest fingerprint mismatch")
    expected_conversion = compute_trace_conversion_fingerprint(evidence.conversion)
    if evidence.conversion.conversion_fingerprint != expected_conversion:
        failures.append("conversion manifest fingerprint mismatch")

    expected_ndjson_sha256, expected_ndjson_bytes = normalized_trace_ndjson_identity(
        evidence.events
    )
    if evidence.normalized_ndjson_sha256 != expected_ndjson_sha256:
        failures.append("normalized NDJSON SHA-256 mismatch")
    if evidence.normalized_ndjson_bytes != expected_ndjson_bytes:
        failures.append("normalized NDJSON byte count mismatch")
    if len(evidence.events) != evidence.quality.emitted_event_count:
        failures.append("normalized event count differs from emitted_event_count")
    if not evidence.events and (
        evidence.status != "partial" or evidence.quality.quality_status != "partial"
    ):
        failures.append("empty normalized evidence was not marked partial")
    if evidence.input_line_count > evidence.limits.max_input_lines:
        failures.append("input line count exceeds max_input_lines")
    if evidence.input_line_count < evidence.quality.input_event_count:
        failures.append("input line count is below input_event_count")
    if evidence.diagnostic_count > evidence.limits.max_diagnostics:
        failures.append("diagnostic count exceeds max_diagnostics")

    dropped = (
        evidence.quality.malformed_event_count
        + evidence.quality.duplicate_event_count
        + evidence.quality.out_of_order_event_count
        + evidence.quality.unsupported_event_count
        + evidence.quality.truncated_event_count
        + evidence.quality.foreign_event_dropped_count
    )
    if evidence.quality.input_event_count + evidence.quality.expanded_derived_event_count != (
        evidence.quality.emitted_event_count
        + evidence.quality.merged_enrichment_event_count
        + dropped
    ):
        failures.append("input event dispositions do not conserve input_event_count")
    if evidence.quality.unpaired_event_count > evidence.quality.emitted_event_count:
        failures.append("unpaired event count exceeds emitted events")
    degraded = bool(
        evidence.quality.input_event_count == 0
        or evidence.quality.emitted_event_count == 0
        or evidence.quality.lost_event_count
        or evidence.quality.unpaired_event_count
        or dropped
        or evidence.quality.diagnostics_truncated
        or evidence.diagnostic_count
        or evidence.source.capture.backend_id != "target_filtered_kernel_v1"
    )
    expected_quality = "partial" if degraded else "verified"
    if evidence.quality.quality_status != expected_quality:
        failures.append("quality status does not match loss/drop/truncation counters")
    expected_status = "partial" if degraded else "complete"
    if evidence.status != expected_status:
        failures.append("artifact status does not match evidence quality")
    if degraded and not evidence.quality.limitations:
        failures.append("degraded trace evidence omits an explicit limitation")

    target_tid_sequence = evidence.target.observed_target_tids
    target_tids = set(target_tid_sequence)
    if len(target_tids) != len(target_tid_sequence):
        failures.append("observed target TID identities are not unique")
    if tuple(sorted(target_tid_sequence)) != target_tid_sequence:
        failures.append("observed target TID identities are not canonical")
    if len(target_tids) > evidence.limits.max_unique_target_tids:
        failures.append("observed target TID identities exceed max_unique_target_tids")
    event_ids: set[str] = set()
    previous_sort_key: tuple[int, int, int, str] | None = None
    for expected_index, event in enumerate(evidence.events):
        if event.event_id in event_ids:
            failures.append("normalized event IDs are not unique")
        event_ids.add(event.event_id)
        if event.event_index != expected_index:
            failures.append("normalized event indexes are not contiguous")
        sort_key = (
            event.timestamp_ns,
            event.cpu,
            event.source_sequence,
            event.event_id,
        )
        if previous_sort_key is not None and sort_key < previous_sort_key:
            failures.append("normalized events violate canonical source ordering")
        previous_sort_key = sort_key
        if not (
            evidence.observation_window.start_timestamp_ns
            <= event.timestamp_ns
            <= evidence.observation_window.end_timestamp_ns
        ):
            failures.append("normalized event lies outside the observation window")
        if event.target_pid != evidence.target.target_pid:
            failures.append("normalized event escaped the target PID")
        if event.target_tid not in target_tids:
            failures.append("normalized event escaped the target TID allowlist")
        if (
            isinstance(
                event,
                (
                    SchedSwitchEvent,
                    SchedWakeupEvent,
                    SchedMigrateEvent,
                    LockWaitEvent,
                    LockWaitEndedEvent,
                    LockReleasedEvent,
                ),
            )
            and event.semantics != "exact"
        ):
            failures.append("exact normalized event was mislabeled as candidate")
        if isinstance(event, (FutexWaitEvent, FutexWakeEvent)) and (event.semantics != "candidate"):
            failures.append("futex observation was mislabeled as exact")
        if isinstance(event, SchedWakeupEvent) and event.source_event not in {
            "sched_wakeup",
            "sched_wakeup_new",
        }:
            failures.append("sched_waking cannot create a successful wakeup event")
        if isinstance(event, SchedWakeupEvent) and (
            event.waker_target_tid is not None and event.waker_target_tid not in target_tids
        ):
            failures.append("normalized waker escaped the target TID allowlist")
        if isinstance(event, LockWaitEvent) and (
            event.owner_target_tid is not None and event.owner_target_tid not in target_tids
        ):
            failures.append("normalized owner escaped the target TID allowlist")
        if evidence.mode in {"sched", "off_cpu"} and not isinstance(
            event, (SchedSwitchEvent, SchedWakeupEvent, SchedMigrateEvent)
        ):
            failures.append("scheduler trace contains a lock event")
        if evidence.mode == "lock" and isinstance(
            event, (SchedSwitchEvent, SchedWakeupEvent, SchedMigrateEvent)
        ):
            failures.append("lock trace contains a scheduler event")
        stack = ()
        if isinstance(
            event,
            (
                SchedSwitchEvent,
                LockWaitEvent,
                LockWaitEndedEvent,
                LockReleasedEvent,
                FutexWaitEvent,
            ),
        ):
            stack = event.call_stack
        if len(stack) > evidence.limits.max_stack_depth:
            failures.append("normalized event stack exceeds max_stack_depth")

    if evidence.input_bytes > evidence.limits.max_input_bytes:
        failures.append("raw trace input exceeds max_input_bytes")
    if evidence.quality.input_event_count > evidence.limits.max_input_events:
        failures.append("input event count exceeds max_input_events")
    if evidence.quality.emitted_event_count > evidence.limits.max_exported_events:
        failures.append("emitted event count exceeds max_exported_events")
    if evidence.normalized_ndjson_bytes > evidence.limits.max_output_bytes:
        failures.append("normalized NDJSON exceeds max_output_bytes")
    unique_locks = {
        event.lock_id
        for event in evidence.events
        if isinstance(
            event,
            (
                LockWaitEvent,
                LockWaitEndedEvent,
                LockReleasedEvent,
                FutexWaitEvent,
                FutexWakeEvent,
            ),
        )
    }
    if len(unique_locks) > evidence.limits.max_unique_locks:
        failures.append("normalized lock identities exceed max_unique_locks")
    if (
        evidence.observation_window.end_timestamp_ns
        - evidence.observation_window.start_timestamp_ns
        > evidence.limits.max_duration_seconds * 1_000_000_000
    ):
        failures.append("observation window exceeds max_duration_seconds")
    if evidence.observation_window.source == "observed_event_bounds":
        if not evidence.events:
            failures.append("observed-event bounds require emitted events")
        elif (
            evidence.events[0].timestamp_ns != evidence.observation_window.start_timestamp_ns
            or evidence.events[-1].timestamp_ns != evidence.observation_window.end_timestamp_ns
        ):
            failures.append("observed-event bounds differ from first/last event timestamps")

    expected_fingerprint = compute_trace_evidence_fingerprint(evidence)
    if evidence.evidence_fingerprint != expected_fingerprint:
        failures.append("trace evidence fingerprint mismatch")
    if evidence.trace_evidence_id != f"trace-evidence-{expected_fingerprint[:16]}":
        failures.append("trace evidence identifier does not match its fingerprint")
    if evidence.content_sha256 != compute_trace_evidence_content_sha256(evidence):
        failures.append("trace evidence content SHA-256 mismatch")
    return tuple(dict.fromkeys(failures))


def validate_trace_evidence_invariants(evidence: TraceEvidenceArtifact) -> None:
    failures = trace_evidence_invariant_failures(evidence)
    if not failures:
        return
    raise PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        "Trace evidence failed deterministic verification",
        details={
            "trace_evidence_id": evidence.trace_evidence_id,
            "failures": failures,
        },
        suggested_actions=(
            "Do not use this trace evidence for Agent conclusions; retain private raw evidence.",
        ),
    )


def _json_value(payload: object) -> object:
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json", exclude_none=True)
    if isinstance(payload, Mapping):
        mapping = cast(Mapping[object, object], payload)
        return {str(key): _json_value(value) for key, value in mapping.items()}
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], payload)
        return [_json_value(value) for value in sequence]
    return payload


def _raw_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_raw_error(
    source: TraceRawArtifactReference,
    failure: str,
) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        "Private trace evidence failed raw-artifact verification",
        details={"collection_id": source.collection_id, "failure": failure},
        suggested_actions=(
            "Do not expose derived trace evidence; retain the private source for investigation.",
        ),
    )
