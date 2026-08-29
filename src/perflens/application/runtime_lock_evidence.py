"""Canonical identity and invariant checks for public Runtime Lock evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import BaseModel

from perflens.application.evidence import contract_content_sha256
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts import runtime_locks as public
from perflens.domain.errors import ErrorCode, PerfLensError

_EVIDENCE_FINGERPRINT_DOMAIN = "perflens.runtime-lock-evidence.v1.1"
_NORMALIZED_RECORD_DOMAIN = "perflens.runtime-lock-normalized-records.v1.1"
_SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS = frozenset(
    {
        "performance_root_cause",
        "verified_improvement",
        "cross_artifact_lock_identity",
        "system_wide_or_cross_target_behavior",
    }
)


def canonical_runtime_lock_json_sha256(payload: object) -> str:
    encoded = json.dumps(
        _json_value(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_value(payload: object) -> object:
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json", exclude_none=True)
    if isinstance(payload, Mapping):
        mapping = cast(Mapping[object, object], payload)
        return {str(key): _json_value(value) for key, value in mapping.items()}
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], payload)
        return [_json_value(value) for value in sequence]
    if payload is None or isinstance(payload, (str, int, float, bool)):
        return payload
    raise TypeError(f"runtime lock fingerprint received unsupported {type(payload).__name__}")


def compute_runtime_source_conversion_fingerprint(
    manifest: public.RuntimeSourceManifest,
) -> str:
    """Bind the converter/tool identity, source receipt, controls, and semantics."""

    return contract_content_sha256(manifest, exclude={"conversion_fingerprint"})


def normalized_runtime_lock_records_identity(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> tuple[str, int]:
    """Return a bounded canonical identity for the replayable public normalization."""

    digest = hashlib.sha256()
    byte_count = 0
    header = {
        "domain": _NORMALIZED_RECORD_DOMAIN,
        "schema_version": evidence.schema_version,
    }
    records: Sequence[tuple[str, BaseModel]] = (
        *(("execution_context", value) for value in evidence.execution_contexts),
        *(("stack", value) for value in evidence.stacks),
        *(("event", value) for value in evidence.events),
    )
    first = (
        json.dumps(header, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        + b"\n"
    )
    digest.update(first)
    byte_count += len(first)
    for record_type, record in records:
        payload = {
            "record_type": record_type,
            "record": record.model_dump(mode="json", exclude_none=True),
        }
        line = (
            json.dumps(
                payload,
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


def compute_runtime_lock_evidence_fingerprint(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> str:
    """Bind the preassigned Artifact ID and every replay-relevant public field.

    The Artifact ID is assigned from the immutable source receipt before conversion.  It is
    intentionally not derived from this fingerprint because Artifact-local lock IDs are in turn
    derived from that ID.
    """

    normalized_sha256, normalized_bytes = normalized_runtime_lock_records_identity(evidence)
    material = {
        "domain": _EVIDENCE_FINGERPRINT_DOMAIN,
        "schema_version": evidence.schema_version,
        "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
        "created_at": evidence.created_at,
        "target": evidence.target,
        "source": evidence.source,
        "computed_conversion_fingerprint": (
            compute_runtime_source_conversion_fingerprint(evidence.source)
        ),
        "limits": evidence.limits,
        "quality": evidence.quality,
        "normalized_records_sha256": normalized_sha256,
        "normalized_records_bytes": normalized_bytes,
        "allowed_conclusions": evidence.allowed_conclusions,
        "forbidden_conclusions": evidence.forbidden_conclusions,
    }
    return canonical_runtime_lock_json_sha256(material)


def compute_runtime_lock_evidence_content_sha256(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> str:
    return contract_content_sha256(evidence, exclude={"content_sha256"})


def runtime_lock_evidence_invariant_failures(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> tuple[str, ...]:
    """Recheck critical invariants even when a caller used ``model_copy``."""

    failures: list[str] = []
    source = evidence.source
    quality = evidence.quality
    limits = evidence.limits
    if source.conversion_fingerprint != compute_runtime_source_conversion_fingerprint(source):
        failures.append("runtime source conversion fingerprint mismatch")
    if evidence.evidence_fingerprint != compute_runtime_lock_evidence_fingerprint(evidence):
        failures.append("runtime evidence fingerprint mismatch")
    if evidence.content_sha256 != compute_runtime_lock_evidence_content_sha256(evidence):
        failures.append("runtime evidence Agent-visible content digest mismatch")
    actual_bytes = len(serialize_json(evidence))
    if evidence.content_bytes != actual_bytes:
        failures.append("runtime evidence content byte count mismatch")
    if evidence.content_bytes > limits.max_output_bytes:
        failures.append("runtime evidence exceeds max_output_bytes")
    if source.source_bytes > limits.max_source_bytes:
        failures.append("runtime source exceeds max_source_bytes")

    terminal = (
        quality.emitted_event_count
        + quality.filtered_outside_target_count
        + quality.malformed_record_count
        + quality.duplicate_record_count
        + quality.out_of_order_record_count
        + quality.unsupported_record_count
        + quality.truncated_event_count
    )
    if terminal != quality.input_record_count:
        failures.append("runtime input event records are not conserved")
    stack_terminal = (
        quality.emitted_stack_count
        + quality.malformed_stack_record_count
        + quality.duplicate_stack_record_count
        + quality.truncated_stack_record_count
    )
    if stack_terminal != quality.stack_input_record_count:
        failures.append("runtime input stack records are not conserved")
    if quality.emitted_event_count != len(evidence.events):
        failures.append("runtime emitted event count differs from public events")
    if quality.emitted_stack_count != len(evidence.stacks):
        failures.append("runtime emitted stack count differs from public stacks")

    semantic_counts = {
        semantics: sum(event.measurement_semantics == semantics for event in evidence.events)
        for semantics in ("exact", "thresholded", "sampled", "cumulative")
    }
    expected_semantic_counts = {
        "exact": quality.exact_event_count,
        "thresholded": quality.thresholded_event_count,
        "sampled": quality.sampled_event_count,
        "cumulative": quality.cumulative_event_count,
    }
    if semantic_counts != expected_semantic_counts:
        failures.append("runtime semantic event counts are not conserved")
    if any(
        event.measurement_semantics != source.measurement_semantics for event in evidence.events
    ):
        failures.append("runtime evidence mixed measurement semantics")

    event_ids = tuple(event.event_id for event in evidence.events)
    if len(set(event_ids)) != len(event_ids):
        failures.append("runtime event IDs are not unique")
    if tuple(event.event_index for event in evidence.events) != tuple(range(len(evidence.events))):
        failures.append("runtime event indexes are not contiguous")
    ordering = tuple((event.timestamp_ns, event.event_index) for event in evidence.events)
    if ordering != tuple(sorted(ordering)):
        failures.append("runtime event ordering is not canonical")
    stack_ids = tuple(stack.stack_id for stack in evidence.stacks)
    if len(set(stack_ids)) != len(stack_ids):
        failures.append("runtime stack IDs are not unique")
    if any(
        event.stack_id is not None and event.stack_id not in stack_ids for event in evidence.events
    ):
        failures.append("runtime event references an unknown stack")

    allowed_tids = set(evidence.target.observed_target_tids)
    contexts = {context.context_id: context for context in evidence.execution_contexts}
    if len(contexts) != len(evidence.execution_contexts):
        failures.append("runtime execution-context IDs are not unique")
    referenced_context_ids: set[str] = set()
    owner_count = 0
    for ordinal, context in enumerate(evidence.execution_contexts):
        if context.target_pid != evidence.target.target_pid:
            failures.append("runtime execution context escaped the target PID")
        if context.target_tid is not None and context.target_tid not in allowed_tids:
            failures.append("runtime execution context escaped the target TID scope")
        if evidence.schema_version == "1.1":
            if context.kind == "os_thread" and (
                context.target_tid is None or context.runtime_context_id is not None
            ):
                failures.append("runtime OS-thread execution-context shape is invalid")
            elif context.kind == "process_aggregate" and (
                context.target_tid is not None or context.runtime_context_id is not None
            ):
                failures.append("runtime process-aggregate execution-context shape is invalid")
            elif context.kind not in {"os_thread", "process_aggregate"} and (
                context.runtime_context_id is None
            ):
                failures.append("runtime-native execution context omitted its opaque identity")
            if context.kind in {"java_virtual_thread", "go_goroutine"} and (
                context.target_tid is not None
            ):
                failures.append("runtime virtual execution context fabricated an OS TID")
            if context.context_id != public.derive_runtime_execution_context_id(
                evidence.runtime_lock_evidence_id,
                ordinal,
            ):
                failures.append(
                    "runtime execution-context identity escaped Artifact-local ordinal derivation"
                )
            if (
                context.runtime_context_id is not None
                and context.runtime_context_id
                != public.derive_runtime_native_context_id(
                    evidence.runtime_lock_evidence_id,
                    ordinal,
                )
            ):
                failures.append(
                    "runtime-native context identity escaped Artifact-local ordinal derivation"
                )
    for event in evidence.events:
        if evidence.schema_version == "1.1":
            if event.target_tid is not None:
                failures.append("schema 1.1 event carried a legacy target TID")
            context_id = event.execution_context_id
            if context_id is None or context_id not in contexts:
                failures.append("runtime event references an unknown execution context")
            else:
                referenced_context_ids.add(context_id)
            owner_id = getattr(event, "owner_execution_context_id", None)
            parked_id = getattr(event, "parked_execution_context_id", None)
            for referenced_id in (owner_id, parked_id):
                if referenced_id is not None:
                    if referenced_id not in contexts:
                        failures.append("runtime event context reference escaped target scope")
                    else:
                        referenced_context_ids.add(referenced_id)
            if owner_id is not None:
                owner_count += 1
            if (
                getattr(event, "owner_target_tid", None) is not None
                or getattr(event, "parked_target_tid", None) is not None
            ):
                failures.append("schema 1.1 event carried a legacy TID reference")
        else:
            target_tid = event.target_tid
            if target_tid is None or target_tid not in allowed_tids:
                failures.append("schema 1.0 event escaped the target TID scope")
            owner_tid = getattr(event, "owner_target_tid", None)
            parked_tid = getattr(event, "parked_target_tid", None)
            if owner_tid is not None:
                owner_count += 1
            if any(
                value is not None and value not in allowed_tids for value in (owner_tid, parked_tid)
            ):
                failures.append("schema 1.0 event TID reference escaped target scope")
        owner_reference = (
            getattr(event, "owner_execution_context_id", None)
            if evidence.schema_version == "1.1"
            else getattr(event, "owner_target_tid", None)
        )
        if owner_reference is not None and not evidence.source.owner_is_source_observed:
            failures.append("runtime event fabricated owner visibility")
        if (
            isinstance(event, public.RuntimeReleaseEvent)
            and event.hold_duration_ns is not None
            and not evidence.source.hold_time_is_source_observed
        ):
            failures.append("runtime event fabricated hold-time visibility")
    if evidence.schema_version == "1.1" and referenced_context_ids != set(contexts):
        failures.append("runtime execution-context table is not referenced exactly")
    if owner_count != quality.owner_observed_event_count:
        failures.append("runtime owner observations are not conserved")

    lock_ids = tuple(
        dict.fromkeys(event.lock_id for event in evidence.events if event.lock_id is not None)
    )
    if evidence.schema_version == "1.1" and any(
        lock_id != public.derive_runtime_lock_id(evidence.runtime_lock_evidence_id, ordinal)
        for ordinal, lock_id in enumerate(lock_ids)
    ):
        failures.append("runtime lock identity escaped Artifact-local ordinal derivation")
    lock_kinds: dict[str, str] = {}
    for event in evidence.events:
        if event.lock_id is None:
            continue
        previous = lock_kinds.setdefault(event.lock_id, event.lock_kind)
        if evidence.schema_version == "1.1" and previous != event.lock_kind:
            failures.append("runtime lock identity changed lock kind")
    if len(lock_ids) > limits.max_unique_locks:
        failures.append("runtime evidence exceeds max_unique_locks")
    if len(evidence.execution_contexts) > limits.max_unique_target_tids:
        failures.append("runtime evidence exceeds execution-context limit")
    if len(evidence.stacks) > limits.max_unique_stacks:
        failures.append("runtime evidence exceeds stack limit")
    if any(len(stack.frames) > limits.max_stack_depth for stack in evidence.stacks):
        failures.append("runtime evidence stack depth exceeds its limit")

    degraded = bool(
        quality.malformed_record_count
        or quality.duplicate_record_count
        or quality.out_of_order_record_count
        or quality.unsupported_record_count
        or quality.lost_event_count
        or quality.truncated_event_count
        or quality.malformed_stack_record_count
        or quality.duplicate_stack_record_count
        or quality.truncated_stack_record_count
        or quality.diagnostic_count
        or quality.limitations
    )
    expected_status = "partial" if degraded else "complete"
    if quality.status != expected_status:
        failures.append("runtime quality status contradicts loss/drop/limitation counters")
    if set(evidence.allowed_conclusions) & set(evidence.forbidden_conclusions):
        failures.append("runtime evidence conclusion gates overlap")
    if evidence.schema_version == "1.1":
        allowed = set(evidence.allowed_conclusions)
        forbidden = set(evidence.forbidden_conclusions)
        if allowed & _SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS:
            failures.append("runtime evidence allowed an intrinsically forbidden conclusion")
        if not _SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS.issubset(forbidden):
            failures.append("runtime evidence omitted an intrinsically forbidden conclusion")
    return tuple(dict.fromkeys(failures))


def validate_runtime_lock_evidence_invariants(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> None:
    failures = runtime_lock_evidence_invariant_failures(evidence)
    if not failures:
        return
    raise PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "runtime_lock_evidence",
        "Runtime Lock evidence failed deterministic invariant checks",
        details={
            "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
            "failures": tuple(failures[:20]),
            "failure_count": len(failures),
        },
        suggested_actions=(
            "Retain the immutable source and rebuild Runtime Lock evidence before analysis.",
        ),
    )
