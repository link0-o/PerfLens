from __future__ import annotations

# pyright: reportPrivateUsage=false
from typing import cast

import pytest
from tests.unit.test_runtime_lock_comparison import _evidence_with_duration

from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
    runtime_lock_evidence_invariant_failures,
    validate_runtime_lock_evidence_invariants,
)
from perflens.contracts.runtime_locks import (
    RuntimeLockEvidenceArtifact,
    derive_runtime_execution_context_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("source_fingerprint", "source conversion fingerprint mismatch"),
        ("evidence_fingerprint", "runtime evidence fingerprint mismatch"),
        ("content_digest", "Agent-visible content digest mismatch"),
        ("content_bytes", "content byte count mismatch"),
        ("output_limit", "exceeds max_output_bytes"),
        ("source_limit", "source exceeds max_source_bytes"),
        ("input_conservation", "input event records are not conserved"),
        ("stack_conservation", "input stack records are not conserved"),
        ("event_count", "emitted event count differs"),
        ("stack_count", "emitted stack count differs"),
        ("semantic_counts", "semantic event counts are not conserved"),
        ("mixed_semantics", "mixed measurement semantics"),
        ("duplicate_event", "event IDs are not unique"),
        ("event_index", "event indexes are not contiguous"),
        ("event_order", "event ordering is not canonical"),
        ("duplicate_stack", "stack IDs are not unique"),
        ("unknown_stack", "references an unknown stack"),
        ("duplicate_context", "execution-context IDs are not unique"),
        ("context_pid", "execution context escaped the target PID"),
        ("context_tid", "execution context escaped the target TID scope"),
        ("os_thread_shape", "OS-thread execution-context shape is invalid"),
        ("process_shape", "process-aggregate execution-context shape is invalid"),
        ("native_context_missing", "omitted its opaque identity"),
        ("virtual_tid", "fabricated an OS TID"),
        ("context_id", "execution-context identity escaped"),
        ("native_context_id", "runtime-native context identity escaped"),
        ("legacy_event_tid", "schema 1.1 event carried a legacy target TID"),
        ("unknown_context", "event references an unknown execution context"),
        ("unknown_owner", "event context reference escaped target scope"),
        ("legacy_owner_tid", "schema 1.1 event carried a legacy TID reference"),
        ("fabricated_owner", "event fabricated owner visibility"),
        ("fabricated_hold", "event fabricated hold-time visibility"),
        ("unreferenced_context", "execution-context table is not referenced exactly"),
        ("owner_count", "owner observations are not conserved"),
        ("lock_id", "lock identity escaped Artifact-local ordinal derivation"),
        ("lock_kind", "lock identity changed lock kind"),
        ("lock_limit", "exceeds max_unique_locks"),
        ("context_limit", "exceeds execution-context limit"),
        ("stack_limit", "exceeds stack limit"),
        ("stack_depth", "stack depth exceeds its limit"),
        ("quality_status", "quality status contradicts"),
        ("conclusion_overlap", "conclusion gates overlap"),
        ("allowed_intrinsic", "allowed an intrinsically forbidden conclusion"),
        ("missing_intrinsic", "omitted an intrinsically forbidden conclusion"),
    ),
)
def test_runtime_lock_evidence_rechecks_all_security_invariants(
    case: str,
    expected: str,
) -> None:
    evidence = _mutate_evidence(_evidence_with_duration(50), case)

    failures = runtime_lock_evidence_invariant_failures(evidence)

    assert any(expected in failure for failure in failures)


def _mutate_evidence(
    evidence: RuntimeLockEvidenceArtifact,
    case: str,
) -> RuntimeLockEvidenceArtifact:
    source = evidence.source
    quality = evidence.quality
    limits = evidence.limits
    contexts = list(evidence.execution_contexts)
    stacks = list(evidence.stacks)
    events = list(evidence.events)
    if case == "source_fingerprint":
        source = source.model_copy(update={"conversion_fingerprint": "f" * 64})
    elif case == "evidence_fingerprint":
        return evidence.model_copy(update={"evidence_fingerprint": "f" * 64})
    elif case == "content_digest":
        return evidence.model_copy(update={"content_sha256": "f" * 64})
    elif case == "content_bytes":
        return evidence.model_copy(update={"content_bytes": evidence.content_bytes + 1})
    elif case == "output_limit":
        limits = limits.model_copy(update={"max_output_bytes": 1})
    elif case == "source_limit":
        limits = limits.model_copy(update={"max_source_bytes": 1})
    elif case == "input_conservation":
        quality = quality.model_copy(update={"input_record_count": quality.input_record_count + 1})
    elif case == "stack_conservation":
        quality = quality.model_copy(
            update={"stack_input_record_count": quality.stack_input_record_count + 1}
        )
    elif case == "event_count":
        quality = quality.model_copy(
            update={"emitted_event_count": quality.emitted_event_count + 1}
        )
    elif case == "stack_count":
        quality = quality.model_copy(
            update={"emitted_stack_count": quality.emitted_stack_count + 1}
        )
    elif case == "semantic_counts":
        quality = quality.model_copy(update={"exact_event_count": quality.exact_event_count - 1})
    elif case == "mixed_semantics":
        events[0] = events[0].model_copy(update={"measurement_semantics": "sampled"})
    elif case == "duplicate_event":
        events[1] = events[1].model_copy(update={"event_id": events[0].event_id})
    elif case == "event_index":
        events[0] = events[0].model_copy(update={"event_index": 99})
    elif case == "event_order":
        events[0] = events[0].model_copy(update={"timestamp_ns": 999})
    elif case == "duplicate_stack":
        stacks.append(stacks[0])
    elif case == "unknown_stack":
        events[0] = events[0].model_copy(update={"stack_id": "runtime-stack-" + "f" * 20})
    elif case == "duplicate_context":
        contexts.append(contexts[0])
    elif case == "context_pid":
        contexts[0] = contexts[0].model_copy(update={"target_pid": 999})
    elif case == "context_tid":
        contexts[0] = contexts[0].model_copy(update={"target_tid": 999})
    elif case == "os_thread_shape":
        contexts[0] = contexts[0].model_copy(update={"target_tid": None})
    elif case == "process_shape":
        contexts[0] = contexts[0].model_copy(update={"kind": "process_aggregate"})
    elif case == "native_context_missing":
        contexts[0] = contexts[0].model_copy(
            update={"kind": "java_platform_thread", "runtime_context_id": None}
        )
    elif case == "virtual_tid":
        contexts[0] = contexts[0].model_copy(
            update={
                "kind": "java_virtual_thread",
                "runtime_context_id": "runtime-native-" + "1" * 20,
            }
        )
    elif case == "context_id":
        contexts[0] = contexts[0].model_copy(update={"context_id": "runtime-context-" + "f" * 20})
    elif case == "native_context_id":
        contexts[0] = contexts[0].model_copy(
            update={
                "kind": "java_platform_thread",
                "runtime_context_id": "runtime-native-" + "f" * 20,
            }
        )
    elif case == "legacy_event_tid":
        events[0] = events[0].model_copy(update={"target_tid": 101})
    elif case == "unknown_context":
        events[0] = events[0].model_copy(
            update={"execution_context_id": "runtime-context-" + "f" * 20}
        )
    elif case == "unknown_owner":
        events[0] = events[0].model_copy(
            update={"owner_execution_context_id": "runtime-context-" + "f" * 20}
        )
    elif case == "legacy_owner_tid":
        events[0] = events[0].model_copy(update={"owner_target_tid": 100})
    elif case == "fabricated_owner":
        source = source.model_copy(update={"owner_is_source_observed": False})
    elif case == "fabricated_hold":
        source = source.model_copy(update={"hold_time_is_source_observed": False})
    elif case == "unreferenced_context":
        contexts.append(
            contexts[1].model_copy(
                update={
                    "context_id": derive_runtime_execution_context_id(
                        evidence.runtime_lock_evidence_id,
                        2,
                    )
                }
            )
        )
    elif case == "owner_count":
        quality = quality.model_copy(
            update={"owner_observed_event_count": quality.owner_observed_event_count + 1}
        )
    elif case == "lock_id":
        events[0] = events[0].model_copy(update={"lock_id": "runtime-lock-" + "f" * 20})
    elif case == "lock_kind":
        events[1] = events[1].model_copy(update={"lock_kind": "rwlock_read"})
    elif case == "lock_limit":
        limits = limits.model_copy(update={"max_unique_locks": 0})
    elif case == "context_limit":
        limits = limits.model_copy(update={"max_unique_target_tids": 1})
    elif case == "stack_limit":
        limits = limits.model_copy(update={"max_unique_stacks": 0})
    elif case == "stack_depth":
        limits = limits.model_copy(update={"max_stack_depth": 0})
    elif case == "quality_status":
        quality = quality.model_copy(update={"status": "partial"})
    elif case == "conclusion_overlap":
        return evidence.model_copy(
            update={
                "allowed_conclusions": (
                    *evidence.allowed_conclusions,
                    evidence.forbidden_conclusions[0],
                )
            }
        )
    elif case == "allowed_intrinsic":
        return evidence.model_copy(
            update={"allowed_conclusions": (*evidence.allowed_conclusions, "verified_improvement")}
        )
    elif case == "missing_intrinsic":
        return evidence.model_copy(
            update={
                "forbidden_conclusions": tuple(
                    value
                    for value in evidence.forbidden_conclusions
                    if value != "cross_artifact_lock_identity"
                )
            }
        )
    else:
        raise AssertionError(f"unknown test case: {case}")
    return evidence.model_copy(
        update={
            "source": source,
            "quality": quality,
            "limits": limits,
            "execution_contexts": tuple(contexts),
            "stacks": tuple(stacks),
            "events": tuple(events),
        }
    )


def test_validate_runtime_lock_evidence_reports_bounded_failure() -> None:
    evidence = _evidence_with_duration(50).model_copy(update={"content_sha256": "f" * 64})

    with pytest.raises(PerfLensError, match="failed deterministic invariant checks") as raised:
        validate_runtime_lock_evidence_invariants(evidence)

    assert raised.value.code == ErrorCode.PROFILE_PARSE_FAILED
    assert any(
        "Agent-visible content digest mismatch" in failure
        for failure in raised.value.details["failures"]
    )


def test_canonical_runtime_lock_json_rejects_non_json_identity_material() -> None:
    with pytest.raises(TypeError, match="unsupported set"):
        canonical_runtime_lock_json_sha256(cast(object, {"not", "json"}))
