from __future__ import annotations

from typing import Any, Protocol, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from perflens.contracts.runtime_locks import (
    RuntimeAdapterCapabilityArtifact,
    RuntimeContainerTargetReference,
    RuntimeEvidenceQuality,
    RuntimeExecutionContext,
    RuntimeLockAggregate,
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockEvidenceArtifact,
    RuntimeLockImportHeader,
    RuntimeLockVerificationCheck,
    RuntimeNanosecondDistribution,
    RuntimeSourceManifest,
    RuntimeStackFrame,
    RuntimeTargetIdentity,
    RuntimeToolIdentity,
    derive_runtime_execution_context_id,
    derive_runtime_lock_id,
)

ZERO_SHA = "0" * 64
ONE_SHA = "1" * 64
EVIDENCE_ID = "runtime-lock-evidence-" + "a" * 16
CONTEXT_ID = derive_runtime_execution_context_id(EVIDENCE_ID, 0)
LOCK_ID = derive_runtime_lock_id(EVIDENCE_ID, 0)


class _JsonSchemaValidator(Protocol):
    def validate(self, instance: Any) -> None: ...


def _validate_json_schema(schema: dict[str, Any], payload: dict[str, Any]) -> None:
    validator = cast(_JsonSchemaValidator, Draft202012Validator(schema))
    validator.validate(payload)


def _target() -> dict[str, Any]:
    return {
        "target_pid": 100,
        "target_uid": 1000,
        "target_start_time_ticks": 55,
        "observed_target_tids": [100, 101],
        "target_kind": "host",
    }


def _container_reference() -> dict[str, str]:
    return {
        "container_target_id": "container-target-" + "1" * 20,
        "container_target_content_sha256": "2" * 64,
        "container_run_id": "container-run-" + "3" * 20,
        "container_run_content_sha256": "4" * 64,
        "container_identity_sha256": "5" * 64,
        "target_identity_sha256": "6" * 64,
        "cgroup_identity_sha256": "7" * 64,
    }


def _tool() -> dict[str, Any]:
    return {
        "name": "python3",
        "path": "python3",
        "version": "Python 3.13.5",
        "binary_sha256": ZERO_SHA,
        "status": "available",
    }


def _source(*, semantics: str = "exact", **overrides: Any) -> dict[str, Any]:
    source: dict[str, Any] = {
        "schema_version": "1.1",
        "runtime": "python",
        "adapter_id": "cpython-locks",
        "adapter_version": "runtime-lock-adapter-v1",
        "backend_id": "strict-ndjson-import",
        "backend_version": "1",
        "measurement_semantics": semantics,
        "source_format": "perflens_runtime_lock_ndjson_v1",
        "converter_version": "runtime-lock-ndjson-v1.1",
        "source_sha256": ZERO_SHA,
        "source_bytes": 512,
        "conversion_fingerprint": ONE_SHA,
        "clock": {"clock": "monotonic"},
        "fast_path_visibility": "partial",
        "owner_is_source_observed": False,
        "hold_time_is_source_observed": False,
        "target_scope": "verified_import",
        "tool": _tool(),
    }
    if semantics == "thresholded":
        source["duration_threshold_ns"] = 10_000_000
    elif semantics == "sampled":
        source["sampling_fraction"] = 5
    elif semantics == "cumulative":
        source["block_profile_rate_ns"] = 1_000_000
    source.update(overrides)
    return source


def _quality(*, semantics: str = "exact", status: str = "complete") -> dict[str, Any]:
    counts = {
        "exact_event_count": 2 if semantics == "exact" else 0,
        "thresholded_event_count": 2 if semantics == "thresholded" else 0,
        "sampled_event_count": 2 if semantics == "sampled" else 0,
        "cumulative_event_count": 2 if semantics == "cumulative" else 0,
    }
    return {
        "status": status,
        "input_record_count": 2,
        "emitted_event_count": 2,
        "filtered_outside_target_count": 0,
        "malformed_record_count": 0,
        "duplicate_record_count": 0,
        "unsupported_record_count": 0,
        "lost_event_count": 0,
        "truncated_event_count": 0,
        "out_of_order_record_count": 0,
        "stack_input_record_count": 0,
        "emitted_stack_count": 0,
        "malformed_stack_record_count": 0,
        "duplicate_stack_record_count": 0,
        "truncated_stack_record_count": 0,
        **counts,
        "owner_observed_event_count": 0,
        "diagnostic_count": 0,
        "diagnostics_truncated": False,
        "diagnostics": [],
        "limitations": [] if status == "complete" else ["test limitation"],
    }


def _contexts() -> list[dict[str, Any]]:
    return [
        {
            "context_id": CONTEXT_ID,
            "kind": "os_thread",
            "target_pid": 100,
            "target_tid": 101,
        }
    ]


def _events(*, semantics: str = "exact") -> list[dict[str, Any]]:
    return [
        {
            "event_kind": "wait_begin",
            "event_id": "runtime-event-" + "a" * 16,
            "event_index": 0,
            "timestamp_ns": 100,
            "execution_context_id": CONTEXT_ID,
            "lock_id": LOCK_ID,
            "lock_kind": "mutex",
            "measurement_semantics": semantics,
        },
        {
            "event_kind": "wait_end",
            "event_id": "runtime-event-" + "b" * 16,
            "event_index": 1,
            "timestamp_ns": 150,
            "execution_context_id": CONTEXT_ID,
            "lock_id": LOCK_ID,
            "lock_kind": "mutex",
            "measurement_semantics": semantics,
            "wait_begin_event_id": "runtime-event-" + "a" * 16,
            "duration_ns": 50,
            "outcome": "acquired",
        },
    ]


def _evidence(*, semantics: str = "exact", **overrides: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": "1.1",
        "runtime_lock_evidence_id": EVIDENCE_ID,
        "created_at": "2026-08-16T00:00:00+00:00",
        "target": _target(),
        "source": _source(semantics=semantics),
        "limits": {},
        "quality": _quality(semantics=semantics),
        "execution_contexts": _contexts(),
        "stacks": [],
        "events": _events(semantics=semantics),
        "allowed_conclusions": ["observed_runtime_wait_distribution"],
        "forbidden_conclusions": [
            "exact_hold_time",
            "exact_owner_relationship",
            "performance_root_cause",
            "verified_improvement",
            "cross_artifact_lock_identity",
            "system_wide_or_cross_target_behavior",
            *([] if semantics == "exact" else ["exact_contention_count"]),
        ],
        "evidence_fingerprint": ZERO_SHA,
        "content_sha256": ONE_SHA,
        "content_bytes": 1024,
    }
    evidence.update(overrides)
    return evidence


def _schema_1_0_evidence() -> dict[str, Any]:
    payload = _evidence()
    payload["schema_version"] = "1.0"
    payload["source"]["schema_version"] = "1.0"
    payload["source"].pop("converter_version")
    payload["target"].pop("target_kind")
    payload.pop("execution_contexts")
    for field in (
        "out_of_order_record_count",
        "stack_input_record_count",
        "emitted_stack_count",
        "malformed_stack_record_count",
        "duplicate_stack_record_count",
        "truncated_stack_record_count",
    ):
        payload["quality"].pop(field)
    for event in payload["events"]:
        event.pop("execution_context_id")
        event["target_tid"] = 101
        event["lock_id"] = "runtime-lock-" + "f" * 20
    return payload


def _zero_distribution() -> dict[str, int]:
    return {
        "sample_count": 0,
        "total_ns": 0,
        "minimum_ns": 0,
        "mean_ns": 0,
        "p50_ns": 0,
        "p95_ns": 0,
        "p99_ns": 0,
        "maximum_ns": 0,
    }


def _one_distribution() -> dict[str, int]:
    return {
        "sample_count": 1,
        "total_ns": 50,
        "minimum_ns": 50,
        "mean_ns": 50,
        "p50_ns": 50,
        "p95_ns": 50,
        "p99_ns": 50,
        "maximum_ns": 50,
    }


def test_available_capability_requires_concrete_observable_semantics() -> None:
    capability = RuntimeAdapterCapabilityArtifact.model_validate(
        {
            "capability_id": "runtime-capability-" + "a" * 16,
            "created_at": "2026-08-16T00:00:00+00:00",
            "runtime": "python",
            "runtime_name": "CPython",
            "runtime_version": "3.13.5",
            "runtime_build": "main",
            "adapter_id": "cpython-locks",
            "adapter_version": "runtime-lock-adapter-v1",
            "backend_id": "usdt-import",
            "availability": "available",
            "supported_lock_kinds": ["gil", "mutex"],
            "supported_event_kinds": ["wait_begin", "wait_end"],
            "measurement_semantics": ["exact"],
            "fast_path_visibility": "partial",
            "owner_visibility": "unavailable",
            "hold_time_visibility": "unavailable",
            "launch_instrumentation_required": False,
            "attach_required": False,
            "privileged_backend_required": False,
            "tools": [_tool()],
            "content_sha256": ZERO_SHA,
        }
    )
    assert capability.availability == "available"

    payload = capability.model_dump(mode="json")
    payload["supported_event_kinds"] = []
    with pytest.raises(ValidationError, match="observable semantics"):
        RuntimeAdapterCapabilityArtifact.model_validate(payload)


def test_unavailable_capability_cannot_advertise_active_events() -> None:
    with pytest.raises(ValidationError, match="cannot claim active observations"):
        RuntimeAdapterCapabilityArtifact.model_validate(
            {
                "capability_id": "runtime-capability-" + "a" * 16,
                "created_at": "2026-08-16T00:00:00+00:00",
                "runtime": "go",
                "runtime_name": "Go",
                "adapter_id": "go-pprof-locks",
                "adapter_version": "1",
                "backend_id": "go-tool-pprof",
                "availability": "unavailable",
                "supported_event_kinds": ["sampled_contention"],
                "measurement_semantics": ["cumulative"],
                "fast_path_visibility": "unknown",
                "owner_visibility": "unavailable",
                "hold_time_visibility": "unavailable",
                "launch_instrumentation_required": False,
                "attach_required": False,
                "privileged_backend_required": False,
                "limitations": ["go tool is missing"],
                "content_sha256": ZERO_SHA,
            }
        )


def test_available_tool_identity_is_complete_and_uses_a_safe_public_name() -> None:
    assert RuntimeToolIdentity.model_validate(_tool()).status == "available"
    invalid = _tool()
    invalid["path"] = "../python3"
    with pytest.raises(ValidationError, match="safe basename"):
        RuntimeToolIdentity.model_validate(invalid)


def test_schema_1_1_tool_identity_rejects_absolute_paths_but_legacy_reads_them() -> None:
    capability_payload = {
        "schema_version": "1.1",
        "capability_id": "runtime-capability-" + "a" * 16,
        "created_at": "2026-08-16T00:00:00+00:00",
        "runtime": "python",
        "runtime_name": "CPython",
        "adapter_id": "cpython-locks",
        "adapter_version": "runtime-lock-adapter-v1",
        "backend_id": "usdt-import",
        "availability": "available",
        "supported_event_kinds": ["wait_begin", "wait_end"],
        "measurement_semantics": ["exact"],
        "fast_path_visibility": "partial",
        "owner_visibility": "unavailable",
        "hold_time_visibility": "unavailable",
        "launch_instrumentation_required": False,
        "attach_required": False,
        "privileged_backend_required": False,
        "tools": [{**_tool(), "path": "/usr/bin/python3"}],
        "content_sha256": ZERO_SHA,
    }
    with pytest.raises(ValidationError, match="cannot expose absolute tool paths"):
        RuntimeAdapterCapabilityArtifact.model_validate(capability_payload)
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(
            RuntimeAdapterCapabilityArtifact.model_json_schema(),
            capability_payload,
        )

    capability_payload["schema_version"] = "1.0"
    legacy = RuntimeAdapterCapabilityArtifact.model_validate(capability_payload)
    assert legacy.tools[0].path == "/usr/bin/python3"

    source_payload = _source(tool={**_tool(), "path": "/usr/bin/python3"})
    with pytest.raises(ValidationError, match="cannot expose an absolute tool path"):
        RuntimeSourceManifest.model_validate(source_payload)
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeSourceManifest.model_json_schema(), source_payload)


@pytest.mark.parametrize(
    ("semantics", "missing_field"),
    [
        ("thresholded", "duration_threshold_ns"),
        ("sampled", "sampling_fraction"),
        ("cumulative", "block_profile_rate_ns"),
    ],
)
def test_source_manifest_requires_declared_measurement_controls(
    semantics: str, missing_field: str
) -> None:
    payload = _source(semantics=semantics)
    del payload[missing_field]
    with pytest.raises(ValidationError):
        RuntimeSourceManifest.model_validate(payload)


def test_import_header_is_strict_and_has_no_path_or_command_surface() -> None:
    header = RuntimeLockImportHeader.model_validate(
        {
            "schema_version": "1.1",
            "runtime": "custom",
            "runtime_version": "1",
            "adapter_id": "custom-import",
            "adapter_version": "1",
            "backend_id": "strict-ndjson",
            "backend_version": "1",
            "target": _target(),
            "clock": {"clock": "monotonic"},
            "measurement_semantics": "exact",
            "visible_lock_kinds": ["custom"],
            "fast_path_visibility": "partial",
            "owner_is_source_observed": False,
            "hold_time_is_source_observed": False,
            "declared_event_count": 2,
            "declared_lost_event_count": 0,
            "declared_truncated": False,
        }
    )
    assert header.record_type == "runtime_lock_header"
    assert header.schema_version == "1.1"
    with pytest.raises(ValidationError, match="Extra inputs"):
        RuntimeLockImportHeader.model_validate(
            {**header.model_dump(mode="json"), "command": ["arbitrary"]}
        )


@pytest.mark.parametrize("semantics", ["exact", "thresholded"])
def test_event_evidence_preserves_exact_or_thresholded_semantics(semantics: str) -> None:
    evidence = RuntimeLockEvidenceArtifact.model_validate(_evidence(semantics=semantics))
    assert evidence.source.measurement_semantics == semantics
    assert len(evidence.events) == 2


def test_non_exact_evidence_must_forbid_exact_contention_counts() -> None:
    payload = _evidence(semantics="thresholded")
    payload["forbidden_conclusions"] = ["exact_hold_time", "exact_owner_relationship"]
    with pytest.raises(ValidationError, match="forbid exact contention"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_evidence_rejects_foreign_tid_and_unknown_stack() -> None:
    payload = _evidence()
    payload["execution_contexts"][0]["target_tid"] = 999
    with pytest.raises(ValidationError, match="escaped"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][0]["stack_id"] = "runtime-stack-" + "a" * 16
    with pytest.raises(ValidationError, match="unknown stack"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_evidence_rejects_count_and_order_tampering() -> None:
    payload = _evidence()
    payload["quality"]["input_record_count"] = 3
    with pytest.raises(ValidationError, match="not conserved"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][1]["event_index"] = 2
    with pytest.raises(ValidationError, match="contiguous"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_partial_evidence_requires_unqualified_conclusion_boundary() -> None:
    payload = _evidence()
    payload["quality"] = _quality(status="partial")
    with pytest.raises(ValidationError, match="unqualified"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_evidence_rejects_fabricated_owner_and_hold_visibility() -> None:
    payload = _evidence()
    payload["events"][0]["owner_execution_context_id"] = CONTEXT_ID
    payload["quality"]["owner_observed_event_count"] = 1
    with pytest.raises(ValidationError, match="fabricated owner"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"] = [
        {
            "event_kind": "acquire",
            "event_id": "runtime-event-" + "a" * 16,
            "event_index": 0,
            "timestamp_ns": 100,
            "execution_context_id": CONTEXT_ID,
            "lock_id": LOCK_ID,
            "lock_kind": "mutex",
            "measurement_semantics": "exact",
        },
        {
            "event_kind": "release",
            "event_id": "runtime-event-" + "b" * 16,
            "event_index": 1,
            "timestamp_ns": 150,
            "execution_context_id": CONTEXT_ID,
            "lock_id": LOCK_ID,
            "lock_kind": "mutex",
            "measurement_semantics": "exact",
            "acquire_event_id": "runtime-event-" + "a" * 16,
            "hold_duration_ns": 50,
        },
    ]
    with pytest.raises(ValidationError, match="fabricated hold"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_evidence_enforces_resource_and_diagnostic_limits() -> None:
    payload = _evidence()
    payload["limits"] = {"max_source_bytes": 511}
    with pytest.raises(ValidationError, match="max_source_bytes"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["quality"].update(
        {
            "status": "partial",
            "diagnostic_count": 2,
            "diagnostics_truncated": True,
            "diagnostics": ["one bounded diagnostic"],
            "limitations": ["adapter diagnostics were emitted"],
        }
    )
    payload["limits"] = {"max_diagnostics": 1}
    with pytest.raises(ValidationError, match="max_diagnostics"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_release_requires_paired_identity_and_duration() -> None:
    payload = _evidence()
    payload["events"][1] = {
        "event_kind": "release",
        "event_id": "runtime-event-" + "b" * 16,
        "event_index": 1,
        "timestamp_ns": 150,
        "execution_context_id": CONTEXT_ID,
        "lock_id": LOCK_ID,
        "lock_kind": "mutex",
        "measurement_semantics": "exact",
        "hold_duration_ns": 50,
    }
    with pytest.raises(ValidationError, match="identity and duration together"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_execution_context_does_not_invent_native_tid() -> None:
    virtual = RuntimeExecutionContext.model_validate(
        {
            "context_id": "runtime-context-" + "b" * 16,
            "kind": "java_virtual_thread",
            "target_pid": 100,
            "runtime_context_id": "runtime-native-" + "c" * 16,
            "name": "worker-1",
        }
    )
    assert virtual.target_tid is None

    payload = virtual.model_dump(mode="json")
    payload["target_tid"] = 101
    with pytest.raises(ValidationError, match="cannot claim an OS TID"):
        RuntimeExecutionContext.model_validate(payload)

    with pytest.raises(ValidationError, match="process aggregate"):
        RuntimeExecutionContext.model_validate(
            {
                "context_id": "runtime-context-" + "d" * 16,
                "kind": "process_aggregate",
                "target_pid": 100,
                "target_tid": 100,
            }
        )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "context_id": "runtime-context-" + "a" * 16,
            "kind": "os_thread",
            "target_pid": 100,
        },
        {
            "context_id": "runtime-context-" + "b" * 16,
            "kind": "process_aggregate",
            "target_pid": 100,
            "target_tid": 101,
        },
        {
            "context_id": "runtime-context-" + "c" * 16,
            "kind": "java_virtual_thread",
            "target_pid": 100,
            "target_tid": 101,
            "runtime_context_id": "runtime-native-" + "d" * 16,
        },
    ],
)
def test_execution_context_json_schema_matches_model_invariants(payload: dict[str, Any]) -> None:
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeExecutionContext.model_json_schema(), payload)
    with pytest.raises(ValidationError):
        RuntimeExecutionContext.model_validate(payload)


def test_runtime_target_binds_complete_docker_artifact_references() -> None:
    payload = {
        **_target(),
        "target_kind": "docker",
        "container_reference": _container_reference(),
    }
    _validate_json_schema(RuntimeTargetIdentity.model_json_schema(), payload)
    target = RuntimeTargetIdentity.model_validate(payload)
    assert isinstance(target.container_reference, RuntimeContainerTargetReference)

    for changed in (
        {**payload, "container_reference": None},
        {**payload, "target_kind": "host"},
        {
            **payload,
            "container_reference": {
                key: value
                for key, value in _container_reference().items()
                if key != "container_run_content_sha256"
            },
        },
    ):
        with pytest.raises(JsonSchemaValidationError):
            _validate_json_schema(RuntimeTargetIdentity.model_json_schema(), changed)
        with pytest.raises(ValidationError):
            RuntimeTargetIdentity.model_validate(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("symbol", "/home/alice/private/source.cpp"),
        ("symbol", r"C:\Users\alice\private\source.cpp"),
        ("symbol", r"\\server\share\source.cpp"),
        ("module", "/private/libprobe.so"),
        ("source_file", r"C:\private\source.cpp"),
    ],
)
def test_runtime_stack_frame_rejects_absolute_paths_in_public_labels(
    field: str,
    value: str,
) -> None:
    payload: dict[str, Any] = {"symbol": "worker", "module": "libworker.so"}
    payload[field] = value
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeStackFrame.model_json_schema(), payload)
    with pytest.raises(ValidationError, match="absolute-path"):
        RuntimeStackFrame.model_validate(payload)


@pytest.mark.parametrize(
    "name",
    [
        "/home/alice/worker",
        r"C:\Users\alice\worker",
        r"\\server\share\worker",
        "token=target-secret",
    ],
)
def test_runtime_context_name_rejects_sensitive_or_absolute_labels(name: str) -> None:
    payload = {
        "context_id": "runtime-context-" + "a" * 16,
        "kind": "os_thread",
        "target_pid": 100,
        "target_tid": 100,
        "name": name,
    }
    if "token=" not in name:
        with pytest.raises(JsonSchemaValidationError):
            _validate_json_schema(RuntimeExecutionContext.model_json_schema(), payload)
    with pytest.raises(ValidationError, match="sensitive or absolute-path"):
        RuntimeExecutionContext.model_validate(payload)


def test_schema_1_0_evidence_remains_strictly_readable() -> None:
    payload = _schema_1_0_evidence()
    evidence = RuntimeLockEvidenceArtifact.model_validate(payload)
    assert evidence.schema_version == "1.0"

    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_schema_1_0_evidence_preserves_legacy_pair_and_conclusion_acceptance() -> None:
    payload = _schema_1_0_evidence()
    payload["allowed_conclusions"] = [
        "observed_runtime_wait_distribution",
        "observed_runtime_wait_distribution",
    ]
    payload["events"][1]["wait_begin_event_id"] = "runtime-event-" + "f" * 16
    payload["events"][1]["duration_ns"] = 49

    evidence = RuntimeLockEvidenceArtifact.model_validate(payload)

    assert evidence.schema_version == "1.0"
    assert len(evidence.allowed_conclusions) == 2


def test_versionless_evidence_uses_the_legacy_contract() -> None:
    payload = _schema_1_0_evidence()
    payload.pop("schema_version")
    payload["source"].pop("schema_version")

    _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), payload)
    assert RuntimeLockEvidenceArtifact.model_validate(payload).schema_version == "1.0"


@pytest.mark.parametrize(
    ("surface", "field", "value"),
    [
        ("root", "execution_contexts", []),
        ("quality", "out_of_order_record_count", 0),
        ("event", "execution_context_id", None),
    ],
)
def test_schema_1_0_evidence_rejects_1_1_fields_even_when_empty(
    surface: str, field: str, value: Any
) -> None:
    payload = _schema_1_0_evidence()
    if surface == "root":
        payload[field] = value
    elif surface == "quality":
        payload["quality"][field] = value
    else:
        payload["events"][0][field] = value

    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), payload)
    with pytest.raises(ValidationError, match=r"schema 1\.0"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_schema_1_1_evidence_rejects_legacy_fields_and_missing_accounting() -> None:
    legacy_null = _evidence()
    legacy_null["events"][0]["target_tid"] = None
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), legacy_null)
    with pytest.raises(ValidationError, match="legacy TID fields"):
        RuntimeLockEvidenceArtifact.model_validate(legacy_null)

    missing_quality = _evidence()
    missing_quality["quality"].pop("stack_input_record_count")
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), missing_quality)
    with pytest.raises(ValidationError, match=r"requires 1\.1 accounting fields"):
        RuntimeLockEvidenceArtifact.model_validate(missing_quality)


@pytest.mark.parametrize(
    ("schema_version", "identity_field"),
    [("1.0", "target_tid"), ("1.1", "execution_context_id")],
)
def test_evidence_event_identity_is_required_by_schema_version(
    schema_version: str,
    identity_field: str,
) -> None:
    payload = _schema_1_0_evidence() if schema_version == "1.0" else _evidence()
    payload["events"][0].pop(identity_field)

    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), payload)
    with pytest.raises(ValidationError):
        RuntimeLockEvidenceArtifact.model_validate(payload)


@pytest.mark.parametrize("schema_version", ["1.0", "1.1"])
def test_unpark_context_is_required_by_schema_version(schema_version: str) -> None:
    payload = _schema_1_0_evidence() if schema_version == "1.0" else _evidence()
    event = payload["events"][0]
    event["event_kind"] = "unpark"
    event["lock_kind"] = "park"
    event.pop(
        "owner_target_tid" if schema_version == "1.0" else "owner_execution_context_id",
        None,
    )

    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), payload)
    with pytest.raises(
        ValidationError,
        match=r"requires ((a )?parked context|parked_target_tid)",
    ):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_evidence_and_source_schema_versions_match_in_json_schema_and_model() -> None:
    current_with_legacy_source = _evidence()
    current_with_legacy_source["source"]["schema_version"] = "1.0"
    current_with_legacy_source["source"].pop("converter_version")

    legacy_with_current_source = _schema_1_0_evidence()
    legacy_with_current_source["source"]["schema_version"] = "1.1"
    legacy_with_current_source["source"]["converter_version"] = "runtime-lock-ndjson-v1.1"

    for payload in (current_with_legacy_source, legacy_with_current_source):
        with pytest.raises(JsonSchemaValidationError):
            _validate_json_schema(RuntimeLockEvidenceArtifact.model_json_schema(), payload)
        with pytest.raises(ValidationError, match="versions must match"):
            RuntimeLockEvidenceArtifact.model_validate(payload)


def test_schema_1_1_evidence_always_forbids_unqualified_global_conclusions() -> None:
    payload = _evidence()
    payload["forbidden_conclusions"].remove("verified_improvement")
    with pytest.raises(ValidationError, match="mandatory forbidden"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["allowed_conclusions"].append("performance_root_cause")
    payload["forbidden_conclusions"].remove("performance_root_cause")
    with pytest.raises(ValidationError, match="categorically forbidden"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_source_converter_version_is_schema_bound() -> None:
    payload = _evidence()
    payload["source"].pop("converter_version")
    with pytest.raises(ValidationError, match="requires a converter version"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _schema_1_0_evidence()
    payload["source"]["converter_version"] = "runtime-lock-ndjson-v1.1"
    with pytest.raises(ValidationError, match="cannot carry converter_version"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_runtime_source_converter_json_schema_matches_model_version_rules() -> None:
    current = _source()
    _validate_json_schema(RuntimeSourceManifest.model_json_schema(), current)
    assert RuntimeSourceManifest.model_validate(current).schema_version == "1.1"

    missing_current = _source()
    missing_current.pop("converter_version")
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeSourceManifest.model_json_schema(), missing_current)
    with pytest.raises(ValidationError, match="requires a converter version"):
        RuntimeSourceManifest.model_validate(missing_current)

    legacy = _source()
    legacy["schema_version"] = "1.0"
    legacy.pop("converter_version")
    _validate_json_schema(RuntimeSourceManifest.model_json_schema(), legacy)
    assert RuntimeSourceManifest.model_validate(legacy).schema_version == "1.0"

    legacy_with_converter = {**legacy, "converter_version": "runtime-lock-ndjson-v1.1"}
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeSourceManifest.model_json_schema(), legacy_with_converter)
    with pytest.raises(ValidationError, match="cannot carry converter_version"):
        RuntimeSourceManifest.model_validate(legacy_with_converter)

    legacy_with_null = {**legacy, "converter_version": None}
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeSourceManifest.model_json_schema(), legacy_with_null)
    with pytest.raises(ValidationError, match="cannot carry converter_version"):
        RuntimeSourceManifest.model_validate(legacy_with_null)

    versionless_legacy = dict(legacy)
    versionless_legacy.pop("schema_version")
    _validate_json_schema(RuntimeSourceManifest.model_json_schema(), versionless_legacy)
    assert RuntimeSourceManifest.model_validate(versionless_legacy).schema_version == "1.0"


def test_schema_1_1_rejects_unbound_ids_and_legacy_tid() -> None:
    payload = _evidence()
    for event in payload["events"]:
        event["lock_id"] = "runtime-lock-" + "f" * 20
    with pytest.raises(ValidationError, match="not bound"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][0]["target_tid"] = 101
    with pytest.raises(ValidationError, match="legacy TID fields"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_wait_pair_references_type_identity_time_and_duration() -> None:
    payload = _evidence()
    payload["events"][1]["wait_begin_event_id"] = "runtime-event-" + "f" * 16
    with pytest.raises(ValidationError, match="non-wait_begin"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][1]["duration_ns"] = 49
    with pytest.raises(ValidationError, match="duration contradicts"):
        RuntimeLockEvidenceArtifact.model_validate(payload)

    payload = _evidence()
    payload["events"][1]["lock_kind"] = "semaphore"
    with pytest.raises(ValidationError, match="changed lock identity or kind"):
        RuntimeLockEvidenceArtifact.model_validate(payload)


def test_quality_conserves_out_of_order_events_and_stack_records() -> None:
    payload = _quality(status="partial")
    payload.update(
        {
            "input_record_count": 3,
            "out_of_order_record_count": 1,
            "stack_input_record_count": 2,
            "emitted_stack_count": 1,
            "duplicate_stack_record_count": 1,
        }
    )
    payload["limitations"] = ["one event was out of order"]
    quality = RuntimeEvidenceQuality.model_validate(payload)
    assert quality.stack_input_record_count == 2

    payload["stack_input_record_count"] = 3
    with pytest.raises(ValidationError, match="stack records are not conserved"):
        RuntimeEvidenceQuality.model_validate(payload)


def test_distribution_rejects_non_floor_mean_and_non_monotonic_quantiles() -> None:
    payload = _one_distribution()
    payload["mean_ns"] = 49
    with pytest.raises(ValidationError, match="integer floor"):
        RuntimeNanosecondDistribution.model_validate(payload)

    payload = _one_distribution()
    payload["p95_ns"] = 60
    with pytest.raises(ValidationError, match="monotonic"):
        RuntimeNanosecondDistribution.model_validate(payload)


def _exact_metrics() -> dict[str, Any]:
    return {
        "exact_waits": _one_distribution(),
        "thresholded_waits": _zero_distribution(),
        "sampled_observation_count": 0,
        "cumulative_observation_count": 0,
        "observed_or_estimated_wait_ns": 50,
        "exact_holds": _zero_distribution(),
        "owner_observed_count": 0,
    }


def _coverage(*, rows: int = 1) -> dict[str, int]:
    return {
        "total_row_count": rows,
        "exported_row_count": rows,
        "omitted_row_count": 0,
        "omitted_exact_wait_count": 0,
        "omitted_exact_wait_ns": 0,
        "omitted_thresholded_wait_count": 0,
        "omitted_thresholded_wait_ns": 0,
        "omitted_sampled_observation_count": 0,
        "omitted_cumulative_observation_count": 0,
        "omitted_observed_or_estimated_wait_ns": 0,
        "omitted_exact_hold_count": 0,
        "omitted_exact_hold_ns": 0,
        "omitted_owner_observed_count": 0,
    }


def _analysis() -> dict[str, Any]:
    metrics = _exact_metrics()
    return {
        "schema_version": "1.1",
        "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
        "runtime_lock_evidence_id": EVIDENCE_ID,
        "runtime_lock_evidence_content_sha256": ZERO_SHA,
        "runtime_lock_evidence_content_bytes": 1024,
        "created_at": "2026-08-16T00:00:00+00:00",
        "runtime": "python",
        "measurement_semantics": "exact",
        "quality_status": "complete",
        "limits": {},
        "aggregates": [
            {
                "lock_id": LOCK_ID,
                "lock_kind": "mutex",
                "waiter_execution_context_count": 1,
                **metrics,
            }
        ],
        "execution_context_aggregates": [
            {"execution_context_id": CONTEXT_ID, "lock_count": 1, **metrics}
        ],
        "call_path_aggregates": [
            {
                "stack_id": None,
                "lock_count": 1,
                "execution_context_count": 1,
                **metrics,
            }
        ],
        "wait_outcome_aggregates": [
            {
                "wait_outcome": "acquired",
                "lock_count": 1,
                "execution_context_count": 1,
                **metrics,
            }
        ],
        "lock_kind_aggregates": [
            {
                "lock_kind": "mutex",
                "lock_count": 1,
                "execution_context_count": 1,
                **metrics,
            }
        ],
        "total_exact_wait_count": 1,
        "total_exact_wait_ns": 50,
        "total_thresholded_wait_count": 0,
        "total_thresholded_wait_ns": 0,
        "total_sampled_observation_count": 0,
        "total_cumulative_observation_count": 0,
        "total_observed_or_estimated_wait_ns": 50,
        "total_exact_hold_count": 0,
        "total_exact_hold_ns": 0,
        "total_owner_observed_count": 0,
        "lock_coverage": _coverage(),
        "execution_context_coverage": _coverage(),
        "call_path_coverage": _coverage(),
        "wait_outcome_coverage": _coverage(),
        "lock_kind_coverage": _coverage(),
        "omitted_lock_count": 0,
        "allowed_conclusions": ["observed_runtime_wait_distribution"],
        "forbidden_conclusions": ["exact_owner_relationship", "exact_hold_time"],
        "analysis_fingerprint": ONE_SHA,
        "content_sha256": ZERO_SHA,
        "content_bytes": 512,
    }


def _schema_1_0_analysis() -> dict[str, Any]:
    payload = _analysis()
    payload["schema_version"] = "1.0"
    for field in _SCHEMA_1_1_ANALYSIS_TEST_FIELDS:
        payload.pop(field)
    payload["aggregates"][0].pop("waiter_execution_context_count")
    payload["aggregates"][0]["waiter_thread_count"] = 1
    return payload


_SCHEMA_1_1_ANALYSIS_TEST_FIELDS = (
    "execution_context_aggregates",
    "call_path_aggregates",
    "wait_outcome_aggregates",
    "lock_kind_aggregates",
    "lock_coverage",
    "execution_context_coverage",
    "call_path_coverage",
    "wait_outcome_coverage",
    "lock_kind_coverage",
    "total_exact_wait_ns",
    "total_thresholded_wait_ns",
    "total_observed_or_estimated_wait_ns",
    "total_exact_hold_ns",
    "total_owner_observed_count",
)


def test_analysis_all_projection_metrics_are_conserved() -> None:
    aggregate = RuntimeLockAggregate.model_validate(_analysis()["aggregates"][0])
    assert aggregate.waiter_execution_context_count == 1

    payload = _analysis()
    analysis = RuntimeLockAnalysisArtifact.model_validate(payload)
    assert analysis.total_exact_wait_count == 1

    payload["call_path_coverage"].update(
        {"total_row_count": 2, "omitted_row_count": 1, "omitted_exact_wait_count": 1}
    )
    with pytest.raises(ValidationError, match="not conserved"):
        RuntimeLockAnalysisArtifact.model_validate(payload)


def test_schema_1_0_analysis_remains_readable_without_new_projections() -> None:
    payload = _schema_1_0_analysis()
    payload["aggregates"][0]["observed_or_estimated_wait_ns"] = 999
    payload["allowed_conclusions"] = [
        "observed_runtime_wait_distribution",
        "observed_runtime_wait_distribution",
    ]
    analysis = RuntimeLockAnalysisArtifact.model_validate(payload)
    assert analysis.schema_version == "1.0"


def test_versionless_analysis_uses_the_legacy_contract() -> None:
    payload = _schema_1_0_analysis()
    payload.pop("schema_version")

    _validate_json_schema(RuntimeLockAnalysisArtifact.model_json_schema(), payload)
    assert RuntimeLockAnalysisArtifact.model_validate(payload).schema_version == "1.0"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("execution_context_aggregates", []),
        ("lock_coverage", None),
        ("total_exact_wait_ns", 0),
    ],
)
def test_schema_1_0_analysis_rejects_1_1_fields_even_when_empty(field: str, value: Any) -> None:
    payload = _schema_1_0_analysis()
    payload[field] = value

    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockAnalysisArtifact.model_json_schema(), payload)
    with pytest.raises(ValidationError, match=r"schema 1\.0"):
        RuntimeLockAnalysisArtifact.model_validate(payload)


def test_analysis_waiter_cardinality_shape_matches_schema_version() -> None:
    legacy = _schema_1_0_analysis()
    legacy["aggregates"][0]["waiter_execution_context_count"] = None
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockAnalysisArtifact.model_json_schema(), legacy)
    with pytest.raises(ValidationError, match=r"schema 1\.0"):
        RuntimeLockAnalysisArtifact.model_validate(legacy)

    current = _analysis()
    current["aggregates"][0]["waiter_thread_count"] = None
    with pytest.raises(JsonSchemaValidationError):
        _validate_json_schema(RuntimeLockAnalysisArtifact.model_json_schema(), current)
    with pytest.raises(ValidationError, match="legacy cardinality"):
        RuntimeLockAnalysisArtifact.model_validate(current)


def test_schema_1_1_analysis_rejects_per_row_wait_weight_tampering() -> None:
    payload = _analysis()
    payload["aggregates"][0]["observed_or_estimated_wait_ns"] = 49
    payload["lock_coverage"].update(
        {
            "total_row_count": 2,
            "omitted_row_count": 1,
            "omitted_observed_or_estimated_wait_ns": 1,
        }
    )

    with pytest.raises(ValidationError, match="wait weight contradicts"):
        RuntimeLockAnalysisArtifact.model_validate(payload)

    zero_count = _analysis()
    zero_count["aggregates"][0]["exact_waits"] = _zero_distribution()
    zero_count["aggregates"][0]["observed_or_estimated_wait_ns"] = 1
    with pytest.raises(ValidationError, match="wait weight contradicts"):
        RuntimeLockAnalysisArtifact.model_validate(zero_count)

    omitted = _analysis()
    omitted["lock_coverage"].update(
        {
            "total_row_count": 2,
            "omitted_row_count": 1,
            "omitted_exact_wait_count": 1,
            "omitted_exact_wait_ns": 1,
            "omitted_observed_or_estimated_wait_ns": 0,
        }
    )
    with pytest.raises(ValidationError, match="omitted wait weight"):
        RuntimeLockAnalysisArtifact.model_validate(omitted)


def test_non_exact_analysis_cannot_claim_exact_count() -> None:
    payload = _analysis()
    payload["runtime"] = "go"
    payload["measurement_semantics"] = "cumulative"
    payload["aggregates"] = []
    payload["execution_context_aggregates"] = []
    payload["call_path_aggregates"] = []
    payload["wait_outcome_aggregates"] = []
    payload["lock_kind_aggregates"] = []
    for field in (
        "total_exact_wait_count",
        "total_exact_wait_ns",
        "total_observed_or_estimated_wait_ns",
    ):
        payload[field] = 0
    for field in (
        "lock_coverage",
        "execution_context_coverage",
        "call_path_coverage",
        "wait_outcome_coverage",
        "lock_kind_coverage",
    ):
        payload[field] = _coverage(rows=0)
    payload["allowed_conclusions"] = ["cumulative_runtime_contention_distribution"]
    payload["forbidden_conclusions"] = ["exact_owner_relationship"]
    with pytest.raises(ValidationError, match="forbid exact counts"):
        RuntimeLockAnalysisArtifact.model_validate(payload)


def test_verification_status_is_derived_from_checks() -> None:
    passed = RuntimeLockVerificationCheck(
        name="content_hash", status="passed", detail="content digest matches"
    )
    verification = RuntimeLockAnalysisVerificationArtifact.model_validate(
        {
            "schema_version": "1.1",
            "runtime_lock_verification_id": "runtime-lock-verification-" + "a" * 16,
            "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
            "runtime_lock_evidence_content_sha256": ZERO_SHA,
            "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
            "runtime_lock_analysis_content_sha256": ONE_SHA,
            "created_at": "2026-08-16T00:00:00+00:00",
            "verification_status": "verified",
            "checks": [passed.model_dump(mode="json")],
            "content_sha256": ZERO_SHA,
        }
    )
    assert verification.verification_status == "verified"
    assert verification.schema_version == "1.1"
    assert verification.verifier_version == "runtime-lock-verifier-v2"

    payload = verification.model_dump(mode="json")
    payload["checks"][0]["status"] = "failed"
    with pytest.raises(ValidationError, match="contradicts"):
        RuntimeLockAnalysisVerificationArtifact.model_validate(payload)

    legacy = verification.model_dump(mode="json")
    legacy["schema_version"] = "1.0"
    legacy["verifier_version"] = "runtime-lock-verifier-v1"
    assert RuntimeLockAnalysisVerificationArtifact.model_validate(legacy).schema_version == "1.0"


def test_verifier_version_defaults_and_json_schema_follow_the_artifact_schema() -> None:
    common = {
        "runtime_lock_verification_id": "runtime-lock-verification-" + "b" * 16,
        "runtime_lock_evidence_id": "runtime-lock-evidence-" + "a" * 16,
        "runtime_lock_evidence_content_sha256": ZERO_SHA,
        "runtime_lock_analysis_id": "runtime-lock-analysis-" + "a" * 16,
        "runtime_lock_analysis_content_sha256": ONE_SHA,
        "created_at": "2026-08-16T00:00:00+00:00",
        "verification_status": "verified",
        "checks": [{"name": "content_hash", "status": "passed", "detail": "matches"}],
        "content_sha256": ZERO_SHA,
    }
    schema = RuntimeLockAnalysisVerificationArtifact.model_json_schema()

    _validate_json_schema(schema, common)
    legacy = RuntimeLockAnalysisVerificationArtifact.model_validate(common)
    assert legacy.schema_version == "1.0"
    assert legacy.verifier_version == "runtime-lock-verifier-v1"

    current = {**common, "schema_version": "1.1"}
    _validate_json_schema(schema, current)
    assert (
        RuntimeLockAnalysisVerificationArtifact.model_validate(current).verifier_version
        == "runtime-lock-verifier-v2"
    )

    for payload in (
        {**common, "schema_version": "1.0", "verifier_version": "runtime-lock-verifier-v2"},
        {**common, "schema_version": "1.1", "verifier_version": "runtime-lock-verifier-v1"},
    ):
        with pytest.raises(JsonSchemaValidationError):
            _validate_json_schema(schema, payload)
        with pytest.raises(ValidationError, match="contradicts"):
            RuntimeLockAnalysisVerificationArtifact.model_validate(payload)
