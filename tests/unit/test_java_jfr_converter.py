from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeLockEvidenceArtifact, RuntimeWaitEndEvent
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks import java_jfr_stream
from perflens.runtime_locks.java_jfr_converter import (
    convert_java_jfr_json,
    verify_java_jfr_replay,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/runtime_locks/jfr"
CREATED_AT = "2026-08-30T00:00:00+00:00"


def _duplicate_key(raw: bytes) -> bytes:
    return raw.replace(b'"type":', b'"type":"duplicate","type":', 1)


def _non_finite(raw: bytes) -> bytes:
    return raw.replace(b'"address": 140', b'"address": NaN, "discard": 140', 1)


def _unknown_field(raw: bytes) -> bytes:
    return raw.replace(b'"duration":', b'"unknownField":1,"duration":', 1)


def _truncated(raw: bytes) -> bytes:
    return raw[:-3]


def _whitespace_inside_prefix_key(raw: bytes) -> bytes:
    return raw.replace(b'"recording"', b'"rec ording"', 1)


def _convert(raw: bytes, jdk: int = 25):
    return convert_java_jfr_json(
        BytesIO(raw),
        execution_binding=_binding(jdk),
        target_pid=9000,
        target_uid=1000,
        target_start_time_ticks=77,
        created_at=CREATED_AT,
    )


def _binding(jdk: int = 25, *, profile: str = "deep") -> RuntimeLockAdapterExecutionBinding:
    version = f"{jdk}.0.1"
    tools = (
        RuntimeLockAdapterToolBinding(name="java", version=version, binary_sha256="1" * 64),
        RuntimeLockAdapterToolBinding(name="jfr", version=version, binary_sha256="2" * 64),
    )
    threshold = 1_000_000 if profile == "deep" else 10_000_000
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    execution = derive_runtime_lock_adapter_execution_identity(
        "java_jfr",
        "java-jfr-adapter-v1",
        "jfr",
        version,
        profile,
        "thresholded",
        threshold,
        toolchain,
        "3" * 64,
        "4" * 64,
        "5" * 64,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="java_jfr",
        adapter_version="java-jfr-adapter-v1",
        backend_id="jfr",
        runtime_version=version,
        profile=profile,
        measurement_semantics="thresholded",
        duration_threshold_ns=threshold,
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="3" * 64,
        metadata_sha256="4" * 64,
        runtime_payload_identity_sha256="5" * 64,
        execution_identity_sha256=execution,
    )


@pytest.mark.parametrize("jdk", [21, 25])
def test_real_jfr_fixtures_convert_without_leaking_private_identity(jdk: int) -> None:
    raw = (FIXTURES / f"jdk{jdk}-locks.json").read_bytes()
    receipt = _convert(raw, jdk)
    evidence = receipt.evidence
    private = json.loads(raw)["recording"]["events"]
    assert len(evidence.events) >= 3
    assert evidence.quality.status == "complete"
    assert evidence.source.fast_path_visibility == "none"
    assert "exact_owner_relationship" in evidence.forbidden_conclusions
    assert {event.event_kind for event in evidence.events} == {"wait_end"}
    assert {event.lock_kind for event in evidence.events} >= {"mutex", "condition", "park"}
    monitor_enter = next(
        event
        for event in evidence.events
        if isinstance(event, RuntimeWaitEndEvent) and event.lock_kind == "mutex"
    )
    monitor_waits = [
        event
        for event in evidence.events
        if isinstance(event, RuntimeWaitEndEvent) and event.lock_kind == "condition"
    ]
    timed_out_wait = next(event for event in monitor_waits if event.outcome == "timed_out")
    notified_wait = next(event for event in monitor_waits if event.outcome == "notified")
    park = next(
        event
        for event in evidence.events
        if isinstance(event, RuntimeWaitEndEvent) and event.lock_kind == "park"
    )
    assert monitor_enter.owner_execution_context_id is not None
    assert timed_out_wait.owner_execution_context_id is None
    assert notified_wait.owner_execution_context_id is None
    assert {event.outcome for event in monitor_waits} == {"timed_out", "notified"}
    raw_monitor_waits = [event for event in private if event["type"] == "jdk.JavaMonitorWait"]
    assert any(event["values"]["timedOut"] is True for event in raw_monitor_waits)
    assert any(
        event["values"]["timedOut"] is False and event["values"]["notifier"] is not None
        for event in raw_monitor_waits
    )
    assert park.outcome == "unknown"
    assert park.lock_id is None
    public = evidence.model_dump_json()
    assert all(
        str(event["values"]["address"]) not in public
        for event in private
        if event["values"]["address"] != 0
    )
    assert all(context.name is None for context in evidence.execution_contexts)
    assert "jrt:/" not in public and '"location"' not in public
    assert any(
        stack.frames[0].symbol == "java.lang.Thread.run"
        and stack.frames[-1].symbol == "java.lang.Object.wait0"
        for stack in evidence.stacks
    )
    replay = verify_java_jfr_replay(
        BytesIO(raw),
        expected=receipt,
        execution_binding=_binding(jdk),
        target_pid=9000,
        target_uid=1000,
        target_start_time_ticks=77,
        created_at=CREATED_AT,
    )
    assert replay == receipt


def test_monitor_wait_without_real_notifier_does_not_invent_notification() -> None:
    payload = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    monitor_wait = next(
        event
        for event in payload["recording"]["events"]
        if event["type"] == "jdk.JavaMonitorWait" and not event["values"]["timedOut"]
    )
    monitor_wait["values"]["notifier"] = None

    evidence = _convert(json.dumps(payload).encode(), 25).evidence
    condition_events = [
        event
        for event in evidence.events
        if isinstance(event, RuntimeWaitEndEvent) and event.lock_kind == "condition"
    ]
    observed = next(event for event in condition_events if event.outcome != "timed_out")
    assert observed.outcome == "unknown"
    assert {event.outcome for event in condition_events} == {"timed_out", "unknown"}


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (_duplicate_key, ErrorCode.PROFILE_PARSE_FAILED),
        (_non_finite, ErrorCode.PROFILE_PARSE_FAILED),
        (_unknown_field, ErrorCode.PROFILE_PARSE_FAILED),
        (_truncated, ErrorCode.PROFILE_PARSE_FAILED),
        (_whitespace_inside_prefix_key, ErrorCode.PROFILE_PARSE_FAILED),
    ],
)
def test_strict_stream_rejects_malformed_json(
    mutator: Callable[[bytes], bytes], code: ErrorCode
) -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    with pytest.raises(PerfLensError) as raised:
        _convert(mutator(raw))
    assert raised.value.code == code


def test_stream_enforces_source_event_and_depth_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    monkeypatch.setattr(java_jfr_stream, "MAX_JFR_JSON_BYTES", len(raw) - 1)
    with pytest.raises(PerfLensError, match="64 MiB"):
        _convert(raw)
    monkeypatch.setattr(java_jfr_stream, "MAX_JFR_JSON_BYTES", 67_108_864)
    monkeypatch.setattr(java_jfr_stream, "MAX_JFR_EVENTS", 1)
    with pytest.raises(PerfLensError, match="event count"):
        _convert(raw)
    deep = b'{"recording":{"events":[{"type":"jdk.ThreadPark","values":' + b"[" * 193
    with pytest.raises(PerfLensError, match="nesting"):
        _convert(deep)


def test_virtual_thread_never_claims_an_os_tid() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    event = document["recording"]["events"][0]
    event["values"]["eventThread"]["virtual"] = True
    event["values"]["eventThread"]["osThreadId"] = 0
    receipt = _convert(json.dumps(document, separators=(",", ":")).encode())
    context = next(
        context
        for context in receipt.evidence.execution_contexts
        if context.kind == "java_virtual_thread"
    )
    assert context.target_tid is None
    assert context.runtime_context_id is not None


def test_jdk17_thread_metadata_without_virtual_flag_is_accepted_as_platform() -> None:
    document = json.loads((FIXTURES / "jdk21-locks.json").read_bytes())
    for event in document["recording"]["events"]:
        event["values"]["eventThread"].pop("virtual", None)
        owner = event["values"].get("previousOwner")
        if owner is not None:
            owner.pop("virtual", None)
        notifier = event["values"].get("notifier")
        if notifier is not None:
            notifier.pop("virtual", None)
    evidence = _convert(json.dumps(document, separators=(",", ":")).encode(), 17).evidence
    assert all(context.kind != "java_virtual_thread" for context in evidence.execution_contexts)


@pytest.mark.parametrize("jdk", [21, 25])
def test_jdk21_and_newer_require_explicit_virtual_thread_metadata(jdk: int) -> None:
    document = json.loads((FIXTURES / f"jdk{jdk}-locks.json").read_bytes())
    event = next(item for item in document["recording"]["events"] if item["type"] != "jdk.DataLoss")
    event["values"]["eventThread"].pop("virtual")
    with pytest.raises(PerfLensError, match="virtual-thread marker"):
        _convert(json.dumps(document, separators=(",", ":")).encode(), jdk)


@pytest.mark.parametrize("field", ["monitorClass", "parkedClass"])
def test_lock_class_metadata_uses_the_strict_java_type_shape(field: str) -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    event = next(item for item in document["recording"]["events"] if field in item["values"])
    event["values"][field] = {"name": "drift"}
    with pytest.raises(PerfLensError, match="strict validation"):
        _convert(json.dumps(document, separators=(",", ":")).encode())


def test_stack_depth_above_jfr_print_contract_is_rejected() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    frames = document["recording"]["events"][0]["values"]["stackTrace"]["frames"]
    frames[:] = [frames[0] for _ in range(128)]
    with pytest.raises(PerfLensError, match="strict validation"):
        _convert(json.dumps(document, separators=(",", ":")).encode())


def test_stack_trace_requires_frames_and_a_strict_truncated_boolean() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    stack_trace = document["recording"]["events"][0]["values"]["stackTrace"]
    stack_trace.pop("frames")
    with pytest.raises(PerfLensError, match="strict validation"):
        _convert(json.dumps(document, separators=(",", ":")).encode())

    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    document["recording"]["events"][0]["values"]["stackTrace"]["truncated"] = "false"
    with pytest.raises(PerfLensError, match="strict validation"):
        _convert(json.dumps(document, separators=(",", ":")).encode())


def test_empty_stack_frames_are_accepted_only_as_explicit_partial_evidence() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    document["recording"]["events"][0]["values"]["stackTrace"]["frames"] = []

    evidence = _convert(json.dumps(document, separators=(",", ":")).encode()).evidence

    assert evidence.quality.status == "partial"
    assert any("empty frame list" in value for value in evidence.quality.limitations)
    assert "unqualified_runtime_lock_conclusion" in evidence.forbidden_conclusions
    assert any(event.stack_id is None for event in evidence.events)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_method",
        "missing_type",
        "string_hidden",
        "overlong_name",
        "boolean_line",
    ],
)
def test_stack_frame_method_and_type_are_strict_and_bounded(mutation: str) -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    frame = document["recording"]["events"][0]["values"]["stackTrace"]["frames"][0]
    if mutation == "missing_method":
        frame["method"] = {}
    elif mutation == "missing_type":
        frame["method"]["type"] = {}
    elif mutation == "string_hidden":
        frame["method"]["type"]["hidden"] = "false"
    elif mutation == "overlong_name":
        frame["method"]["name"] = "x" * 4097
    else:
        frame["lineNumber"] = True
    with pytest.raises(PerfLensError, match="strict validation"):
        _convert(json.dumps(document, separators=(",", ":")).encode())


def test_data_loss_is_partial_and_reports_bytes_as_a_limitation() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    document["recording"]["events"].insert(
        0,
        {
            "type": "jdk.DataLoss",
            "values": {
                "startTime": "2026-08-30T00:00:00.000000001+00:00",
                "amount": 4096,
                "total": 4096,
            },
        },
    )
    evidence = _convert(json.dumps(document, separators=(",", ":")).encode()).evidence
    assert evidence.quality.status == "partial"
    assert evidence.quality.lost_event_count == 0
    assert evidence.quality.lost_source_bytes == 4096
    assert any("4096 lost source bytes" in value for value in evidence.quality.limitations)


def test_zero_event_and_data_loss_only_evidence_are_honest() -> None:
    empty = _convert(b'{"recording":{"events":[]}}').evidence
    assert empty.events == ()
    assert empty.quality.lost_source_bytes == 0
    assert empty.quality.status == "partial"
    assert any("no accepted events" in item.lower() for item in empty.quality.limitations)

    data_loss = {
        "recording": {
            "events": [
                {
                    "type": "jdk.DataLoss",
                    "values": {
                        "startTime": "2026-08-30T00:00:00.000000001+00:00",
                        "amount": 64,
                        "total": 64,
                    },
                }
            ]
        }
    }
    evidence = _convert(json.dumps(data_loss, separators=(",", ":")).encode()).evidence
    assert evidence.events == ()
    assert evidence.quality.status == "partial"
    assert evidence.quality.lost_source_bytes == 64
    assert any("64 lost source bytes" in item for item in evidence.quality.limitations)


def test_jfr_source_is_fully_bound_and_path_free() -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    binding = _binding(25)
    evidence = _convert(raw).evidence
    assert evidence.quality.lost_source_bytes == 0
    source = evidence.source
    assert source.runtime == "java"
    assert source.adapter_id == "java_jfr"
    assert source.adapter_version == binding.adapter_version
    assert source.backend_id == "jfr"
    assert source.backend_version == binding.runtime_version
    assert source.target_scope == "bound_pid"
    assert source.tool is not None
    assert source.tool.name == source.tool.path == "jfr"
    assert source.tool.binary_sha256 == binding.tools[1].binary_sha256
    assert source.adapter_execution_identity_sha256 == binding.execution_identity_sha256
    assert source.configuration_sha256 == binding.configuration_sha256
    assert source.metadata_sha256 == binding.metadata_sha256
    public = evidence.model_dump_json()
    assert "/usr/" not in public and "/home/" not in public
    without_loss_disclosure = evidence.model_dump(mode="json", exclude_none=True)
    without_loss_disclosure["quality"].pop("lost_source_bytes")
    with pytest.raises(ValueError, match=r"must disclose jdk\.DataLoss bytes"):
        RuntimeLockEvidenceArtifact.model_validate(without_loss_disclosure)


def test_profile_threshold_and_jdk_version_are_content_bound() -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    with pytest.raises(PerfLensError, match="threshold"):
        convert_java_jfr_json(
            BytesIO(raw),
            execution_binding=_binding(25, profile="deep").model_copy(
                update={"duration_threshold_ns": 10_000_000}
            ),
            target_pid=1,
            target_uid=1,
            target_start_time_ticks=1,
            created_at=CREATED_AT,
        )
    with pytest.raises(PerfLensError, match="reviewed JDK"):
        _convert(raw, 22)


def test_wait_end_timestamp_is_start_plus_duration_and_end_ordered() -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    evidence = _convert(raw).evidence
    assert [event.timestamp_ns for event in evidence.events] == [
        70_396_925,
        112_077_606,
        112_263_772,
        132_676_046,
    ]
    assert all(
        isinstance(event, RuntimeWaitEndEvent) and event.timestamp_ns >= event.duration_ns
        for event in evidence.events
    )


def test_end_ordered_events_may_start_before_the_first_source_event() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    events = document["recording"]["events"]
    events[0]["values"]["startTime"] = "2026-08-30T18:33:02.200000000+08:00"
    events[0]["values"]["duration"] = "PT0.020S"
    events[1]["values"]["startTime"] = "2026-08-30T18:33:02.190000000+08:00"
    events[1]["values"]["duration"] = "PT0.040S"

    evidence = _convert(json.dumps(document, separators=(",", ":")).encode()).evidence

    assert [event.timestamp_ns for event in evidence.events[:2]] == [30_000_000, 40_000_000]
    assert [event.timestamp_ns for event in evidence.events] == sorted(
        event.timestamp_ns for event in evidence.events
    )
    assert all(
        isinstance(event, RuntimeWaitEndEvent) and event.timestamp_ns >= event.duration_ns
        for event in evidence.events
    )


def test_wait_end_timestamp_and_duration_enforce_signed_64_bit_bound() -> None:
    document = json.loads((FIXTURES / "jdk25-locks.json").read_bytes())
    events = document["recording"]["events"]
    events[0]["values"]["startTime"] = "1970-01-01T00:00:00+00:00"
    events[0]["values"]["duration"] = "PT1S"
    events[1]["values"]["startTime"] = "2262-04-11T23:47:16+00:00"
    events[1]["values"]["duration"] = "PT1S"
    with pytest.raises(PerfLensError, match="wait end timestamp exceeds"):
        _convert(json.dumps(document, separators=(",", ":")).encode())

    events[1]["values"]["startTime"] = "1970-01-01T00:00:02+00:00"
    events[1]["values"]["duration"] = "PT9223372037S"
    with pytest.raises(PerfLensError, match="duration exceeds"):
        _convert(json.dumps(document, separators=(",", ":")).encode())


def test_private_replay_compares_complete_conversion_receipt() -> None:
    raw = (FIXTURES / "jdk25-locks.json").read_bytes()
    receipt = _convert(raw)
    assert (
        verify_java_jfr_replay(
            BytesIO(raw),
            expected=replace(receipt, normalized_source_sha256="f" * 64),
            execution_binding=_binding(25),
            target_pid=9000,
            target_uid=1000,
            target_start_time_ticks=77,
            created_at=CREATED_AT,
        )
        is None
    )
