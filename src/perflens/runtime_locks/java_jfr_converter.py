"""Convert bounded JFR JSON lock events into public Runtime Lock Evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from tempfile import SpooledTemporaryFile
from typing import Any, BinaryIO, cast

from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
)
from perflens.contracts.runtime_locks import RuntimeLockEvidenceArtifact, RuntimeToolIdentity
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.importer import import_runtime_lock_ndjson
from perflens.runtime_locks.java_jfr_models import JfrDataLossEvent, JfrLockEvent, JfrThread
from perflens.runtime_locks.java_jfr_stream import JfrJsonEventStream

JAVA_JFR_CONVERTER_VERSION = "java-jfr-converter-v1"
_DURATION = re.compile(r"^PT([0-9]+)(?:\.([0-9]{1,9}))?S$")
_TIMESTAMP = re.compile(r"^(.*?)(?:\.([0-9]{1,9}))?([+-][0-9]{2}:[0-9]{2}|Z)$")
_SUPPORTED_JDKS = frozenset({17, 21, 25})
_MAX_NORMALIZED_SOURCE_BYTES = 67_108_864
_MAX_TIME_NS = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class JavaJfrConversionReceipt:
    evidence: RuntimeLockEvidenceArtifact
    raw_source_sha256: str
    raw_source_bytes: int
    normalized_source_sha256: str
    normalized_source_bytes: int


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PROFILE_PARSE_FAILED, "java_jfr_conversion", message)


def _validate_execution_binding(
    binding: RuntimeLockAdapterExecutionBinding,
) -> tuple[int, int, RuntimeLockAdapterToolBinding]:
    try:
        binding = RuntimeLockAdapterExecutionBinding.model_validate(binding.model_dump(mode="json"))
    except ValueError:
        raise _invalid(
            "JFR execution binding profile, threshold, toolchain, or identity failed "
            "deterministic validation"
        ) from None
    if (
        binding.adapter_id != "java_jfr"
        or binding.adapter_version != "java-jfr-adapter-v1"
        or binding.backend_id != "jfr"
        or binding.measurement_semantics != "thresholded"
    ):
        raise _invalid("JFR converter requires the complete authorized Java execution binding")
    try:
        jdk_major = int(binding.runtime_version.split(".", 1)[0])
    except ValueError:
        raise _invalid("JFR execution binding runtime version is malformed") from None
    if jdk_major not in _SUPPORTED_JDKS:
        raise _invalid("JFR converter only accepts the reviewed JDK 17, 21, and 25 formats")
    tools = {tool.name: tool for tool in binding.tools}
    if set(tools) != {"java", "jfr"}:
        raise _invalid("JFR execution binding must identify fixed java and jfr tools")
    if tools["java"].version != binding.runtime_version or (
        tools["jfr"].version != binding.runtime_version
    ):
        raise _invalid("JFR tool versions differ from the authorized runtime")
    assert binding.duration_threshold_ns is not None
    return jdk_major, binding.duration_threshold_ns, tools["jfr"]


def convert_java_jfr_json(
    stream: BinaryIO,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    created_at: str,
) -> JavaJfrConversionReceipt:
    jdk_major, duration_threshold_ns, jfr_tool = _validate_execution_binding(execution_binding)
    if jdk_major not in _SUPPORTED_JDKS:
        raise _invalid("JFR converter only accepts the reviewed JDK 17, 21, and 25 formats")
    reader = JfrJsonEventStream(stream)
    projected: list[dict[str, Any]] = []
    stacks: list[dict[str, Any]] = []
    first_timestamp: int | None = None
    observed_tids: set[int] = {target_pid}
    lost_bytes = 0
    source_tokens: dict[tuple[int, str], str] = {}
    stack_tokens: dict[str, str] = {}
    stack_truncated = False
    empty_stack_trace_count = 0
    for source_index, event in enumerate(reader):
        if isinstance(event, JfrDataLossEvent):
            lost_bytes += event.values.amount
            continue
        _validate_thread_metadata_for_jdk(event, jdk_major)
        wait_start_timestamp = _timestamp_ns(event.values.startTime)
        first_timestamp = wait_start_timestamp if first_timestamp is None else first_timestamp
        relative_wait_start = wait_start_timestamp - first_timestamp
        if relative_wait_start < 0:
            raise _invalid("JFR events are not in non-decreasing time order")
        context = _context(event.values.eventThread, target_pid, observed_tids)
        owner = None
        if event.type == "jdk.JavaMonitorEnter" and event.values.previousOwner is not None:
            owner = _context(event.values.previousOwner, target_pid, observed_tids)
        stack_id = _stack(event, stacks, stack_tokens)
        if event.values.stackTrace is not None:
            stack_truncated = stack_truncated or event.values.stackTrace.truncated
            empty_stack_trace_count += not event.values.stackTrace.frames
        duration = _duration_ns(event.values.duration)
        if duration < duration_threshold_ns:
            raise _invalid("JFR event duration is below the configured threshold")
        # JFR's startTime identifies when blocking began, while the normalized
        # event is a wait_end.  Publishing startTime as the end timestamp made
        # the public temporal model internally false even though JFR supplied
        # the exact duration.  Keep the profile-relative epoch private, and
        # place the public event at the observed end with an explicit signed
        # 64-bit bound matching the Runtime Lock importer.
        relative_timestamp = _checked_wait_end_timestamp(
            relative_wait_start,
            duration,
        )
        if event.type == "jdk.JavaMonitorEnter":
            lock_kind = "mutex"
            outcome = "acquired"
        elif event.type == "jdk.JavaMonitorWait":
            lock_kind = "condition"
            outcome = (
                "timed_out"
                if event.values.timedOut
                else ("notified" if event.values.notifier is not None else "unknown")
            )
        else:
            lock_kind = "park"
            outcome = "unknown"
        address = event.values.address
        source_lock_id = (
            None
            if address == 0
            else source_tokens.setdefault((address, lock_kind), f"jfr-lock-{len(source_tokens)}")
        )
        record: dict[str, Any] = {
            "schema_version": "1.1",
            "record_type": "runtime_lock_event",
            "source_event_id": f"jfr-event-{source_index + 1}",
            "event_kind": "wait_end",
            "timestamp_ns": relative_timestamp,
            "execution_context": context,
            "source_lock_id": source_lock_id,
            "lock_kind": lock_kind,
            "source_stack_id": stack_id,
            "wait_begin_source_event_id": None,
            "duration_ns": duration,
            "outcome": outcome,
            "owner_execution_context": owner,
        }
        projected.append(record)
    if reader.identity is None:
        raise _invalid("JFR JSON stream did not reach a complete footer")
    projected.sort(
        key=lambda record: (cast(int, record["timestamp_ns"]), cast(str, record["source_event_id"]))
    )
    header = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_header",
        "runtime": "java",
        "runtime_version": execution_binding.runtime_version,
        "adapter_id": "java_jfr",
        "adapter_version": execution_binding.adapter_version,
        "backend_id": "jfr",
        "backend_version": jfr_tool.version,
        "target": {
            "target_pid": target_pid,
            "target_uid": target_uid,
            "target_start_time_ticks": target_start_time_ticks,
            "observed_target_tids": sorted(observed_tids),
            "target_kind": "host",
        },
        "clock": {
            "clock": "profile_relative",
            "unit": "nanoseconds",
            "epoch_correlation_available": False,
        },
        "measurement_semantics": "thresholded",
        "visible_lock_kinds": ["condition", "mutex", "park"],
        # JFR emits only waits that cross the configured threshold.  It never
        # observes uncontended monitor acquisition, so exposing "partial"
        # here would overstate the visible fast-path surface.
        "fast_path_visibility": "none",
        "owner_is_source_observed": True,
        "hold_time_is_source_observed": False,
        "duration_threshold_ns": duration_threshold_ns,
        "declared_event_count": len(projected),
        # DataLoss.amount is bytes, not an event count.  Do not invent an
        # event count; declared_truncated plus the explicit byte limitation
        # carries the loss honestly.
        "declared_lost_event_count": 0,
        # The common NDJSON contract forbids a truncated marker without at
        # least one retained event. DataLoss-only evidence is instead marked
        # partial below with its exact lost-byte limitation.
        "declared_truncated": bool(
            projected and (lost_bytes or stack_truncated or empty_stack_trace_count)
        ),
    }
    normalized = cast(
        BinaryIO,
        SpooledTemporaryFile(max_size=1_048_576, mode="w+b"),  # noqa: SIM115
    )
    try:
        _write(normalized, header)
        for stack in stacks:
            _write(normalized, stack)
        for record in projected:
            _write(normalized, record)
        normalized_bytes = normalized.tell()
        if normalized_bytes > _MAX_NORMALIZED_SOURCE_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "java_jfr_conversion",
                "Normalized JFR evidence exceeds 64 MiB",
            )
        normalized.seek(0)
        normalized_sha256 = _hash_stream(normalized)
        normalized.seek(0)
        imported = import_runtime_lock_ndjson(normalized, created_at=created_at)
    finally:
        normalized.close()
    evidence = _bind_raw_source(
        imported,
        raw_sha256=reader.identity.source_sha256,
        raw_bytes=reader.identity.source_bytes,
        data_loss_bytes=lost_bytes,
        empty_stack_trace_count=empty_stack_trace_count,
        execution_binding=execution_binding,
        jfr_tool=jfr_tool,
    )
    return JavaJfrConversionReceipt(
        evidence=evidence,
        raw_source_sha256=reader.identity.source_sha256,
        raw_source_bytes=reader.identity.source_bytes,
        normalized_source_sha256=normalized_sha256,
        normalized_source_bytes=normalized_bytes,
    )


def verify_java_jfr_replay(
    stream: BinaryIO,
    *,
    expected: JavaJfrConversionReceipt,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    created_at: str,
) -> JavaJfrConversionReceipt | None:
    """Replay conversion and return the complete receipt only on exact identity.

    Evidence equality alone does not bind the private JFR JSON to the exact
    normalized NDJSON byte stream.  The caller persists replay proof only from
    the second receipt, after raw and normalized byte counts/hashes have all
    matched the first conversion.
    """

    replay = convert_java_jfr_json(
        stream,
        execution_binding=execution_binding,
        target_pid=target_pid,
        target_uid=target_uid,
        target_start_time_ticks=target_start_time_ticks,
        created_at=created_at,
    )
    if (
        serialize_json(replay.evidence) != serialize_json(expected.evidence)
        or replay.raw_source_sha256 != expected.raw_source_sha256
        or replay.raw_source_bytes != expected.raw_source_bytes
        or replay.normalized_source_sha256 != expected.normalized_source_sha256
        or replay.normalized_source_bytes != expected.normalized_source_bytes
    ):
        return None
    return replay


def _context(thread: JfrThread, pid: int, observed_tids: set[int]) -> dict[str, Any]:
    if thread.virtual:
        return {
            "kind": "java_virtual_thread",
            "target_pid": pid,
            "runtime_context_id": f"java-thread-{thread.javaThreadId}",
        }
    observed_tids.add(thread.osThreadId)
    return {
        "kind": "java_platform_thread",
        "target_pid": pid,
        "target_tid": thread.osThreadId,
        "runtime_context_id": f"java-thread-{thread.javaThreadId}",
    }


def _validate_thread_metadata_for_jdk(event: JfrLockEvent, jdk_major: int) -> None:
    if jdk_major == 17:
        return
    for thread in (
        event.values.eventThread,
        event.values.previousOwner,
        event.values.notifier,
    ):
        if thread is not None and "virtual" not in thread.model_fields_set:
            raise _invalid("JDK 21/25 JFR thread metadata omitted the virtual-thread marker")


def _stack(event: JfrLockEvent, stacks: list[dict[str, Any]], tokens: dict[str, str]) -> str | None:
    trace = event.values.stackTrace
    if trace is None or not trace.frames:
        return None
    frames: list[dict[str, Any]] = []
    for frame in trace.frames:
        owner_type = frame.method.type
        symbol = f"{owner_type.name.replace('/', '.')}.{frame.method.name}"
        module = owner_type.package.module if owner_type.package is not None else None
        module_name = module.name if module is not None else None
        frames.append(
            {
                "symbol": symbol,
                "module": module_name
                if isinstance(module_name, str) and module_name
                else "unnamed-java-module",
                "source_file": None,
                "source_line": None,
                "is_runtime": symbol.startswith(("java.", "jdk.")),
                "is_unknown": False,
            }
        )
    canonical = json.dumps(frames, sort_keys=True, separators=(",", ":"))
    token = tokens.get(canonical)
    if token is None:
        token = f"jfr-stack-{len(tokens) + 1}"
        tokens[canonical] = token
        stacks.append(
            {
                "schema_version": "1.1",
                "record_type": "runtime_lock_stack",
                "source_stack_id": token,
                "frames": frames,
            }
        )
    return token


def _timestamp_ns(value: str) -> int:
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise _invalid("JFR timestamp is malformed")
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    try:
        parsed = datetime.fromisoformat(f"{match.group(1)}{zone}")
    except ValueError:
        raise _invalid("JFR timestamp is malformed") from None
    if parsed.tzinfo is None:
        raise _invalid("JFR timestamp lacks an offset")
    fraction = (match.group(2) or "").ljust(9, "0")
    return int(parsed.timestamp()) * 1_000_000_000 + int(fraction or "0")


def _duration_ns(value: str) -> int:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise _invalid("JFR duration is malformed")
    fraction = (match.group(2) or "").ljust(9, "0")
    seconds = int(match.group(1))
    fraction_ns = int(fraction or "0")
    if seconds > _MAX_TIME_NS // 1_000_000_000:
        raise _invalid("JFR duration exceeds the fixed nanosecond bound")
    duration_ns = seconds * 1_000_000_000 + fraction_ns
    if duration_ns > _MAX_TIME_NS:
        raise _invalid("JFR duration exceeds the fixed nanosecond bound")
    return duration_ns


def _checked_wait_end_timestamp(relative_start_ns: int, duration_ns: int) -> int:
    if relative_start_ns < 0 or relative_start_ns > _MAX_TIME_NS:
        raise _invalid("JFR relative timestamp exceeds the fixed nanosecond bound")
    if duration_ns < 0 or duration_ns > _MAX_TIME_NS - relative_start_ns:
        raise _invalid("JFR wait end timestamp exceeds the fixed nanosecond bound")
    return relative_start_ns + duration_ns


def _write(stream: BinaryIO, record: object) -> None:
    stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")


def _hash_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        digest.update(chunk)
    return digest.hexdigest()


def _bind_raw_source(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    raw_sha256: str,
    raw_bytes: int,
    data_loss_bytes: int,
    empty_stack_trace_count: int,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    jfr_tool: RuntimeLockAdapterToolBinding,
) -> RuntimeLockEvidenceArtifact:
    source0 = evidence.source.model_copy(
        update={
            "source_format": "jfr_json_v1",
            "converter_version": JAVA_JFR_CONVERTER_VERSION,
            "runtime": "java",
            "adapter_id": "java_jfr",
            "adapter_version": execution_binding.adapter_version,
            "backend_id": "jfr",
            "backend_version": execution_binding.runtime_version,
            "source_sha256": raw_sha256,
            "source_bytes": raw_bytes,
            "target_scope": "bound_pid",
            "tool": RuntimeToolIdentity(
                name="jfr",
                path="jfr",
                version=jfr_tool.version,
                binary_sha256=jfr_tool.binary_sha256,
                status="available",
            ),
            "adapter_execution_identity_sha256": (execution_binding.execution_identity_sha256),
            "configuration_sha256": execution_binding.configuration_sha256,
            "metadata_sha256": execution_binding.metadata_sha256,
            "conversion_fingerprint": "0" * 64,
        }
    )
    source = source0.model_copy(
        update={"conversion_fingerprint": compute_runtime_source_conversion_fingerprint(source0)}
    )
    quality = evidence.quality
    if data_loss_bytes:
        loss_limitation = f"JFR reported {data_loss_bytes} lost source bytes"
        loss_limitation += "; the lost event count is unavailable"
        quality = quality.model_copy(
            update={
                "limitations": tuple(
                    sorted(
                        {
                            *quality.limitations,
                            loss_limitation,
                        }
                    )
                )
            }
        )
    if empty_stack_trace_count:
        empty_stack_limitation = (
            f"JFR reported {empty_stack_trace_count} lock event stack trace(s) with an empty "
            "frame list; call-path attribution is unavailable for those events"
        )
        quality = quality.model_copy(
            update={
                "status": "partial",
                "limitations": tuple(
                    sorted(
                        {
                            *quality.limitations,
                            empty_stack_limitation,
                        }
                    )
                ),
            }
        )
    current = evidence.model_copy(
        update={
            "source": source,
            "quality": quality,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
        }
    )
    current = current.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(current)}
    )
    for _ in range(8):
        size = len(serialize_json(current))
        if size == current.content_bytes:
            break
        current = current.model_copy(update={"content_bytes": size})
    return RuntimeLockEvidenceArtifact.model_validate(
        {
            **current.model_dump(mode="json", exclude_unset=True),
            "content_sha256": compute_runtime_lock_evidence_content_sha256(current),
        }
    )
