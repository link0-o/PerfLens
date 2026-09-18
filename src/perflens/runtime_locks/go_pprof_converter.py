"""Strict conversion of bounded ``go tool pprof -raw`` text."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from tempfile import SpooledTemporaryFile
from typing import BinaryIO, Literal, cast

from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
    validate_runtime_lock_evidence_invariants,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_lock_sessions import RuntimeLockAdapterExecutionBinding
from perflens.contracts.runtime_locks import (
    LockKind,
    RuntimeClock,
    RuntimeLockEvidenceArtifact,
    RuntimeLockResourceLimits,
    RuntimeSourceManifest,
    RuntimeToolIdentity,
    derive_runtime_execution_context_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.importer import import_runtime_lock_ndjson

GO_PPROF_CONVERTER_VERSION = "go-pprof-converter-v1"
GoProfileKind = Literal["mutex", "block"]
_SAMPLE = re.compile(r"^\s*([0-9]+)\s+([0-9]+):\s*([0-9]+(?:\s+[0-9]+)*)?\s*$")
_LOCATION = re.compile(r"^\s*([0-9]+):\s+0x[0-9a-fA-F]+\s+M=[0-9]+(?:\s+(.*))?$")
_FRAME = re.compile(r"^(.+?)\s+(.+):([0-9]+):[0-9]+\s+s=[0-9]+$")
_SPOOL_MEMORY_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class GoPprofConversionReceipt:
    evidence: RuntimeLockEvidenceArtifact
    raw_source_sha256: str
    raw_source_bytes: int
    normalized_source_sha256: str
    normalized_source_bytes: int
    profile_kind: GoProfileKind


@dataclass(frozen=True, slots=True)
class _Frame:
    symbol: str
    source_file: str | None
    source_line: int | None


@dataclass(frozen=True, slots=True)
class _Sample:
    observed_count: int
    cumulative_wait_ns: int
    locations: tuple[int, ...]


def convert_go_pprof_raw(
    stream: BinaryIO,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    profile_kind: GoProfileKind,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    mutex_profile_fraction: int | None,
    block_profile_rate_ns: int | None,
    limits: RuntimeLockResourceLimits | None = None,
    created_at: str | None = None,
) -> GoPprofConversionReceipt:
    """Convert one complete raw profile without inventing lock or thread identity."""

    limits = limits or RuntimeLockResourceLimits()
    binding = _validate_binding(execution_binding)
    _validate_profile_rate(profile_kind, mutex_profile_fraction, block_profile_rate_ns)
    created = _created_at(created_at)
    with SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b") as raw_spool:
        raw_io = cast(BinaryIO, raw_spool)
        raw_sha256, raw_source_bytes = _copy_bounded(
            stream,
            raw_io,
            limits.max_source_bytes,
        )
        raw_io.seek(0)
        samples, locations = _parse_raw_stream(raw_io, limits=limits)
    sample_stacks: dict[tuple[int, ...], tuple[str, tuple[_Frame, ...]]] = {}
    for sample in samples:
        if sample.locations not in sample_stacks:
            leaf_first_frames = tuple(
                frame for location in sample.locations for frame in locations[location]
            )
            # Profile.proto orders both Sample.location entries and inlined
            # Location.line entries leaf-first. Publish the repository-wide
            # root/caller -> leaf/callee order.
            frames = tuple(reversed(leaf_first_frames))
            if len(frames) > limits.max_stack_depth:
                raise _limit("Go pprof merged call path exceeds max_stack_depth")
            sample_stacks[sample.locations] = (
                f"go-stack-{len(sample_stacks) + 1}",
                frames,
            )
    visible_kinds = tuple(
        sorted(
            {_classify_lock(profile_kind, sample_stacks[sample.locations][1]) for sample in samples}
        )
    )
    with SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b") as normalized:
        normalized_io = cast(BinaryIO, normalized)
        _write(
            normalized_io,
            {
                "schema_version": "1.1",
                "record_type": "runtime_lock_header",
                "runtime": "go",
                "runtime_version": binding.runtime_version,
                "adapter_id": "go_pprof",
                "adapter_version": binding.adapter_version,
                "backend_id": f"pprof-{profile_kind}",
                "backend_version": binding.runtime_version,
                "target": {
                    "target_pid": target_pid,
                    "target_uid": target_uid,
                    "target_start_time_ticks": target_start_time_ticks,
                    "observed_target_tids": [],
                    "target_kind": "host",
                },
                "clock": {
                    "clock": "profile_relative",
                    "unit": "nanoseconds",
                    "epoch_correlation_available": False,
                },
                "measurement_semantics": "cumulative",
                "visible_lock_kinds": list(visible_kinds or ("unknown",)),
                "fast_path_visibility": "none",
                "owner_is_source_observed": False,
                "hold_time_is_source_observed": False,
                "sampling_fraction": (mutex_profile_fraction if profile_kind == "mutex" else None),
                "block_profile_rate_ns": (
                    block_profile_rate_ns if profile_kind == "block" else None
                ),
                "declared_event_count": len(samples),
                "declared_lost_event_count": 0,
                "declared_truncated": False,
            },
        )
        for stack_id, frames in sample_stacks.values():
            _write(
                normalized_io,
                {
                    "schema_version": "1.1",
                    "record_type": "runtime_lock_stack",
                    "source_stack_id": stack_id,
                    "frames": [_public_frame(frame) for frame in frames],
                },
            )
        for ordinal, sample in enumerate(samples, start=1):
            # pprof samples have no event timestamp. The ordinal is only a
            # canonical profile-relative ordering key, never wall-clock time.
            record = {
                "schema_version": "1.1",
                "record_type": "runtime_lock_event",
                "source_event_id": f"go-sample-{ordinal}",
                "event_kind": "sampled_contention",
                "timestamp_ns": ordinal - 1,
                "execution_context": {
                    "kind": "process_aggregate",
                    "target_pid": target_pid,
                },
                "source_lock_id": None,
                "lock_kind": _classify_lock(profile_kind, sample_stacks[sample.locations][1]),
                "source_stack_id": sample_stacks[sample.locations][0],
                "observed_count": sample.observed_count,
                # The raw text does not prove whether Go already scaled this
                # cumulative weight by the configured sampling rate. Never
                # manufacture an independent contention estimate.
                "estimated_count": None,
                "cumulative_wait_ns": sample.cumulative_wait_ns,
            }
            _write(normalized_io, record)
        normalized_bytes = normalized_io.tell()
        if normalized_bytes > limits.max_source_bytes:
            raise _limit("normalized Go pprof evidence exceeds max_source_bytes")
        normalized_io.seek(0)
        normalized_sha256 = _stream_sha256(normalized_io)
        normalized_io.seek(0)
        imported = import_runtime_lock_ndjson(
            normalized_io,
            limits=limits,
            created_at=created,
        )
    evidence = _rebind_source(
        imported,
        binding=binding,
        profile_kind=profile_kind,
        raw_source_sha256=raw_sha256,
        raw_source_bytes=raw_source_bytes,
        mutex_profile_fraction=mutex_profile_fraction,
        block_profile_rate_ns=block_profile_rate_ns,
    )
    validate_runtime_lock_evidence_invariants(evidence)
    return GoPprofConversionReceipt(
        evidence=evidence,
        raw_source_sha256=raw_sha256,
        raw_source_bytes=raw_source_bytes,
        normalized_source_sha256=normalized_sha256,
        normalized_source_bytes=normalized_bytes,
        profile_kind=profile_kind,
    )


def verify_go_pprof_replay(
    stream: BinaryIO,
    *,
    expected: GoPprofConversionReceipt,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    mutex_profile_fraction: int | None,
    block_profile_rate_ns: int | None,
) -> GoPprofConversionReceipt | None:
    replay = convert_go_pprof_raw(
        stream,
        execution_binding=execution_binding,
        profile_kind=expected.profile_kind,
        target_pid=target_pid,
        target_uid=target_uid,
        target_start_time_ticks=target_start_time_ticks,
        mutex_profile_fraction=mutex_profile_fraction,
        block_profile_rate_ns=block_profile_rate_ns,
        limits=expected.evidence.limits,
        created_at=expected.evidence.created_at,
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


def _parse_raw_stream(
    stream: BinaryIO,
    *,
    limits: RuntimeLockResourceLimits,
) -> tuple[tuple[_Sample, ...], dict[int, tuple[_Frame, ...]]]:
    maximum_lines = min(
        1_000_000,
        limits.max_input_records + limits.max_unique_stacks * (limits.max_stack_depth + 1) + 64,
    )
    samples: list[_Sample] = []
    locations: dict[int, tuple[_Frame, ...]] = {}
    current_id: int | None = None
    current_frames: list[_Frame] = []
    state = "period_type"
    mapping_count = 0
    header_fields: set[str] = set()
    for line in _bounded_lines(stream, limits.max_line_bytes, maximum_lines):
        if state == "period_type":
            if line != "PeriodType: contentions count":
                raise _invalid("Go pprof raw output has an unsupported period contract")
            state = "period"
            continue
        if state == "period":
            if line != "Period: 1":
                raise _invalid("Go pprof raw output has an unsupported period contract")
            state = "header"
            continue
        if state == "header":
            if line == "Samples:":
                state = "sample_types"
                continue
            key = line.partition(":")[0]
            if key not in {"Time", "Duration"} or key in header_fields:
                raise _invalid("Go pprof raw header contains an unsupported field")
            header_fields.add(key)
            continue
        if state == "sample_types":
            if line != "contentions/count delay/nanoseconds":
                raise _invalid("Go pprof raw sample types are unsupported")
            state = "samples"
            continue
        if state == "samples":
            if line == "Locations":
                state = "locations"
                continue
            if not line:
                continue
            match = _SAMPLE.fullmatch(line)
            if match is None:
                raise _invalid("Go pprof raw sample row is malformed")
            observed = _bounded_uint(match.group(1), "Go contention weight")
            wait_ns = _bounded_uint(match.group(2), "Go delay weight")
            location_ids = tuple(
                _bounded_uint(value, "Go location identity")
                for value in (match.group(3) or "").split()
            )
            if (
                observed <= 0
                or wait_ns <= 0
                or not location_ids
                or len(location_ids) > limits.max_stack_depth
            ):
                raise _invalid("Go pprof raw sample has invalid weight or call path")
            if len(samples) >= limits.max_input_records:
                raise _limit("Go pprof raw sample count exceeds max_input_records")
            samples.append(_Sample(observed, wait_ns, location_ids))
            continue
        if state == "mappings":
            if not line:
                continue
            if not re.match(r"^[0-9]+:\s+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+/0x[0-9a-fA-F]+", line):
                raise _invalid("Go pprof mapping row is malformed")
            mapping_count += 1
            continue
        if not line:
            continue
        if line == "Mappings":
            if current_id is not None:
                _store_location(locations, current_id, current_frames, limits)
                current_id = None
            state = "mappings"
            continue
        location_match = _LOCATION.fullmatch(line)
        if location_match is not None:
            if current_id is not None:
                _store_location(locations, current_id, current_frames, limits)
            current_id = _bounded_uint(location_match.group(1), "Go location identity")
            current_frames = []
            tail = location_match.group(2)
            if tail:
                current_frames.append(_parse_frame(tail))
            continue
        if current_id is None:
            raise _invalid("Go pprof frame precedes its location")
        current_frames.append(_parse_frame(line.strip()))
    if state != "mappings" or mapping_count == 0:
        raise _invalid("Go pprof raw output is missing a required section")
    if not samples or not locations:
        raise _invalid("Go pprof raw output contains no usable samples")
    referenced = {location for sample in samples for location in sample.locations}
    if not referenced.issubset(locations):
        raise _invalid("Go pprof samples reference an unknown location")
    return tuple(samples), locations


def _parse_frame(value: str) -> _Frame:
    match = _FRAME.fullmatch(value)
    if match is None:
        raise _invalid("Go pprof location frame is malformed")
    symbol = match.group(1).strip()
    path = match.group(2).replace("\\", "/")
    if not symbol or len(symbol.encode("utf-8")) > 4096:
        raise _invalid("Go pprof symbol is invalid")
    leaf = PurePosixPath(path).name
    source_file = leaf if leaf not in {"", ".", ".."} else None
    source_line_value = _bounded_uint(match.group(3), "Go source line", allow_zero=True)
    if symbol in {"?", "??", "<unknown>"}:
        symbol = "[unknown]"
        source_file = None
        source_line_value = 0
    return _Frame(
        symbol=symbol,
        source_file=source_file,
        source_line=(source_line_value or None),
    )


def _store_location(
    locations: dict[int, tuple[_Frame, ...]],
    location_id: int,
    frames: list[_Frame],
    limits: RuntimeLockResourceLimits,
) -> None:
    if location_id <= 0 or location_id in locations or not frames:
        raise _invalid("Go pprof location identity is invalid or duplicated")
    if len(locations) >= limits.max_unique_stacks or len(frames) > limits.max_stack_depth:
        raise _limit("Go pprof call paths exceed their configured bound")
    locations[location_id] = tuple(frames)


def _classify_lock(profile_kind: GoProfileKind, frames: tuple[_Frame, ...]) -> LockKind:
    symbols = tuple(frame.symbol for frame in frames)
    if any(symbol == "runtime._LostContendedRuntimeLock" for symbol in symbols):
        return "runtime_internal"
    if any(re.match(r"^sync\.\(\*WaitGroup\)\.", symbol) for symbol in symbols):
        return "wait_group"
    if any(re.match(r"^sync\.\(\*Cond\)\.", symbol) for symbol in symbols):
        return "condition"
    if any(re.match(r"^runtime\.(?:chan|selectgo)", symbol) for symbol in symbols):
        return "channel"
    if any(re.match(r"^sync\.\(\*(?:Mutex|RWMutex)\)\.", symbol) for symbol in symbols):
        return "mutex"
    if profile_kind == "mutex":
        return "mutex"
    return "unknown"


def _public_frame(frame: _Frame) -> dict[str, object]:
    is_runtime = frame.symbol.startswith(("runtime.", "sync."))
    return {
        "symbol": frame.symbol,
        "module": "go-runtime" if is_runtime else "go-workload",
        "source_file": frame.source_file,
        "source_line": frame.source_line,
        "is_runtime": is_runtime,
        "is_unknown": frame.symbol == "[unknown]",
    }


def _rebind_source(
    imported: RuntimeLockEvidenceArtifact,
    *,
    binding: RuntimeLockAdapterExecutionBinding,
    profile_kind: GoProfileKind,
    raw_source_sha256: str,
    raw_source_bytes: int,
    mutex_profile_fraction: int | None,
    block_profile_rate_ns: int | None,
) -> RuntimeLockEvidenceArtifact:
    seed = canonical_runtime_lock_json_sha256(
        {
            "domain": "perflens.go-pprof-evidence-id.v1",
            "raw_source_sha256": raw_source_sha256,
            "raw_source_bytes": raw_source_bytes,
            "created_at": imported.created_at,
            "profile_kind": profile_kind,
            "execution_identity_sha256": binding.execution_identity_sha256,
            "limits": imported.limits,
        }
    )
    evidence_id = f"runtime-lock-evidence-{seed[:24]}"
    context_ids = {
        context.context_id: derive_runtime_execution_context_id(evidence_id, ordinal)
        for ordinal, context in enumerate(imported.execution_contexts)
    }
    stack_ids = {
        stack.stack_id: _opaque_id(evidence_id, "stack", ordinal)
        for ordinal, stack in enumerate(imported.stacks)
    }
    event_ids = {
        event.event_id: _opaque_id(evidence_id, "event", ordinal)
        for ordinal, event in enumerate(imported.events)
    }
    contexts = tuple(
        context.model_copy(update={"context_id": context_ids[context.context_id]})
        for context in imported.execution_contexts
    )
    stacks = tuple(
        stack.model_copy(update={"stack_id": stack_ids[stack.stack_id]})
        for stack in imported.stacks
    )
    events: list[dict[str, object]] = []
    for event in imported.events:
        data = event.model_dump(mode="json", exclude_none=True)
        data["event_id"] = event_ids[event.event_id]
        if event.execution_context_id is not None:
            data["execution_context_id"] = context_ids[event.execution_context_id]
        if event.stack_id is not None:
            data["stack_id"] = stack_ids[event.stack_id]
        events.append(data)
    pprof_tool = next(tool for tool in binding.tools if tool.name == "pprof")
    source_provisional = RuntimeSourceManifest(
        schema_version="1.1",
        runtime="go",
        adapter_id="go_pprof",
        adapter_version=binding.adapter_version,
        backend_id=f"pprof-{profile_kind}",
        backend_version=binding.runtime_version,
        runtime_version=binding.runtime_version,
        measurement_semantics="cumulative",
        source_format="pprof_text_v1",
        converter_version=GO_PPROF_CONVERTER_VERSION,
        source_sha256=raw_source_sha256,
        source_bytes=raw_source_bytes,
        conversion_fingerprint="0" * 64,
        clock=RuntimeClock(clock="profile_relative"),
        sampling_fraction=(mutex_profile_fraction if profile_kind == "mutex" else None),
        block_profile_rate_ns=(block_profile_rate_ns if profile_kind == "block" else None),
        fast_path_visibility="none",
        owner_is_source_observed=False,
        hold_time_is_source_observed=False,
        target_scope="bound_pid",
        tool=RuntimeToolIdentity(
            name="pprof",
            version=pprof_tool.version,
            path="pprof",
            binary_sha256=pprof_tool.binary_sha256,
            status="available",
        ),
        adapter_execution_identity_sha256=binding.execution_identity_sha256,
        configuration_sha256=binding.configuration_sha256,
        metadata_sha256=binding.metadata_sha256,
    )
    source = source_provisional.model_copy(
        update={
            "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                source_provisional
            )
        }
    )
    limitations = tuple(
        dict.fromkeys(
            (
                *imported.quality.limitations,
                "Go pprof is cumulative profile evidence; sample rows are not exact lock events.",
                "Go pprof exposes no exact TID, lock object, owner relationship, or hold time.",
                "Mutex and block profiles remain separate Evidence Artifacts and cannot be mixed.",
                *(
                    (
                        "Go mutex profile stacks generally describe the releasing side of "
                        "contention, not an exact waiter-to-owner relationship.",
                    )
                    if profile_kind == "mutex"
                    else ()
                ),
                "Profile sampling controls are policy declarations and are not independently "
                "attested by the profile payload.",
                *(binding.limitations),
            )
        )
    )
    forbidden = tuple(
        dict.fromkeys(
            (
                *imported.forbidden_conclusions,
                "exact_contention_count",
                "exact_owner_relationship",
                "exact_hold_time",
                "cross_profile_weight_addition",
                "unqualified_runtime_lock_conclusion",
            )
        )
    )
    provisional = RuntimeLockEvidenceArtifact.model_validate(
        {
            **imported.model_dump(mode="json", exclude_unset=True),
            "runtime_lock_evidence_id": evidence_id,
            "source": source.model_dump(mode="json", exclude_none=True),
            "quality": imported.quality.model_copy(
                update={"status": "partial", "limitations": limitations}
            ).model_dump(mode="json"),
            "execution_contexts": [
                value.model_dump(mode="json", exclude_none=True) for value in contexts
            ],
            "stacks": [value.model_dump(mode="json", exclude_none=True) for value in stacks],
            "events": events,
            "forbidden_conclusions": forbidden,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
            "content_bytes": 1,
        }
    )
    fingerprinted = provisional.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(provisional)}
    )
    sized = _stable_size(fingerprinted)
    return RuntimeLockEvidenceArtifact.model_validate(
        {
            **sized.model_dump(mode="json", exclude_unset=True),
            "content_sha256": compute_runtime_lock_evidence_content_sha256(sized),
        }
    )


def _validate_binding(
    binding: RuntimeLockAdapterExecutionBinding,
) -> RuntimeLockAdapterExecutionBinding:
    try:
        binding = RuntimeLockAdapterExecutionBinding.model_validate(binding.model_dump(mode="json"))
    except ValueError:
        raise _invalid("Go pprof execution binding failed deterministic validation") from None
    if (
        binding.adapter_id != "go_pprof"
        or binding.adapter_version != "go-pprof-adapter-v1"
        or binding.backend_id != "pprof"
        or binding.profile != "mutex_and_block"
        or binding.measurement_semantics != "cumulative"
        or len(binding.tools) != 2
        or tuple(tool.name for tool in binding.tools) != ("go", "pprof")
    ):
        raise _invalid("Go pprof converter requires one authorized execution binding")
    return binding


def _validate_profile_rate(
    profile_kind: GoProfileKind,
    mutex_profile_fraction: int | None,
    block_profile_rate_ns: int | None,
) -> None:
    if profile_kind == "mutex":
        valid = mutex_profile_fraction is not None and block_profile_rate_ns is None
    else:
        valid = block_profile_rate_ns is not None and mutex_profile_fraction is None
    if not valid:
        raise _invalid("Go pprof profile kind requires exactly its matching declared rate")


def _copy_bounded(stream: BinaryIO, output: BinaryIO, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(min(64 * 1024, maximum + 1 - total)):
        total += len(chunk)
        if total > maximum:
            raise _limit("Go pprof raw output exceeds max_source_bytes")
        digest.update(chunk)
        output.write(chunk)
    if total == 0:
        raise _invalid("Go pprof raw output is empty")
    return digest.hexdigest(), total


def _bounded_lines(
    stream: BinaryIO,
    maximum_line_bytes: int,
    maximum_lines: int,
) -> Iterator[str]:
    line_count = 0
    while True:
        raw = stream.readline(maximum_line_bytes + 2)
        if not raw:
            return
        line_count += 1
        if line_count > maximum_lines:
            raise _limit("Go pprof raw output exceeds its line bound")
        if not raw.endswith(b"\n"):
            if len(raw) > maximum_line_bytes:
                raise _limit("Go pprof raw output contains an oversized line")
            raise _invalid("Go pprof raw output is incomplete")
        payload = raw[:-1]
        if len(payload) > maximum_line_bytes or payload.endswith(b"\r"):
            raise _limit("Go pprof raw output contains an invalid or oversized line")
        try:
            yield payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid("Go pprof raw output is not UTF-8") from exc


def _bounded_uint(value: str, label: str, *, allow_zero: bool = False) -> int:
    if not value or len(value) > 20 or not value.isascii() or not value.isdecimal():
        raise _invalid(f"{label} is malformed or oversized")
    result = int(value)
    minimum = 0 if allow_zero else 1
    if not minimum <= result <= (1 << 63) - 1:
        raise _invalid(f"{label} is outside its supported range")
    return result


def _write(stream: BinaryIO, value: object) -> None:
    stream.write(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        + b"\n"
    )


def _opaque_id(evidence_id: str, kind: str, ordinal: int) -> str:
    material = f"perflens.runtime-lock.{kind}.v1.1\0{evidence_id}\0{ordinal}"
    return f"runtime-{kind}-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


def _stable_size(evidence: RuntimeLockEvidenceArtifact) -> RuntimeLockEvidenceArtifact:
    current = evidence
    for _ in range(8):
        actual = len(serialize_json(current))
        if actual == current.content_bytes:
            return current
        current = current.model_copy(update={"content_bytes": actual})
    raise _invalid("Go pprof Evidence byte identity did not converge")


def _stream_sha256(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(64 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _created_at(value: str | None) -> str:
    candidate = value or datetime.now(tz=UTC).isoformat()
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        raise _invalid("Go pprof Evidence creation time is invalid") from None
    if parsed.tzinfo is None:
        raise _invalid("Go pprof Evidence creation time lacks a timezone")
    return parsed.isoformat()


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PROFILE_PARSE_FAILED, "go_pprof_conversion", message)


def _limit(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "go_pprof_conversion", message)
