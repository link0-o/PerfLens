from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Literal

import pytest

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.runtime_lock_evidence import (
    runtime_lock_evidence_invariant_failures,
)
from perflens.application.verify_runtime_locks import verify_runtime_lock_analysis_artifact
from perflens.contracts.runtime_locks import (
    RuntimeLockResourceLimits,
    RuntimeReleaseEvent,
    RuntimeWaitEndEvent,
    derive_runtime_lock_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.native_pthread_converter import (
    NATIVE_PTHREAD_CONVERTER_VERSION,
    NativePthreadProbeConverter,
    convert_native_pthread_probe,
    replay_native_pthread_probe,
)

_CREATED_AT = "2026-08-30T00:00:00+00:00"


def _fixture(fixture_root: Path, name: str = "native-pthread-exact.ndjson") -> bytes:
    return (fixture_root / "runtime_locks" / name).read_bytes()


def _records(raw: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in raw.splitlines()]


def _stream(records: list[dict[str, Any]]) -> io.BytesIO:
    return io.BytesIO(
        b"".join(
            json.dumps(record, separators=(",", ":"), allow_nan=True).encode() + b"\n"
            for record in records
        )
    )


def _convert(raw: bytes, **kwargs: Any):
    return convert_native_pthread_probe(
        io.BytesIO(raw),
        created_at=_CREATED_AT,
        **kwargs,
    )


def _convert_records(records: list[dict[str, Any]], **kwargs: Any):
    return convert_native_pthread_probe(
        _stream(records),
        created_at=_CREATED_AT,
        **kwargs,
    )


def test_exact_native_probe_conversion_is_private_content_bound_and_replayable(
    fixture_root: Path,
) -> None:
    raw = _fixture(fixture_root)
    receipt = _convert(raw)
    evidence = receipt.evidence

    assert evidence.schema_version == "1.1"
    assert evidence.source.source_format == "native_interposer_ndjson_v1"
    assert evidence.source.converter_version == NATIVE_PTHREAD_CONVERTER_VERSION
    assert evidence.source.measurement_semantics == "exact"
    assert evidence.source.target_scope == "bound_pid"
    assert evidence.source.owner_is_source_observed is False
    assert evidence.source.hold_time_is_source_observed is True
    assert evidence.quality.status == "complete"
    assert evidence.quality.emitted_event_count == 10
    assert evidence.quality.exact_event_count == 10
    assert evidence.target.target_pid == 4242
    assert evidence.target.observed_target_tids == (4242, 4243)
    assert runtime_lock_evidence_invariant_failures(evidence) == ()
    assert receipt.raw_source_bytes == len(raw)
    assert receipt.raw_source_sha256 == evidence.source.source_sha256
    assert receipt.normalized_source_bytes > 0
    assert replay_native_pthread_probe(evidence, io.BytesIO(raw)) is True

    public = evidence.model_dump_json()
    for private_value in (
        "aaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbb",
        "cccccccccccccccc",
        '"e1"',
        '"s1"',
        "/private/build",
        "/home/alice/project",
    ):
        assert private_value not in public
    assert evidence.stacks[0].frames[0].module == "libworker.so"
    assert evidence.stacks[0].frames[0].source_file == "worker.cc"
    assert evidence.events[0].lock_id == derive_runtime_lock_id(
        evidence.runtime_lock_evidence_id,
        0,
    )


def test_native_analysis_preserves_recursive_lifo_wait_hold_and_condition_semantics(
    fixture_root: Path,
) -> None:
    evidence = _convert(_fixture(fixture_root)).evidence
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)

    assert analysis.measurement_semantics == "exact"
    assert analysis.total_exact_wait_count == 2
    assert analysis.total_exact_wait_ns == 80
    assert analysis.total_exact_hold_count == 3
    assert analysis.total_exact_hold_ns == 90
    assert analysis.total_owner_observed_count == 0
    assert verification.verification_status == "partial"
    statuses = {check.name: check.status for check in verification.checks}
    assert statuses["source_identity"] == "skipped"
    assert statuses["source_conversion_replay"] == "skipped"
    assert all(
        status == "passed"
        for name, status in statuses.items()
        if name not in {"source_identity", "source_conversion_replay"}
    )
    releases = [event for event in evidence.events if isinstance(event, RuntimeReleaseEvent)]
    assert [event.hold_duration_ns for event in releases] == [20, 50, 20]
    waits = [event for event in evidence.events if isinstance(event, RuntimeWaitEndEvent)]
    assert [(event.lock_kind, event.outcome) for event in waits] == [
        ("recursive_mutex", "acquired"),
        ("condition", "notified"),
    ]
    condition_events = [event for event in evidence.events if event.lock_kind == "condition"]
    assert all(not isinstance(event, RuntimeReleaseEvent) for event in condition_events)


def test_native_private_source_replay_verifies_complete_conversion(fixture_root: Path) -> None:
    raw = _fixture(fixture_root)
    evidence = _convert(raw).evidence
    analysis = build_runtime_lock_analysis(evidence)

    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        private_source_stream=io.BytesIO(raw),
    )

    statuses = {check.name: check.status for check in verification.checks}
    assert verification.verification_status == "verified"
    assert statuses["source_identity"] == "passed"
    assert statuses["source_conversion_replay"] == "passed"


def test_thresholded_loss_and_truncation_are_partial_without_fabricated_hold(
    fixture_root: Path,
) -> None:
    raw = _fixture(fixture_root, "native-pthread-thresholded-partial.ndjson")
    evidence = _convert(raw).evidence

    assert evidence.source.measurement_semantics == "thresholded"
    assert evidence.source.duration_threshold_ns == 1_000
    assert evidence.source.fast_path_visibility == "partial"
    assert evidence.source.hold_time_is_source_observed is False
    assert evidence.quality.status == "partial"
    assert evidence.quality.lost_event_count == 2
    assert evidence.quality.thresholded_event_count == 4
    assert evidence.quality.limitations == (
        "the source reported lost runtime events",
        "the source declared truncated runtime evidence",
    )
    wait = evidence.events[1]
    assert isinstance(wait, RuntimeWaitEndEvent)
    assert wait.duration_ns == 1_100
    release = evidence.events[-1]
    assert isinstance(release, RuntimeReleaseEvent)
    assert release.acquire_event_id is None
    assert release.hold_duration_ns is None
    assert "exact_hold_time" in evidence.forbidden_conclusions


def test_no_stack_native_evidence_remains_analyzable(fixture_root: Path) -> None:
    raw = _fixture(fixture_root, "native-pthread-thresholded-partial.ndjson")
    evidence = _convert(raw).evidence
    assert evidence.stacks == ()
    assert all(event.stack_id is None for event in evidence.events)

    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)

    assert analysis.total_thresholded_wait_count == 1
    assert analysis.total_thresholded_wait_ns == 1_100
    assert analysis.call_path_aggregates[0].stack_id is None
    statuses = {check.name: check.status for check in verification.checks}
    assert statuses["aggregate_projection_conservation"] == "passed"


def test_raw_byte_identity_is_bound_and_different_formatting_cannot_replay(
    fixture_root: Path,
) -> None:
    raw = _fixture(fixture_root)
    expected = _convert(raw).evidence
    lines = raw.splitlines(keepends=True)
    lines[0] = lines[0].rstrip(b"\n") + b" \n"
    reformatted = b"".join(lines)
    changed = _convert(reformatted).evidence

    assert changed.runtime_lock_evidence_id != expected.runtime_lock_evidence_id
    assert changed.source.source_sha256 != expected.source.source_sha256
    assert replay_native_pthread_probe(expected, io.BytesIO(reformatted)) is False


def test_converter_object_matches_convenience_function(fixture_root: Path) -> None:
    raw = _fixture(fixture_root)
    expected = _convert(raw)
    actual = NativePthreadProbeConverter(created_at=_CREATED_AT).convert(io.BytesIO(raw))
    assert actual == expected


@pytest.mark.parametrize(
    "record_index, updates, message",
    [
        (
            0,
            {"unexpected": True},
            "header failed strict validation",
        ),
        (
            2,
            {"unexpected": True},
            "event failed strict validation",
        ),
        (
            3,
            {"sequence": 1, "source_event_id": "e1"},
            "sequence is not contiguous",
        ),
        (
            3,
            {"timestamp_ns": 99},
            "timestamps are out of order",
        ),
        (
            2,
            {"pid": 9999},
            "escaped the bound target",
        ),
        (
            2,
            {"stack_id": "s999"},
            "unknown stack",
        ),
        (
            3,
            {"lock_kind": "condition"},
            "changed lock kind",
        ),
        (
            3,
            {"duration_ns": 49},
            "duration contradicts",
        ),
        (
            3,
            {"result": "released"},
            "event failed strict validation",
        ),
        (
            6,
            {"related_source_event_id": "e3"},
            "violates target-local LIFO",
        ),
        (
            -1,
            {"declared_event_count": 9},
            "event count differs",
        ),
        (
            -1,
            {"sequence": 10},
            "footer sequence is not contiguous",
        ),
    ],
)
def test_strict_probe_rejections(
    fixture_root: Path,
    record_index: int,
    updates: dict[str, object],
    message: str,
) -> None:
    records = _records(_fixture(fixture_root))
    records[record_index].update(updates)
    with pytest.raises(PerfLensError, match=message) as caught:
        _convert_records(records)
    assert caught.value.code == ErrorCode.INVALID_INPUT
    assert caught.value.stage == "native_pthread_conversion"


def test_thresholded_wait_below_declared_threshold_is_rejected(fixture_root: Path) -> None:
    records = _records(_fixture(fixture_root, "native-pthread-thresholded-partial.ndjson"))
    records[2]["timestamp_ns"] = 1_099
    records[2]["duration_ns"] = 999
    records[3]["timestamp_ns"] = 1_099
    records[4]["timestamp_ns"] = 1_299
    records[4]["hold_duration_ns"] = None

    with pytest.raises(PerfLensError, match="below its declared threshold"):
        _convert_records(records)


def test_header_tid_subset_is_extended_and_concurrent_timestamps_are_sorted() -> None:
    header = {
        "schema_version": "1.0",
        "record_type": "probe_header",
        "protocol": "native_pthread_probe",
        "protocol_version": "1.0",
        "runtime": "c_cpp",
        "runtime_version": "glibc-2.41",
        "adapter_id": "native-pthread",
        "adapter_version": "1",
        "backend_id": "ld-preload",
        "backend_version": "1",
        "pid": 4242,
        "uid": 1000,
        "target_start_time_ticks": 77,
        "observed_target_tids": [4242],
        "target_kind": "host",
        "container_reference": None,
        "semantics": "exact",
        "duration_threshold_ns": None,
        "max_events": 4,
        "visible_lock_kinds": ["mutex"],
        "fast_path_visibility": "complete",
        "owner_is_source_observed": False,
        "hold_time_is_source_observed": True,
    }

    def event(
        sequence: int,
        *,
        kind: str,
        timestamp: int,
        tid: int,
        lock_key: str,
        related: str | None,
        hold: int | None,
        result: str,
    ) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "record_type": "probe_event",
            "sequence": sequence,
            "source_event_id": f"e{sequence}",
            "event_kind": kind,
            "timestamp_ns": timestamp,
            "pid": 4242,
            "tid": tid,
            "raw_lock_token": lock_key,
            "lock_kind": "mutex",
            "related_source_event_id": related,
            "duration_ns": None,
            "hold_duration_ns": hold,
            "result": result,
            "stack_id": None,
        }

    records = [
        header,
        event(
            1,
            kind="acquire",
            timestamp=200,
            tid=4243,
            lock_key="aaaaaaaaaaaaaaaa",
            related=None,
            hold=None,
            result="acquired",
        ),
        event(
            2,
            kind="acquire",
            timestamp=100,
            tid=4242,
            lock_key="bbbbbbbbbbbbbbbb",
            related=None,
            hold=None,
            result="acquired",
        ),
        event(
            3,
            kind="release",
            timestamp=150,
            tid=4242,
            lock_key="bbbbbbbbbbbbbbbb",
            related="e2",
            hold=50,
            result="released",
        ),
        event(
            4,
            kind="release",
            timestamp=250,
            tid=4243,
            lock_key="aaaaaaaaaaaaaaaa",
            related="e1",
            hold=50,
            result="released",
        ),
        {
            "schema_version": "1.0",
            "record_type": "probe_footer",
            "protocol": "native_pthread_probe",
            "pid": 4242,
            "sequence": 5,
            "declared_event_count": 4,
            "lost_event_count": 0,
            "truncated": False,
        },
    ]
    evidence = _convert_records(records).evidence

    assert evidence.target.observed_target_tids == (4242, 4243)
    assert [event.timestamp_ns for event in evidence.events] == [100, 150, 200, 250]
    assert evidence.quality.out_of_order_record_count == 0
    assert runtime_lock_evidence_invariant_failures(evidence) == ()


def test_chunked_event_sort_is_bounded_and_deterministic_across_thread_interleaving() -> None:
    pair_count = 600
    header: dict[str, object] = {
        "schema_version": "1.0",
        "record_type": "probe_header",
        "protocol": "native_pthread_probe",
        "protocol_version": "1.0",
        "runtime": "c_cpp",
        "runtime_version": "glibc-2.41",
        "adapter_id": "native-pthread",
        "adapter_version": "1",
        "backend_id": "ld-preload",
        "backend_version": "1",
        "pid": 4242,
        "uid": 1000,
        "target_start_time_ticks": 77,
        "observed_target_tids": [4242],
        "target_kind": "host",
        "container_reference": None,
        "semantics": "exact",
        "duration_threshold_ns": None,
        "max_events": pair_count * 2,
        "visible_lock_kinds": ["mutex"],
        "fast_path_visibility": "complete",
        "owner_is_source_observed": False,
        "hold_time_is_source_observed": True,
    }
    records: list[dict[str, object]] = [header]
    for index in range(pair_count):
        tid = 4242 if index % 2 == 0 else 4243
        timestamp = index * 10 if tid == 4242 else 1_000_000 + index * 10
        acquire_sequence = index * 2 + 1
        release_sequence = acquire_sequence + 1
        lock_key = f"{index + 1:016x}"
        common: dict[str, object] = {
            "schema_version": "1.0",
            "record_type": "probe_event",
            "pid": 4242,
            "tid": tid,
            "raw_lock_token": lock_key,
            "lock_kind": "mutex",
            "duration_ns": None,
            "stack_id": None,
        }
        records.extend(
            [
                {
                    **common,
                    "sequence": acquire_sequence,
                    "source_event_id": f"e{acquire_sequence}",
                    "event_kind": "acquire",
                    "timestamp_ns": timestamp,
                    "related_source_event_id": None,
                    "hold_duration_ns": None,
                    "result": "acquired",
                },
                {
                    **common,
                    "sequence": release_sequence,
                    "source_event_id": f"e{release_sequence}",
                    "event_kind": "release",
                    "timestamp_ns": timestamp + 5,
                    "related_source_event_id": f"e{acquire_sequence}",
                    "hold_duration_ns": 5,
                    "result": "released",
                },
            ]
        )
    records.append(
        {
            "schema_version": "1.0",
            "record_type": "probe_footer",
            "protocol": "native_pthread_probe",
            "pid": 4242,
            "sequence": pair_count * 2 + 1,
            "declared_event_count": pair_count * 2,
            "lost_event_count": 0,
            "truncated": False,
        }
    )

    first = _convert_records(records).evidence
    second = _convert_records(records).evidence

    assert first == second
    assert len(first.events) == pair_count * 2
    ordering = [(event.timestamp_ns, event.event_index) for event in first.events]
    assert ordering == sorted(ordering)
    assert first.target.observed_target_tids == (4242, 4243)
    assert runtime_lock_evidence_invariant_failures(first) == ()


def test_hold_visibility_cannot_be_fabricated(fixture_root: Path) -> None:
    records = _records(_fixture(fixture_root, "native-pthread-thresholded-partial.ndjson"))
    records[4]["hold_duration_ns"] = 200
    with pytest.raises(PerfLensError, match="fabricated an unavailable hold duration"):
        _convert_records(records)


@pytest.mark.parametrize(
    "mode, message",
    [
        ("missing", "missing its completion footer"),
        ("after", "records after its footer"),
    ],
)
def test_footer_is_mandatory_and_terminal(
    fixture_root: Path,
    mode: Literal["missing", "after"],
    message: str,
) -> None:
    lines = _fixture(fixture_root).splitlines(keepends=True)
    transformed = lines[:-1] if mode == "missing" else [*lines, lines[1]]
    with pytest.raises(PerfLensError, match=message):
        _convert(b"".join(transformed))


def test_unknown_record_type_duplicate_key_nonfinite_and_missing_newline_are_rejected(
    fixture_root: Path,
) -> None:
    raw = _fixture(fixture_root)
    records = _records(raw)
    records.insert(-1, {"schema_version": "1.0", "record_type": "probe_unknown"})
    with pytest.raises(PerfLensError, match="unknown record_type"):
        _convert_records(records)

    duplicate_header = raw.replace(
        b'{"schema_version":"1.0"',
        b'{"schema_version":"1.0","schema_version":"1.0"',
        1,
    )
    with pytest.raises(PerfLensError, match="not strict JSON"):
        _convert(duplicate_header)

    nonfinite = raw.replace(b'"timestamp_ns":100', b'"timestamp_ns":NaN', 1)
    with pytest.raises(PerfLensError, match="not strict JSON"):
        _convert(nonfinite)

    with pytest.raises(PerfLensError, match="line boundary"):
        _convert(raw.rstrip(b"\n"))


def test_resource_limits_bound_lines_locks_and_exact_events(fixture_root: Path) -> None:
    raw = _fixture(fixture_root)
    with pytest.raises(PerfLensError) as oversized:
        _convert(
            raw,
            limits=RuntimeLockResourceLimits(max_line_bytes=256),
        )
    assert oversized.value.code == ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as locks:
        _convert(
            raw,
            limits=RuntimeLockResourceLimits(max_unique_locks=1),
        )
    assert locks.value.code == ErrorCode.RESOURCE_LIMIT_EXCEEDED

    records = _records(raw)
    records[0]["max_events"] = 20_001
    with pytest.raises(PerfLensError, match="header failed strict validation"):
        _convert_records(records)


def test_invalid_stream_and_created_at_fail_without_leaking_reader_error() -> None:
    class BrokenStream:
        def readline(self, _limit: int) -> bytes:
            raise OSError("credential=/private/token")

    with pytest.raises(PerfLensError, match="could not be read") as broken:
        convert_native_pthread_probe(BrokenStream(), created_at=_CREATED_AT)  # type: ignore[arg-type]
    assert "credential" not in str(broken.value)

    with pytest.raises(PerfLensError, match="must include a timezone"):
        NativePthreadProbeConverter(created_at="2026-08-30T00:00:00")


def test_replay_rejects_non_native_evidence(fixture_root: Path) -> None:
    evidence = _convert(_fixture(fixture_root)).evidence
    foreign_source = evidence.source.model_copy(
        update={"source_format": "perflens_runtime_lock_ndjson_v1"}
    )
    foreign = evidence.model_copy(update={"source": foreign_source})
    with pytest.raises(PerfLensError, match="does not originate"):
        replay_native_pthread_probe(foreign, io.BytesIO(_fixture(fixture_root)))
