from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import validate_runtime_lock_evidence_invariants
from perflens.contracts.runtime_locks import (
    RuntimeAcquireEvent,
    RuntimeLockResourceLimits,
    RuntimeReleaseEvent,
    RuntimeWaitEndEvent,
    derive_runtime_execution_context_id,
    derive_runtime_lock_id,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks import import_runtime_lock_ndjson


def _context(*, pid: int = 100, tid: int = 101) -> dict[str, Any]:
    return {"kind": "os_thread", "target_pid": pid, "target_tid": tid}


def _header(
    *,
    schema_version: str = "1.1",
    event_count: int,
    runtime: str = "python",
    semantics: str = "exact",
    owner_observed: bool = False,
    hold_observed: bool = False,
    observed_tids: list[int] | None = None,
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "schema_version": schema_version,
        "record_type": "runtime_lock_header",
        "runtime": runtime,
        "runtime_version": "test-runtime-1",
        "adapter_id": "strict-test-adapter",
        "adapter_version": "runtime-lock-adapter-v1",
        "backend_id": "strict-ndjson-import",
        "backend_version": "1",
        "target": {
            "target_pid": 100,
            "target_uid": 1000,
            "target_start_time_ticks": 55,
            "observed_target_tids": [100, 101] if observed_tids is None else observed_tids,
        },
        "clock": {"clock": "monotonic"},
        "measurement_semantics": semantics,
        "visible_lock_kinds": ["mutex"],
        "fast_path_visibility": "partial",
        "owner_is_source_observed": owner_observed,
        "hold_time_is_source_observed": hold_observed,
        "declared_event_count": event_count,
        "declared_lost_event_count": 0,
        "declared_truncated": False,
    }
    if schema_version == "1.1":
        header["target"]["target_kind"] = "host"
    if semantics == "thresholded":
        header["duration_threshold_ns"] = 1_000
    elif semantics == "sampled":
        header["sampling_fraction"] = 5
    elif semantics == "cumulative":
        header["block_profile_rate_ns"] = 1_000_000
    return header


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


def _event(
    source_id: str,
    *,
    kind: str = "wait_begin",
    timestamp: int = 100,
    schema_version: str = "1.1",
    tid: int = 101,
    lock_id: str = "0xfeedface",
    **extra: Any,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema_version": schema_version,
        "record_type": "runtime_lock_event",
        "source_event_id": source_id,
        "event_kind": kind,
        "timestamp_ns": timestamp,
        "source_lock_id": lock_id,
        "lock_kind": "mutex",
    }
    if schema_version == "1.0":
        event["target_tid"] = tid
    else:
        event["execution_context"] = _context(tid=tid)
    event.update(extra)
    return event


def _stream(records: list[dict[str, Any]]) -> io.BytesIO:
    payload = "".join(
        json.dumps(record, separators=(",", ":"), allow_nan=True) + "\n" for record in records
    )
    return io.BytesIO(payload.encode())


def _import(records: list[dict[str, Any]], **kwargs: Any):
    return import_runtime_lock_ndjson(
        _stream(records),
        created_at="2026-08-30T00:00:00+00:00",
        **kwargs,
    )


def test_valid_import_is_content_bound_opaque_and_path_redacted(
    fixture_root: Path,
) -> None:
    raw = (fixture_root / "runtime_locks" / "valid-v1.1.ndjson").read_bytes()
    evidence = import_runtime_lock_ndjson(
        io.BytesIO(raw),
        created_at="2026-08-30T00:00:00+00:00",
    )
    replay = import_runtime_lock_ndjson(
        io.BytesIO(raw),
        created_at="2026-08-30T00:00:00+00:00",
    )

    assert evidence == replay
    assert evidence.schema_version == "1.1"
    assert evidence.source.schema_version == "1.1"
    assert evidence.quality.status == "complete"
    assert evidence.content_sha256 == contract_content_sha256(evidence, exclude={"content_sha256"})
    public_json = evidence.model_dump_json()
    for private_value in (
        "0xfeedface",
        "raw-stack-1",
        "raw-wait-begin",
        "/private/build",
        "/home/alice/secret",
        "/private/thread/name",
    ):
        assert private_value not in public_json
    assert evidence.stacks[0].frames[0].module == "libworker.so"
    assert evidence.stacks[0].frames[0].source_file == "worker.py"
    assert evidence.events[0].lock_id == derive_runtime_lock_id(
        evidence.runtime_lock_evidence_id, 0
    )
    assert tuple(context.context_id for context in evidence.execution_contexts) == tuple(
        derive_runtime_execution_context_id(evidence.runtime_lock_evidence_id, index)
        for index in range(2)
    )
    wait_end = evidence.events[1]
    acquire = evidence.events[2]
    release = evidence.events[3]
    assert isinstance(wait_end, RuntimeWaitEndEvent)
    assert isinstance(acquire, RuntimeAcquireEvent)
    assert isinstance(release, RuntimeReleaseEvent)
    assert wait_end.wait_begin_event_id == evidence.events[0].event_id
    assert acquire.wait_end_event_id == wait_end.event_id
    assert release.acquire_event_id == acquire.event_id


def test_docker_target_artifact_references_are_content_bound_against_replacement() -> None:
    header = _header(event_count=1)
    header["target"] = {
        **header["target"],
        "target_kind": "docker",
        "container_reference": _container_reference(),
    }
    evidence = _import([header, _event("event")])
    validate_runtime_lock_evidence_invariants(evidence)
    reference = evidence.target.container_reference
    assert reference is not None
    tampered_reference = reference.model_copy(update={"container_identity_sha256": "f" * 64})
    tampered = evidence.model_copy(
        update={
            "target": evidence.target.model_copy(update={"container_reference": tampered_reference})
        }
    )

    with pytest.raises(PerfLensError, match="invariant"):
        validate_runtime_lock_evidence_invariants(tampered)


def test_schema_1_0_input_is_strictly_read_and_written_as_1_1() -> None:
    records = [
        _header(schema_version="1.0", event_count=2),
        _event("begin", schema_version="1.0"),
        _event(
            "end",
            kind="wait_end",
            timestamp=150,
            schema_version="1.0",
            wait_begin_source_event_id="begin",
            duration_ns=50,
            outcome="acquired",
        ),
    ]
    evidence = _import(records)

    assert evidence.schema_version == "1.1"
    assert evidence.source.schema_version == "1.1"
    assert [context.target_tid for context in evidence.execution_contexts] == [101]
    assert all(event.target_tid is None for event in evidence.events)
    assert all(event.execution_context_id is not None for event in evidence.events)


def test_versionless_schema_1_0_header_remains_importable() -> None:
    header = _header(schema_version="1.0", event_count=2)
    header.pop("schema_version")
    evidence = _import(
        [
            header,
            _event("begin", schema_version="1.0"),
            _event(
                "end",
                kind="wait_end",
                timestamp=150,
                schema_version="1.0",
                wait_begin_source_event_id="begin",
                duration_ns=50,
                outcome="acquired",
            ),
        ]
    )

    assert evidence.schema_version == "1.1"
    assert evidence.source.schema_version == "1.1"
    assert evidence.quality.emitted_event_count == 2


def test_schema_1_0_acquire_rejects_1_1_wait_end_reference_even_when_null() -> None:
    evidence = _import(
        [
            _header(schema_version="1.0", event_count=1),
            _event(
                "acquire",
                kind="acquire",
                schema_version="1.0",
                wait_end_source_event_id=None,
            ),
        ]
    )

    assert evidence.quality.malformed_record_count == 1
    assert evidence.quality.emitted_event_count == 0
    assert any(item.startswith("INVALID_EVENT ") for item in evidence.quality.diagnostics)


def test_thresholded_wait_completion_may_preserve_source_duration_without_pair() -> None:
    evidence = _import(
        [
            _header(event_count=1, semantics="thresholded"),
            _event(
                "thresholded-wait",
                kind="wait_end",
                duration_ns=5_000,
                outcome="acquired",
            ),
        ]
    )

    event = evidence.events[0]
    assert isinstance(event, RuntimeWaitEndEvent)
    assert event.wait_begin_event_id is None
    assert event.duration_ns == 5_000


def test_unknown_fields_nonfinite_and_negative_time_are_rejected_without_echo() -> None:
    records = [
        _header(event_count=4),
        _event("accepted"),
        _event("unknown", timestamp=101, arbitrary_command="do-not-echo"),
        _event("negative", timestamp=-1),
        {
            **_event("nan", kind="sampled_contention", timestamp=102),
            "observed_count": 1,
            "cumulative_wait_ns": 10,
            "estimated_count": float("nan"),
        },
    ]
    evidence = _import(records)

    assert evidence.quality.status == "partial"
    assert evidence.quality.malformed_record_count == 3
    assert evidence.quality.emitted_event_count == 1
    assert "do-not-echo" not in evidence.model_dump_json()
    assert all("do-not-echo" not in item for item in evidence.quality.diagnostics)


@pytest.mark.parametrize("nonfinite", [float("inf"), float("-inf")])
def test_nonfinite_infinity_is_rejected_by_the_raw_ndjson_boundary(
    nonfinite: float,
) -> None:
    evidence = _import(
        [
            _header(event_count=2),
            _event("accepted"),
            {
                **_event("infinite", kind="sampled_contention", timestamp=101),
                "observed_count": 1,
                "cumulative_wait_ns": 10,
                "estimated_count": nonfinite,
            },
        ]
    )

    assert evidence.quality.status == "partial"
    assert evidence.quality.malformed_record_count == 1
    assert evidence.quality.emitted_event_count == 1


@pytest.mark.parametrize("reference", [None, "missing-wait-begin"])
def test_exact_wait_end_without_a_resolved_begin_is_not_emitted(
    reference: str | None,
) -> None:
    event = _event(
        "orphan-wait-end",
        kind="wait_end",
        duration_ns=5_000,
        outcome="acquired",
    )
    if reference is not None:
        event["wait_begin_source_event_id"] = reference

    evidence = _import([_header(event_count=1), event])

    assert evidence.quality.status == "partial"
    assert evidence.quality.malformed_record_count == 1
    assert evidence.quality.emitted_event_count == 0
    assert evidence.events == ()


@pytest.mark.parametrize("foreign_reference", ["event", "owner", "parked"])
def test_foreign_contexts_are_filtered_without_affecting_target_ordering(
    foreign_reference: str,
) -> None:
    foreign = _event("outside-target", timestamp=10_000)
    if foreign_reference == "event":
        foreign["execution_context"] = _context(tid=999)
    elif foreign_reference == "owner":
        foreign["owner_execution_context"] = _context(tid=999)
    else:
        foreign["event_kind"] = "unpark"
        foreign["parked_execution_context"] = _context(tid=999)

    evidence = _import(
        [
            _header(
                event_count=2,
                owner_observed=foreign_reference == "owner",
            ),
            foreign,
            _event("accepted-target-event", timestamp=100),
        ]
    )

    assert evidence.quality.filtered_outside_target_count == 1
    assert evidence.quality.out_of_order_record_count == 0
    assert evidence.quality.emitted_event_count == 1
    assert [event.timestamp_ns for event in evidence.events] == [100]
    assert {context.target_tid for context in evidence.execution_contexts} == {101}


def test_rejected_event_does_not_reserve_identity_or_advance_timestamp() -> None:
    rejected = _event("reusable-event-id", timestamp=10_000)
    rejected["lock_kind"] = "semaphore"
    evidence = _import(
        [
            _header(event_count=3),
            rejected,
            _event("reusable-event-id", timestamp=100),
            _event("accepted-later", timestamp=101),
        ]
    )

    assert evidence.quality.unsupported_record_count == 1
    assert evidence.quality.duplicate_record_count == 0
    assert evidence.quality.out_of_order_record_count == 0
    assert evidence.quality.emitted_event_count == 2
    assert [event.timestamp_ns for event in evidence.events] == [100, 101]


def test_duplicate_ids_out_of_order_and_outside_target_are_conserved() -> None:
    records = [
        _header(event_count=5),
        _event("first", timestamp=100),
        _event("first", timestamp=101),
        _event("older", timestamp=99),
        _event("foreign-pid", timestamp=102, execution_context=_context(pid=999)),
        _event("last", timestamp=103),
    ]
    evidence = _import(records)

    quality = evidence.quality
    assert quality.input_record_count == 5
    assert quality.emitted_event_count == 2
    assert quality.duplicate_record_count == 1
    assert quality.out_of_order_record_count == 1
    assert quality.filtered_outside_target_count == 1
    assert (
        quality.emitted_event_count
        + quality.duplicate_record_count
        + quality.out_of_order_record_count
        + quality.filtered_outside_target_count
        == quality.input_record_count
    )


def test_stack_records_have_independent_conservation_and_path_redaction() -> None:
    good_stack = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_stack",
        "source_stack_id": "stack-one",
        "frames": [{"symbol": "f", "module": "/secret/lib.so"}],
    }
    records = [
        _header(event_count=1),
        good_stack,
        good_stack,
        {**good_stack, "source_stack_id": "bad", "unknown": "/do/not/echo"},
        _event("event", source_stack_id="stack-one"),
    ]
    evidence = _import(records)

    quality = evidence.quality
    assert quality.stack_input_record_count == 3
    assert quality.emitted_stack_count == 1
    assert quality.duplicate_stack_record_count == 1
    assert quality.malformed_stack_record_count == 1
    assert quality.truncated_stack_record_count == 0
    assert evidence.stacks[0].frames[0].module == "lib.so"
    assert "/do/not/echo" not in evidence.model_dump_json()


def test_stack_labels_filter_addresses_credentials_and_private_key_material() -> None:
    stack = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_stack",
        "source_stack_id": "sensitive-stack",
        "frames": [
            {
                "symbol": "token=super-secret-value",
                "module": "/private/build/0xfeedface",
                "source_file": "/private/password=hunter2",
            },
            {
                "symbol": "parse_token",
                "module": "https://alice:hunter2@example.test/libsafe.so",
                "source_file": "-----BEGIN OPENSSH PRIVATE KEY-----",
            },
        ],
    }
    evidence = _import(
        [
            _header(event_count=1),
            stack,
            _event("event", source_stack_id="sensitive-stack"),
        ]
    )

    first, second = evidence.stacks[0].frames
    assert (first.symbol, first.module, first.source_file) == (
        "[redacted]",
        "[redacted]",
        "[redacted]",
    )
    assert second.symbol == "parse_token"
    assert second.module == "[redacted]"
    assert second.source_file == "[redacted]"
    public_json = evidence.model_dump_json()
    for private_value in (
        "super-secret-value",
        "0xfeedface",
        "hunter2",
        "alice",
        "OPENSSH PRIVATE KEY",
    ):
        assert private_value not in public_json


@pytest.mark.parametrize(
    "symbol",
    [
        "/home/alice/private/source.cpp",
        r"C:\Users\alice\private\source.cpp",
        r"\\server\share\source.cpp",
    ],
)
def test_stack_symbol_absolute_paths_are_redacted(symbol: str) -> None:
    stack = {
        "schema_version": "1.1",
        "record_type": "runtime_lock_stack",
        "source_stack_id": "absolute-symbol-stack",
        "frames": [{"symbol": symbol, "module": "libworker.so"}],
    }
    evidence = _import(
        [
            _header(event_count=1),
            stack,
            _event("event", source_stack_id="absolute-symbol-stack"),
        ]
    )

    assert evidence.stacks[0].frames[0].symbol == "[redacted]"
    assert symbol not in evidence.model_dump_json()


@pytest.mark.parametrize(
    ("field", "private_value"),
    [
        ("runtime_version", "/opt/private/python-3.13"),
        ("adapter_version", "token=adapter-secret"),
        ("backend_version", "https://alice:hunter2@example.test/backend"),
        ("runtime_version", "-----BEGIN PRIVATE KEY-----"),
    ],
)
def test_header_version_identity_rejects_paths_and_credentials_without_echo(
    field: str,
    private_value: str,
) -> None:
    header = _header(event_count=1)
    header[field] = private_value

    with pytest.raises(PerfLensError) as raised:
        _import([header, _event("event")])

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert private_value not in str(raised.value)


def test_duplicate_header_and_declared_count_mismatch_fail_closed() -> None:
    with pytest.raises(PerfLensError) as duplicate:
        _import([_header(event_count=0), _header(event_count=0)])
    assert duplicate.value.code is ErrorCode.INVALID_INPUT
    assert "duplicate header" in duplicate.value.message

    with pytest.raises(PerfLensError) as mismatch:
        _import([_header(event_count=2), _event("only-one")])
    assert mismatch.value.code is ErrorCode.INVALID_INPUT
    assert "declared event count" in mismatch.value.message


def test_bytes_lines_records_and_cardinalities_are_bounded() -> None:
    header = _header(event_count=1)
    with pytest.raises(PerfLensError) as oversized_line:
        _import(
            [header, _event("one")],
            limits=RuntimeLockResourceLimits(max_line_bytes=128),
        )
    assert oversized_line.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as oversized_source:
        _import(
            [header, _event("one")],
            limits=RuntimeLockResourceLimits(max_source_bytes=256),
        )
    assert oversized_source.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as records:
        _import(
            [_header(event_count=2), _event("one"), _event("two", timestamp=101)],
            limits=RuntimeLockResourceLimits(max_input_records=1),
        )
    assert records.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as locks:
        _import(
            [
                _header(event_count=2),
                _event("one", lock_id="lock-one"),
                _event("two", timestamp=101, lock_id="lock-two"),
            ],
            limits=RuntimeLockResourceLimits(max_unique_locks=1),
        )
    assert locks.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_execution_context_cardinality_and_diagnostics_are_bounded() -> None:
    java_header = _header(
        event_count=2,
        runtime="java",
        observed_tids=[],
    )
    virtual_one = {
        "kind": "java_virtual_thread",
        "target_pid": 100,
        "runtime_context_id": "source-virtual-1",
    }
    virtual_two = {
        "kind": "java_virtual_thread",
        "target_pid": 100,
        "runtime_context_id": "source-virtual-2",
    }
    with pytest.raises(PerfLensError) as contexts:
        _import(
            [
                java_header,
                _event("one", execution_context=virtual_one),
                _event("two", timestamp=101, execution_context=virtual_two),
            ],
            limits=RuntimeLockResourceLimits(max_unique_target_tids=1),
        )
    assert contexts.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    bad = [_event(f"bad-{index}", timestamp=100 + index, extra="secret") for index in range(3)]
    evidence = _import(
        [_header(event_count=3), *bad],
        limits=RuntimeLockResourceLimits(max_diagnostics=1),
    )
    assert evidence.quality.diagnostic_count == 1
    assert evidence.quality.diagnostics == ()
    assert evidence.quality.diagnostics_truncated
    assert "secret" not in evidence.model_dump_json()


def test_json_duplicate_keys_and_missing_final_newline_do_not_escape_raw_text() -> None:
    header = json.dumps(_header(event_count=2), separators=(",", ":")) + "\n"
    duplicate_key = (
        '{"schema_version":"1.1","record_type":"runtime_lock_event",'
        '"source_event_id":"dup","source_event_id":"raw-secret",'
        '"event_kind":"wait_begin","timestamp_ns":100,'
        '"execution_context":{"kind":"os_thread","target_pid":100,"target_tid":101},'
        '"source_lock_id":"lock","lock_kind":"mutex"}\n'
    )
    no_newline = json.dumps(_event("tail"), separators=(",", ":"))
    evidence = import_runtime_lock_ndjson(
        io.BytesIO((header + duplicate_key + no_newline).encode()),
        created_at="2026-08-30T00:00:00+00:00",
    )

    assert evidence.quality.malformed_record_count == 2
    assert "raw-secret" not in evidence.model_dump_json()


def test_incomplete_exact_begin_is_retained_only_as_partial_evidence() -> None:
    evidence = _import([_header(event_count=1), _event("orphan-wait")])

    assert evidence.quality.emitted_event_count == 1
    assert evidence.quality.status == "partial"
    assert any("incomplete begin/end" in item for item in evidence.quality.limitations)
    assert "unqualified_runtime_lock_conclusion" in evidence.forbidden_conclusions


def test_evidence_identity_binds_normalized_creation_time() -> None:
    records = [_header(event_count=1), _event("orphan-wait")]
    payload = _stream(records).getvalue()
    first = import_runtime_lock_ndjson(io.BytesIO(payload), created_at="2026-08-30T00:00:00+00:00")
    replay = import_runtime_lock_ndjson(io.BytesIO(payload), created_at="2026-08-30T08:00:00+08:00")
    later = import_runtime_lock_ndjson(io.BytesIO(payload), created_at="2026-08-30T00:00:01+00:00")

    assert replay == first
    assert later.runtime_lock_evidence_id != first.runtime_lock_evidence_id
    assert later.events[0].lock_id != first.events[0].lock_id
    assert later.execution_contexts[0].context_id != first.execution_contexts[0].context_id


def test_evidence_creation_time_requires_a_timezone() -> None:
    with pytest.raises(PerfLensError, match="must include a timezone"):
        import_runtime_lock_ndjson(
            _stream([_header(event_count=1), _event("orphan-wait")]),
            created_at="2026-08-30T00:00:00",
        )
