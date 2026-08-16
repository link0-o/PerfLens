from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Literal

import pytest

from perflens.application import analyze_trace as analyze_trace_module
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.trace_evidence import (
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    compute_trace_evidence_content_sha256,
    compute_trace_evidence_fingerprint,
    normalized_trace_ndjson_identity,
    validate_trace_evidence_invariants,
    verify_private_raw_snapshot,
)
from perflens.application.verify_trace import (
    compute_trace_analysis_content_sha256,
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceCaptureManifest,
    TraceConversionManifest,
    TraceEventFormatIdentity,
    TraceEvidenceArtifact,
    TraceQuality,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.trace import FutexEvent, FutexOperation

SHA_B = "b" * 64
SHA_ZERO = "0" * 64
LOCK_ID = f"lock-{'1' * 20}"
TraceMode = Literal["sched", "off_cpu", "lock"]
RecipeId = Literal["sched-v1", "off-cpu-v1", "lock-v1"]


def _trace_quality(event_count: int) -> TraceQuality:
    return TraceQuality(
        quality_status="verified",
        input_event_count=event_count,
        emitted_event_count=event_count,
        expanded_derived_event_count=0,
        merged_enrichment_event_count=0,
        lost_event_count=0,
        malformed_event_count=0,
        duplicate_event_count=0,
        out_of_order_event_count=0,
        unpaired_event_count=0,
        unsupported_event_count=0,
        truncated_event_count=0,
        foreign_event_dropped_count=0,
    )


def _conversion(mode: TraceMode) -> TraceConversionManifest:
    recipe_by_mode: dict[TraceMode, RecipeId] = {
        "sched": "sched-v1",
        "off_cpu": "off-cpu-v1",
        "lock": "lock-v1",
    }
    manifest = TraceConversionManifest(
        recipe_id=recipe_by_mode[mode],
        converter_path="/usr/bin/perf",
        converter_sha256="c" * 64,
        converter_version="perf version test",
        parser_version="trace-parser-v1",
        normalization_version="trace-normalizer-v1",
        argv=(
            "/usr/bin/perf",
            "script",
            "--force",
            "--ns",
            "--show-lost-events",
            "-F",
            "trace:pid,tid,cpu,time,event,trace",
            "-i",
            "<private-input>",
        ),
        locale="C",
        conversion_fingerprint=SHA_ZERO,
    )
    return TraceConversionManifest.model_validate(
        {
            **manifest.model_dump(mode="json"),
            "conversion_fingerprint": compute_trace_conversion_fingerprint(manifest),
        }
    )


def _capture(mode: TraceMode) -> TraceCaptureManifest:
    manifest = TraceCaptureManifest(
        mode=mode,
        backend_id="target_filtered_kernel_v1",
        backend_version="test-v1",
        producer_path="/usr/lib/perflens/perflens-trace-helper",
        producer_sha256="d" * 64,
        kernel_release="6.12-test",
        architecture="x86_64",
        byte_order="little",
        pointer_size_bits=64,
        target_scope="kernel_tgid_filtered",
        dynamic_thread_coverage="complete",
        switch_in_visibility="not_applicable" if mode == "lock" else "complete",
        external_wakeup_visibility=(
            "not_applicable" if mode == "lock" else "complete"
        ),
        foreign_metadata_before_userspace=False,
        event_formats=(
            TraceEventFormatIdentity(
                event_name="perflens:typed_trace",
                format_sha256="e" * 64,
            ),
        ),
        capture_fingerprint=SHA_ZERO,
    )
    return TraceCaptureManifest.model_validate(
        {
            **manifest.model_dump(mode="json"),
            "capture_fingerprint": compute_trace_capture_fingerprint(manifest),
        }
    )


def _event(
    index: int,
    timestamp_ns: int,
    event_type: str,
    **fields: object,
) -> dict[str, object]:
    return {
        "event_type": event_type,
        "event_id": f"event-{index + 1:016x}",
        "event_index": index,
        "source_sequence": index + 10,
        "timestamp_ns": timestamp_ns,
        "cpu": 0,
        "target_pid": 123,
        "target_tid": 123,
        **fields,
    }


def _sched_events() -> list[dict[str, object]]:
    return [
        _event(
            0,
            10,
            "sched_wakeup",
            source_event="sched_wakeup_new",
            waker_relation="unavailable",
        ),
        _event(1, 20, "sched_switch", direction="switch_in"),
        _event(2, 30, "sched_migrate", origin_cpu=0, destination_cpu=1),
        _event(
            3,
            50,
            "sched_switch",
            direction="switch_out",
            previous_state="running",
        ),
    ]


def _off_cpu_events() -> list[dict[str, object]]:
    return [
        _event(
            0,
            10,
            "sched_switch",
            direction="switch_out",
            previous_state="interruptible_sleep",
        ),
        _event(1, 30, "sched_switch", direction="switch_in"),
    ]


def _lock_events() -> list[dict[str, object]]:
    stack = ({"ip": "0x10", "symbol": "waiter", "dso": "workload"},)
    return [
        _event(
            0,
            10,
            "lock_wait",
            lock_id=LOCK_ID,
            lock_kind="kernel_lock",
            owner_target_tid=123,
            call_stack=stack,
        ),
        _event(
            1,
            20,
            "lock_wait_ended",
            lock_id=LOCK_ID,
            lock_kind="kernel_lock",
            outcome="acquired",
            call_stack=stack,
        ),
        _event(
            2,
            50,
            "lock_released",
            lock_id=LOCK_ID,
            lock_kind="kernel_lock",
            call_stack=stack,
        ),
        _event(
            3,
            60,
            "lock_wait",
            lock_id=LOCK_ID,
            lock_kind="kernel_lock",
            call_stack=stack,
        ),
        _event(
            4,
            80,
            "lock_wait_ended",
            lock_id=LOCK_ID,
            lock_kind="kernel_lock",
            outcome="timed_out",
            call_stack=stack,
        ),
    ]


def _futex_events() -> list[dict[str, object]]:
    return [
        _event(
            0,
            10,
            "futex_wait",
            lock_id=LOCK_ID,
            operation="wait_bitset",
            call_stack=(),
        ),
        _event(
            1,
            20,
            "futex_wake",
            lock_id=LOCK_ID,
            operation="wake_bitset",
            woken_count=2,
        ),
    ]


def _evidence(
    raw: bytes,
    *,
    mode: TraceMode = "sched",
    events: list[dict[str, object]] | None = None,
    diagnostic_count: int = 0,
    max_output_bytes: int = 1_048_576,
) -> TraceEvidenceArtifact:
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    event_rows = events if events is not None else _sched_events()
    quality = (
        _trace_quality(len(event_rows))
        if event_rows
        else TraceQuality(
            quality_status="partial",
            input_event_count=0,
            emitted_event_count=0,
            lost_event_count=0,
            malformed_event_count=0,
            duplicate_event_count=0,
            out_of_order_event_count=0,
            unpaired_event_count=0,
            unsupported_event_count=0,
            truncated_event_count=0,
            foreign_event_dropped_count=0,
            limitations=("No target-scoped trace events were emitted.",),
        )
    )
    if diagnostic_count:
        quality = TraceQuality.model_validate(
            {
                **quality.model_dump(mode="json"),
                "quality_status": "partial",
                "limitations": ("The converter emitted bounded raw diagnostics.",),
            }
        )
    common: dict[str, Any] = {
        "schema_version": "1.0",
        "perflens_version": "0.3.0",
        "mode": mode,
        "status": "complete" if event_rows and not diagnostic_count else "partial",
        "input_sha256": raw_sha256,
        "input_bytes": len(raw),
        "source": {
            "collection_id": "collection-bbbbbbbbbbbbbbbb",
            "mode": mode,
            "collection_artifact_sha256": SHA_B,
            "output_sha256": raw_sha256,
            "output_bytes": len(raw),
            "output_format": "perf_data",
            "capture": _capture(mode).model_dump(mode="json"),
        },
        "target": {
            "target_pid": 123,
            "target_uid": 1000,
            "target_start_time_ticks": 456,
            "observed_target_tids": [123] if event_rows else [],
        },
        "conversion": _conversion(mode).model_dump(mode="json"),
        "clock": {
            "clock": "monotonic",
            "unit": "nanoseconds",
            "source": "linux_perf",
        },
        "observation_window": (
            {
                "start_timestamp_ns": event_rows[0]["timestamp_ns"],
                "end_timestamp_ns": event_rows[-1]["timestamp_ns"],
                "source": "observed_event_bounds",
            }
            if event_rows
            else {
                "start_timestamp_ns": 10,
                "end_timestamp_ns": 10,
                "source": "collector_monotonic_bounds",
            }
        ),
        "quality": quality.model_dump(mode="json"),
        "limits": {
            "max_duration_seconds": 10,
            "max_input_bytes": 4096,
            "max_input_lines": 100,
            "max_input_events": 100,
            "max_line_bytes": 4096,
            "max_stack_depth": 32,
            "max_exported_events": 100,
            "max_exported_intervals": 100,
            "max_unique_target_tids": 8,
            "max_unique_locks": 8,
            "max_diagnostics": 2,
            "max_warnings": 10,
            "max_output_bytes": max_output_bytes,
        },
        "allowed_conclusions": [f"{mode}_timing_distribution"],
        "forbidden_conclusions": [
            "performance_root_cause",
            "verified_improvement",
            "unqualified_trace_conclusion",
        ],
        "content_sha256": SHA_ZERO,
        "input_line_count": len(event_rows),
        "diagnostic_count": diagnostic_count,
    }
    typed_events = TraceEvidenceArtifact.model_validate(
        {
            **common,
            "trace_evidence_id": "trace-evidence-0000000000000000",
            "evidence_fingerprint": SHA_ZERO,
            "normalized_ndjson_sha256": SHA_ZERO,
            "normalized_ndjson_bytes": 1 if event_rows else 0,
            "events": event_rows,
        }
    ).events
    ndjson_sha256, ndjson_bytes = normalized_trace_ndjson_identity(typed_events)
    provisional = TraceEvidenceArtifact.model_validate(
        {
            **common,
            "trace_evidence_id": "trace-evidence-0000000000000000",
            "evidence_fingerprint": SHA_ZERO,
            "normalized_ndjson_sha256": ndjson_sha256,
            "normalized_ndjson_bytes": ndjson_bytes,
            "events": event_rows,
        }
    )
    fingerprint = compute_trace_evidence_fingerprint(provisional)
    identified = provisional.model_copy(
        update={
            "trace_evidence_id": f"trace-evidence-{fingerprint[:16]}",
            "evidence_fingerprint": fingerprint,
        }
    )
    return TraceEvidenceArtifact.model_validate(
        {
            **identified.model_dump(mode="json"),
            "content_sha256": compute_trace_evidence_content_sha256(identified),
        }
    )


def _snapshot(evidence: TraceEvidenceArtifact, raw_path: Path):
    metadata = raw_path.stat()
    return verify_private_raw_snapshot(
        evidence.source,
        raw_path,
        max_input_bytes=evidence.limits.max_input_bytes,
        expected_owner_uid=metadata.st_uid,
        expected_owner_gid=metadata.st_gid,
        expected_mode=0o600,
    )


def test_trace_verification_passes_with_private_snapshot_and_real_replay(
    tmp_path: Path,
) -> None:
    raw = b"private perf data"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(raw, mode="lock", events=_lock_events())
    analysis = build_trace_analysis(evidence)

    verification = verify_trace_analysis_artifact(
        analysis,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )

    assert verification.verification_status == "verified"
    assert all(check.status == "passed" for check in verification.checks)
    assert verification.analysis_content_bytes == len(serialize_json(analysis))
    assert str(raw_path) not in verification.model_dump_json()
    require_usable_trace_analysis(verification)


def test_public_verification_only_skips_private_raw_rehash() -> None:
    evidence = _evidence(b"private perf data", mode="lock", events=_lock_events())
    analysis = build_trace_analysis(evidence)

    verification = verify_trace_analysis_artifact(analysis, evidence)

    assert verification.verification_status == "partial"
    skipped = {check.name for check in verification.checks if check.status == "skipped"}
    assert skipped == {"raw_evidence_identity"}
    aggregate = next(
        check for check in verification.checks if check.name == "analysis_aggregate_conservation"
    )
    assert aggregate.status == "passed"
    require_usable_trace_analysis(verification)


def test_failed_aggregate_is_returned_but_agent_use_is_rejected(tmp_path: Path) -> None:
    raw = b"private perf data"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(raw)
    original = build_trace_analysis(evidence)
    assert isinstance(original, SchedulerAnalysisArtifact)
    bad_thread = original.threads[0].model_copy(
        update={"runtime_ns": original.threads[0].runtime_ns + 1}
    )
    tampered = original.model_copy(update={"threads": (bad_thread,)})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_trace_analysis_content_sha256(tampered)}
    )

    verification = verify_trace_analysis_artifact(
        tampered,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )

    assert verification.verification_status == "failed"
    assert any(
        check.name == "analysis_aggregate_conservation" and check.status == "failed"
        for check in verification.checks
    )
    with pytest.raises(PerfLensError) as captured:
        require_usable_trace_analysis(verification)
    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert "analysis_aggregate_conservation" in captured.value.details["failed_checks"]


def test_off_cpu_missing_wakeup_preserves_total_as_unknown_and_verifies(
    tmp_path: Path,
) -> None:
    raw = b"off cpu private data"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(raw, mode="off_cpu", events=_off_cpu_events())
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, OffCpuAnalysisArtifact)

    assert analysis.total_off_cpu_ns == 20
    assert analysis.total_unknown_ns == 20
    assert analysis.total_complete_interval_count == 1
    assert analysis.split_complete_interval_count == 0
    assert analysis.threads[0].candidate_categories[0].category == "sleep"
    assert analysis.threads[0].worst_intervals[0].candidate_wait_category == "sleep"
    assert analysis.quality.quality_status == "partial"
    verification = verify_trace_analysis_artifact(
        analysis,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )
    assert verification.verification_status == "verified"
    assert verification.status == "partial"
    assert verification.quality.quality_status == "partial"
    assert all(check.status == "passed" for check in verification.checks)


def test_lock_outcomes_and_hold_are_replayed_without_promotion(tmp_path: Path) -> None:
    raw = b"lock private data"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(raw, mode="lock", events=_lock_events())
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, LockAnalysisArtifact)

    lock = analysis.locks[0]
    assert lock.exact_wait_count == 2
    assert {row.outcome: row.interval_count for row in lock.exact_wait_outcomes} == {
        "acquired": 1,
        "timed_out": 1,
    }
    assert lock.exact_hold_count == 1
    assert analysis.total_candidate_wait_event_count == 0
    verification = verify_trace_analysis_artifact(
        analysis,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )
    assert verification.verification_status == "verified"


def test_futex_operation_is_preserved_during_deterministic_replay() -> None:
    evidence = _evidence(b"futex private data", mode="lock", events=_futex_events())

    replayed, _ = analyze_trace_module._to_domain_events(  # pyright: ignore[reportPrivateUsage]
        evidence
    )

    futex_events = [event for event in replayed if isinstance(event, FutexEvent)]
    assert [event.operation for event in futex_events] == [
        FutexOperation.WAIT_BITSET,
        FutexOperation.WAKE_BITSET,
    ]
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, LockAnalysisArtifact)
    assert analysis.total_candidate_wait_event_count == 1
    assert analysis.total_candidate_wake_event_count == 1


def test_truncated_full_event_ledger_hash_is_checked_by_real_replay() -> None:
    evidence = _evidence(b"lock private data", mode="lock", events=_lock_events())
    original = build_trace_analysis(evidence)
    assert original.event_accounting.consumed.sample_truncated
    bad_ledger = original.event_accounting.consumed.model_copy(
        update={"all_event_ids_sha256": "f" * 64}
    )
    bad_accounting = original.event_accounting.model_copy(update={"consumed": bad_ledger})
    tampered = original.model_copy(update={"event_accounting": bad_accounting})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_trace_analysis_content_sha256(tampered)}
    )

    verification = verify_trace_analysis_artifact(tampered, evidence)

    assert verification.verification_status == "failed"
    aggregate = next(
        check for check in verification.checks if check.name == "analysis_aggregate_conservation"
    )
    assert aggregate.status == "failed"


def test_analysis_builder_enforces_serialized_output_limit() -> None:
    evidence = _evidence(
        b"lock private data",
        mode="lock",
        events=_lock_events(),
        max_output_bytes=7_000,
    )

    with pytest.raises(PerfLensError) as captured:
        build_trace_analysis(evidence)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert captured.value.stage == "trace_analysis"


def test_empty_partial_evidence_replays_without_inventing_a_target_tid(
    tmp_path: Path,
) -> None:
    raw = b"empty private trace"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(raw, events=[])
    validate_trace_evidence_invariants(evidence)

    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, SchedulerAnalysisArtifact)
    assert evidence.target.observed_target_tids == ()
    assert analysis.threads == ()
    assert analysis.event_accounting.observed_event_count == 0
    verification = verify_trace_analysis_artifact(
        analysis,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )
    assert verification.verification_status == "verified"
    assert verification.status == "partial"
    assert all(check.status == "passed" for check in verification.checks)


def test_diagnostic_only_degradation_remains_partial_and_replayable(
    tmp_path: Path,
) -> None:
    raw = b"trace with a bounded diagnostic"
    raw_path = tmp_path / "private.data"
    raw_path.write_bytes(raw)
    raw_path.chmod(0o600)
    evidence = _evidence(
        raw,
        mode="lock",
        events=_lock_events(),
        diagnostic_count=1,
    )
    validate_trace_evidence_invariants(evidence)
    analysis = build_trace_analysis(evidence)
    assert analysis.quality.quality_status == "partial"

    verification = verify_trace_analysis_artifact(
        analysis,
        evidence,
        private_raw_snapshot=_snapshot(evidence, raw_path),
    )
    assert verification.verification_status == "verified"
    assert verification.status == "partial"
    assert all(check.status == "passed" for check in verification.checks)


@pytest.mark.parametrize(
    "unsafe_case",
    ["symlink", "wrong_owner", "wrong_group", "public_mode"],
)
def test_private_raw_rehash_rejects_unsafe_identity_without_disclosing_path(
    tmp_path: Path,
    unsafe_case: str,
) -> None:
    raw = b"private perf data"
    evidence = _evidence(raw)
    target = tmp_path / "target.data"
    target.write_bytes(raw)
    target.chmod(0o600 if unsafe_case != "public_mode" else 0o644)
    raw_path = target
    if unsafe_case == "symlink":
        raw_path = tmp_path / "private.data"
        raw_path.symlink_to(target)
    expected_uid = os.getuid() + 1 if unsafe_case == "wrong_owner" else os.getuid()
    expected_gid = os.getgid() + 1 if unsafe_case == "wrong_group" else os.getgid()

    with pytest.raises(PerfLensError) as captured:
        verify_private_raw_snapshot(
            evidence.source,
            raw_path,
            max_input_bytes=evidence.limits.max_input_bytes,
            expected_owner_uid=expected_uid,
            expected_owner_gid=expected_gid,
            expected_mode=0o600,
        )

    assert str(raw_path) not in str(captured.value)
    assert str(raw_path) not in str(captured.value.details)
    assert captured.value.details["collection_id"] == evidence.source.collection_id


def test_trace_evidence_validation_rejects_self_rehashed_wrong_event_order() -> None:
    evidence = _evidence(b"private perf data")
    reversed_events = tuple(reversed(evidence.events))
    digest, byte_count = normalized_trace_ndjson_identity(reversed_events)
    tampered = evidence.model_copy(
        update={
            "events": reversed_events,
            "normalized_ndjson_sha256": digest,
            "normalized_ndjson_bytes": byte_count,
        }
    )
    fingerprint = compute_trace_evidence_fingerprint(tampered)
    tampered = tampered.model_copy(
        update={
            "trace_evidence_id": f"trace-evidence-{fingerprint[:16]}",
            "evidence_fingerprint": fingerprint,
        }
    )
    tampered = tampered.model_copy(
        update={"content_sha256": compute_trace_evidence_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError, match="deterministic verification") as captured:
        validate_trace_evidence_invariants(tampered)

    failures = captured.value.details["failures"]
    assert "normalized event indexes are not contiguous" in failures
    assert "normalized events violate canonical source ordering" in failures


def test_verifier_rejects_compound_evidence_identity_and_accounting_tampering() -> None:
    evidence = _evidence(b"compound-tamper")
    analysis = build_trace_analysis(evidence)
    first = evidence.events[0].model_copy(
        update={
            "target_pid": 999,
            "target_tid": 999,
            "event_id": evidence.events[1].event_id,
            "event_index": 9,
        }
    )
    quality = evidence.quality.model_copy(
        update={"input_event_count": 0, "emitted_event_count": 1, "unpaired_event_count": 9}
    )
    source = evidence.source.model_copy(
        update={
            "output_sha256": "e" * 64,
            "output_bytes": evidence.input_bytes + 1,
            "capture": evidence.source.capture.model_copy(
                update={"capture_fingerprint": "f" * 64}
            ),
        }
    )
    tampered = evidence.model_copy(
        update={
            "input_sha256": "c" * 64,
            "input_bytes": evidence.input_bytes + 2,
            "source": source,
            "conversion": evidence.conversion.model_copy(
                update={"conversion_fingerprint": "d" * 64}
            ),
            "quality": quality,
            "trace_evidence_id": "trace-evidence-ffffffffffffffff",
            "evidence_fingerprint": "a" * 64,
            "content_sha256": "b" * 64,
            "normalized_ndjson_sha256": "c" * 64,
            "normalized_ndjson_bytes": evidence.limits.max_output_bytes + 1,
            "events": (first, *evidence.events[1:]),
        }
    )

    verification = verify_trace_analysis_artifact(analysis, tampered)

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert {
        "raw_evidence_identity",
        "conversion_manifest",
        "target_scope",
        "event_count_conservation",
        "analysis_aggregate_conservation",
    }.issubset(failed)


def test_verifier_rejects_scheduler_interval_scope_and_aggregate_tampering() -> None:
    evidence = _evidence(b"scheduler-tamper")
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, SchedulerAnalysisArtifact)
    thread = analysis.threads[0]
    interval = thread.worst_runnable_intervals[0]
    bad_interval = interval.model_copy(
        update={
            "target_tid": 999,
            "waker_target_tid": 999,
            "switch_in_timestamp_ns": interval.wakeup_timestamp_ns - 1,
            "duration_ns": interval.duration_ns + 1,
        }
    )
    bad_thread = thread.model_copy(
        update={
            "target_tid": 999,
            "runtime_ns": thread.runtime_ns + 1,
            "worst_runnable_intervals": (bad_interval,),
        }
    )
    tampered = analysis.model_copy(
        update={
            "threads": (bad_thread, bad_thread),
            "total_context_switch_count": analysis.total_context_switch_count + 1,
        }
    )

    verification = verify_trace_analysis_artifact(tampered, evidence)

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert "target_scope" in failed
    assert "time_interval_conservation" in failed
    assert "analysis_aggregate_conservation" in failed


def test_verifier_rejects_off_cpu_component_and_category_tampering() -> None:
    evidence = _evidence(b"offcpu-tamper", mode="off_cpu", events=_off_cpu_events())
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, OffCpuAnalysisArtifact)
    thread = analysis.threads[0]
    interval = thread.worst_intervals[0]
    bad_interval = interval.model_copy(
        update={
            "target_tid": 999,
            "off_cpu_duration_ns": (interval.off_cpu_duration_ns or 0) + 1,
            "unknown_duration_ns": 0,
            "incomplete_reason": None,
        }
    )
    bad_thread = thread.model_copy(
        update={
            "target_tid": 999,
            "total_complete_interval_count": 9,
            "split_complete_interval_count": 8,
            "candidate_categories": (),
            "worst_intervals": (bad_interval,),
        }
    )
    tampered = analysis.model_copy(
        update={
            "threads": (bad_thread, bad_thread),
            "total_off_cpu_ns": analysis.total_off_cpu_ns + 1,
            "total_unknown_ns": 0,
        }
    )

    verification = verify_trace_analysis_artifact(tampered, evidence)

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert "target_scope" in failed
    assert "time_interval_conservation" in failed
    assert "analysis_aggregate_conservation" in failed


def test_verifier_rejects_lock_scope_projection_and_interval_tampering() -> None:
    evidence = _evidence(b"lock-tamper", mode="lock", events=_lock_events())
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, LockAnalysisArtifact)
    lock = analysis.locks[0]
    wait = lock.worst_waits[0]
    hold = lock.worst_holds[0]
    bad_wait = wait.model_copy(
        update={
            "waiter_tid": 999,
            "owner_target_tid": 999,
            "wait_end_timestamp_ns": wait.wait_begin_timestamp_ns - 1,
            "wait_duration_ns": wait.wait_duration_ns + 1,
        }
    )
    bad_hold = hold.model_copy(
        update={
            "holder_tid": 999,
            "release_timestamp_ns": hold.acquire_timestamp_ns - 1,
            "hold_duration_ns": hold.hold_duration_ns + 1,
        }
    )
    bad_lock = lock.model_copy(
        update={
            "exact_wait_count": lock.exact_wait_count + 1,
            "exact_hold_count": lock.exact_hold_count + 1,
            "exact_wait_outcomes": (*lock.exact_wait_outcomes, *lock.exact_wait_outcomes),
            "worst_waits": (bad_wait,),
            "worst_holds": (bad_hold,),
        }
    )
    thread_projection = analysis.thread_projections[0].model_copy(
        update={"projection_type": "call_path", "target_tid": 999, "path_resolved": True}
    )
    path_projection = analysis.call_path_projections[0].model_copy(
        update={
            "projection_type": "thread",
            "target_tid": 123,
            "path_resolved": not bool(analysis.call_path_projections[0].call_path),
        }
    )
    tampered = analysis.model_copy(
        update={
            "locks": (bad_lock, bad_lock),
            "thread_projections": (thread_projection, thread_projection),
            "call_path_projections": (path_projection, path_projection),
            "total_exact_wait_ns": analysis.total_exact_wait_ns + 1,
        }
    )

    verification = verify_trace_analysis_artifact(tampered, evidence)

    assert verification.verification_status == "failed"
    failed = {check.name for check in verification.checks if check.status == "failed"}
    assert "target_scope" in failed
    assert "time_interval_conservation" in failed
    assert "analysis_aggregate_conservation" in failed
