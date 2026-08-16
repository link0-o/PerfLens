from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Literal

import pytest

from perflens.application.build_trace_evidence import build_trace_evidence
from perflens.application.trace_evidence import (
    VerifiedPrivateRawSnapshot,
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    validate_trace_evidence_invariants,
)
from perflens.contracts import trace as public
from perflens.domain import trace as domain
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.profiles.trace_stream import (
    TraceParseDiagnostic,
    TraceParseStatistics,
    TraceStreamParseResult,
)

TARGET = domain.TargetIdentity(pid=4242, uid=1000, start_time_ticks=998877)
TARGET_TASK = domain.TaskIdentity(pid=4242, tid=4242)
DYNAMIC_TASK = domain.TaskIdentity(pid=4242, tid=4243)
LOCK_ID = f"lock-{'a' * 20}"
RAW = b"private-perf-data"
RAW_SHA = hashlib.sha256(RAW).hexdigest()


TraceMode = Literal["sched", "off_cpu", "lock"]


def _capture(mode: TraceMode) -> public.TraceCaptureManifest:
    provisional = public.TraceCaptureManifest(
        mode=mode,
        backend_id="target_filtered_kernel_v1",
        backend_version="test-v1",
        producer_path="/usr/lib/perflens/perflens-trace-helper",
        producer_sha256="c" * 64,
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
            public.TraceEventFormatIdentity(
                event_name="perflens:typed_trace",
                format_sha256="d" * 64,
            ),
        ),
        capture_fingerprint="0" * 64,
    )
    return public.TraceCaptureManifest.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "capture_fingerprint": compute_trace_capture_fingerprint(provisional),
        }
    )


def _partial_stock_capture(mode: TraceMode) -> public.TraceCaptureManifest:
    provisional = public.TraceCaptureManifest(
        mode=mode,
        backend_id="stock_perf_pid_partial_v1",
        backend_version="perf-test",
        producer_path="/usr/bin/perf",
        producer_sha256="c" * 64,
        kernel_release="6.12-test",
        architecture="x86_64",
        byte_order="little",
        pointer_size_bits=64,
        target_scope="per_task_partial",
        dynamic_thread_coverage="partial",
        switch_in_visibility="not_applicable" if mode == "lock" else "partial",
        external_wakeup_visibility=(
            "not_applicable" if mode == "lock" else "partial"
        ),
        foreign_metadata_before_userspace=True,
        event_formats=(
            public.TraceEventFormatIdentity(
                event_name="sched:sched_switch",
                format_sha256="d" * 64,
            ),
        ),
        capture_fingerprint="0" * 64,
    )
    return public.TraceCaptureManifest.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "capture_fingerprint": compute_trace_capture_fingerprint(provisional),
        }
    )


def _source(mode: TraceMode = "sched") -> public.TraceRawArtifactReference:
    return public.TraceRawArtifactReference.model_validate(
        {
            "collection_id": f"collection-{'1' * 16}",
            "mode": mode,
            "collection_artifact_sha256": "b" * 64,
            "output_sha256": RAW_SHA,
            "output_bytes": len(RAW),
            "output_format": "perf_data",
            "capture": _capture(mode),
        }
    )


def _snapshot(mode: TraceMode = "sched") -> VerifiedPrivateRawSnapshot:
    return VerifiedPrivateRawSnapshot(
        collection_id=f"collection-{'1' * 16}",
        mode=mode,
        collection_artifact_sha256="b" * 64,
        output_sha256=RAW_SHA,
        output_bytes=len(RAW),
        capture_fingerprint=_capture(mode).capture_fingerprint,
    )


def _conversion(mode: TraceMode = "sched") -> public.TraceConversionManifest:
    provisional = public.TraceConversionManifest.model_validate(
        {
            "recipe_id": {
                "sched": "sched-v1",
                "off_cpu": "off-cpu-v1",
                "lock": "lock-v1",
            }[mode],
            "converter_path": "/usr/bin/perf",
            "converter_sha256": "c" * 64,
            "converter_version": "perf version test",
            "parser_version": "trace-perf-script-v1",
            "normalization_version": "trace-normalizer-v1",
            "argv": (
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
            "locale": "C",
            "conversion_fingerprint": "0" * 64,
        }
    )
    return public.TraceConversionManifest.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "conversion_fingerprint": compute_trace_conversion_fingerprint(provisional),
        }
    )


def _statistics(
    *,
    emitted: int,
    input_events: int | None = None,
    enrichment: int = 0,
    lock_phase_enrichment: int = 0,
    diagnostics: tuple[TraceParseDiagnostic, ...] = (),
) -> TraceParseStatistics:
    event_count = (
        emitted + enrichment + lock_phase_enrichment
        if input_events is None
        else input_events
    )
    return TraceParseStatistics(
        input_bytes=128,
        input_line_count=max(event_count, 1),
        input_event_count=event_count,
        emitted_event_count=emitted,
        lost_event_count=0,
        malformed_event_count=0,
        duplicate_event_count=0,
        out_of_order_event_count=0,
        unsupported_event_count=0,
        truncated_event_count=0,
        foreign_event_dropped_count=0,
        provisional_enrichment_event_count=enrichment,
        lock_phase_enrichment_event_count=lock_phase_enrichment,
        diagnostic_count=len(diagnostics),
        diagnostics=diagnostics,
        diagnostics_truncated=False,
    )


def _build(
    parsed: TraceStreamParseResult,
    *,
    mode: TraceMode = "sched",
    limits: public.TraceResourceLimits | None = None,
) -> public.TraceEvidenceArtifact:
    return build_trace_evidence(
        source=_source(mode),
        verified_raw=_snapshot(mode),
        parsed=parsed,
        conversion=_conversion(mode),
        target=TARGET,
        observation_window=public.TraceObservationWindow(
            start_timestamp_ns=0,
            end_timestamp_ns=100,
            source="collector_monotonic_bounds",
        ),
        limits=limits or public.TraceResourceLimits(),
        perflens_version="0.3.0",
    )


def test_dual_target_switch_expands_deterministically_and_conserves_counts() -> None:
    switch = domain.SchedSwitchEvent(
        event_id="private-source-event",
        sequence=7,
        timestamp_ns=10,
        cpu=2,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        previous=TARGET_TASK,
        previous_scope=domain.TraceScope.TARGET,
        next=DYNAMIC_TASK,
        next_scope=domain.TraceScope.TARGET,
        previous_state="running",
    )
    parsed = TraceStreamParseResult(
        events=(switch,),
        observed_target_tids=(4242, 4243),
        statistics=_statistics(emitted=1, enrichment=1),
    )

    first = _build(parsed)
    second = _build(parsed)

    switch_out, switch_in = first.events
    assert isinstance(switch_out, public.SchedSwitchEvent)
    assert isinstance(switch_in, public.SchedSwitchEvent)
    assert [switch_out.direction, switch_in.direction] == ["switch_out", "switch_in"]
    assert [event.target_tid for event in first.events] == [4242, 4243]
    assert [event.source_sequence for event in first.events] == [7, 7]
    assert [event.event_index for event in first.events] == [0, 1]
    assert [event.event_id for event in first.events] == [
        event.event_id for event in second.events
    ]
    assert first.target.observed_target_tids == (4242, 4243)
    assert first.quality.input_event_count == 2
    assert first.quality.emitted_event_count == 2
    assert first.quality.expanded_derived_event_count == 1
    assert first.quality.merged_enrichment_event_count == 1
    assert first.status == "complete"
    validate_trace_evidence_invariants(first)


def test_foreign_identity_and_private_diagnostics_never_reach_public_evidence() -> None:
    wakeup = domain.SchedWakeupEvent(
        event_id="event-wakeup-private",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        woken=DYNAMIC_TASK,
        woken_scope=domain.TraceScope.TARGET,
        source=domain.WakeupSource.WAKEUP_NEW,
        waker=domain.TaskIdentity.external_redacted(),
        waker_scope=domain.TraceScope.FOREIGN,
    )
    diagnostic = TraceParseDiagnostic(
        code="PRIVATE_INPUT_REDACTED",
        line_number=1,
        message="/private/spool/secret.data foreign pid 991122",
    )
    parsed = TraceStreamParseResult(
        events=(wakeup,),
        observed_target_tids=(4242, 4243),
        statistics=_statistics(emitted=1, diagnostics=(diagnostic,)),
    )

    evidence = _build(parsed)
    public_text = repr(evidence)

    event = evidence.events[0]
    assert isinstance(event, public.SchedWakeupEvent)
    assert event.source_event == "sched_wakeup_new"
    assert event.waker_relation == "redacted"
    assert event.waker_target_tid is None
    assert evidence.target.observed_target_tids == (4243,)
    assert evidence.status == "partial"
    assert evidence.quality.quality_status == "partial"
    assert evidence.diagnostic_count == 1
    assert "/private/spool" not in public_text
    assert "991122" not in public_text
    validate_trace_evidence_invariants(evidence)


def test_empty_trace_is_partial_and_does_not_invent_an_observed_tid() -> None:
    parsed = TraceStreamParseResult(
        events=(),
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=0, input_events=0),
    )

    evidence = _build(parsed)

    assert evidence.events == ()
    assert evidence.target.observed_target_tids == ()
    assert evidence.status == "partial"
    assert evidence.quality.quality_status == "partial"
    assert evidence.normalized_ndjson_bytes == 0
    assert evidence.normalized_ndjson_sha256 == hashlib.sha256(b"").hexdigest()
    assert evidence.allowed_conclusions == ("trace_evidence_quality_and_identity",)
    validate_trace_evidence_invariants(evidence)


def test_stock_perf_pid_capture_cannot_be_relabelled_as_complete() -> None:
    event = domain.SchedSwitchEvent(
        event_id="stock-partial-switch",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        previous=TARGET_TASK,
        previous_scope=domain.TraceScope.TARGET,
        next=domain.TaskIdentity.external_redacted(),
        next_scope=domain.TraceScope.FOREIGN,
        previous_state="running",
    )
    parsed = TraceStreamParseResult(
        events=(event,),
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=1),
    )
    capture = _partial_stock_capture("sched")
    source = _source().model_copy(update={"capture": capture})
    snapshot = replace(_snapshot(), capture_fingerprint=capture.capture_fingerprint)

    evidence = build_trace_evidence(
        source=source,
        verified_raw=snapshot,
        parsed=parsed,
        conversion=_conversion(),
        target=TARGET,
        observation_window=public.TraceObservationWindow(
            start_timestamp_ns=0,
            end_timestamp_ns=100,
            source="collector_monotonic_bounds",
        ),
        limits=public.TraceResourceLimits(),
        perflens_version="0.3.0",
    )

    assert evidence.status == "partial"
    assert evidence.quality.quality_status == "partial"
    assert any("complete target-filtered" in item for item in evidence.quality.limitations)
    validate_trace_evidence_invariants(evidence)


def test_lock_outcomes_owner_redaction_and_futex_operations_are_lossless() -> None:
    foreign_owner = domain.TaskIdentity.external_redacted()
    events: tuple[domain.TraceEvent, ...] = (
        domain.LockEvent(
            event_id="lock-wait",
            sequence=0,
            timestamp_ns=10,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.EXACT,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.LockAction.WAIT,
            lock_id=LOCK_ID,
            owner=foreign_owner,
            owner_scope=domain.TraceScope.FOREIGN,
        ),
        domain.LockEvent(
            event_id="lock-timeout",
            sequence=1,
            timestamp_ns=20,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.EXACT,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.LockAction.WAIT_ENDED,
            lock_id=LOCK_ID,
            wait_outcome=domain.LockWaitOutcome.TIMED_OUT,
        ),
        domain.LockEvent(
            event_id="legacy-acquired",
            sequence=2,
            timestamp_ns=30,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.EXACT,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.LockAction.ACQUIRED,
            lock_id=LOCK_ID,
        ),
        domain.LockEvent(
            event_id="lock-release",
            sequence=3,
            timestamp_ns=40,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.EXACT,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.LockAction.RELEASED,
            lock_id=LOCK_ID,
        ),
        domain.FutexEvent(
            event_id="futex-wait-bitset",
            sequence=4,
            timestamp_ns=50,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.CANDIDATE,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.FutexAction.WAIT,
            futex_id=LOCK_ID,
            operation=domain.FutexOperation.WAIT_BITSET,
        ),
        domain.FutexEvent(
            event_id="futex-requeue",
            sequence=5,
            timestamp_ns=60,
            cpu=0,
            target=TARGET,
            semantics=domain.EvidenceSemantics.CANDIDATE,
            task=TARGET_TASK,
            task_scope=domain.TraceScope.TARGET,
            action=domain.FutexAction.WAKE,
            futex_id=LOCK_ID,
            operation=domain.FutexOperation.REQUEUE,
            wake_count=2,
        ),
    )
    parsed = TraceStreamParseResult(
        events=events,
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=len(events)),
    )

    evidence = _build(parsed, mode="lock")

    wait = evidence.events[0]
    timeout = evidence.events[1]
    acquired = evidence.events[2]
    futex_wait = evidence.events[4]
    futex_wake = evidence.events[5]
    assert isinstance(wait, public.LockWaitEvent)
    assert wait.owner_target_tid is None
    assert isinstance(timeout, public.LockWaitEndedEvent)
    assert timeout.outcome == "timed_out"
    assert isinstance(acquired, public.LockWaitEndedEvent)
    assert acquired.outcome == "acquired"
    assert isinstance(evidence.events[3], public.LockReleasedEvent)
    assert isinstance(futex_wait, public.FutexWaitEvent)
    assert futex_wait.operation == "wait_bitset"
    assert isinstance(futex_wake, public.FutexWakeEvent)
    assert futex_wake.operation == "requeue"
    assert futex_wake.woken_count == 2
    assert futex_wait.semantics == "candidate"
    validate_trace_evidence_invariants(evidence)


def test_successful_lock_phase_enrichment_is_conserved_without_degrading_quality() -> None:
    wait = domain.LockEvent(
        event_id="lock-wait-begin",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=domain.TraceScope.TARGET,
        action=domain.LockAction.WAIT,
        lock_id=LOCK_ID,
    )
    ended = domain.LockEvent(
        event_id="lock-wait-end",
        sequence=1,
        timestamp_ns=20,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=domain.TraceScope.TARGET,
        action=domain.LockAction.WAIT_ENDED,
        lock_id=LOCK_ID,
        wait_outcome=domain.LockWaitOutcome.ACQUIRED,
    )
    parsed = TraceStreamParseResult(
        events=(wait, ended),
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=2, lock_phase_enrichment=1),
    )

    evidence = _build(parsed, mode="lock")

    assert evidence.quality.input_event_count == 3
    assert evidence.quality.emitted_event_count == 2
    assert evidence.quality.merged_enrichment_event_count == 1
    assert evidence.quality.quality_status == "verified"
    assert evidence.status == "complete"
    validate_trace_evidence_invariants(evidence)


def test_raw_or_manifest_tampering_and_export_overflow_fail_closed() -> None:
    switch = domain.SchedSwitchEvent(
        event_id="bounded-switch",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        previous=TARGET_TASK,
        previous_scope=domain.TraceScope.TARGET,
        next=DYNAMIC_TASK,
        next_scope=domain.TraceScope.TARGET,
        previous_state="running",
    )
    parsed = TraceStreamParseResult(
        events=(switch,),
        observed_target_tids=(4242, 4243),
        statistics=_statistics(emitted=1),
    )
    source = _source()

    with pytest.raises(PerfLensError) as raw_error:
        build_trace_evidence(
            source=source,
            verified_raw=replace(_snapshot(), output_sha256="d" * 64),
            parsed=parsed,
            conversion=_conversion(),
            target=TARGET,
            observation_window=public.TraceObservationWindow(
                start_timestamp_ns=0,
                end_timestamp_ns=100,
                source="collector_monotonic_bounds",
            ),
            limits=public.TraceResourceLimits(),
            perflens_version="0.3.0",
        )
    assert raw_error.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    tampered_manifest = _conversion().model_copy(
        update={"conversion_fingerprint": "d" * 64}
    )
    with pytest.raises(PerfLensError) as manifest_error:
        build_trace_evidence(
            source=source,
            verified_raw=_snapshot(),
            parsed=parsed,
            conversion=tampered_manifest,
            target=TARGET,
            observation_window=public.TraceObservationWindow(
                start_timestamp_ns=0,
                end_timestamp_ns=100,
                source="collector_monotonic_bounds",
            ),
            limits=public.TraceResourceLimits(),
            perflens_version="0.3.0",
        )
    assert manifest_error.value.code is ErrorCode.PROFILE_PARSE_FAILED

    with pytest.raises(PerfLensError) as limit_error:
        _build(
            parsed,
            limits=public.TraceResourceLimits(max_exported_events=1),
        )
    assert limit_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_malformed_foreign_identity_is_rejected_without_echoing_it() -> None:
    unsafe_foreign = domain.TaskIdentity(pid=991122, tid=991123)
    switch = domain.SchedSwitchEvent(
        event_id="malicious-foreign",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        previous=TARGET_TASK,
        previous_scope=domain.TraceScope.TARGET,
        next=unsafe_foreign,
        next_scope=domain.TraceScope.FOREIGN,
        previous_state="running",
    )
    parsed = TraceStreamParseResult(
        events=(switch,),
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=1),
    )

    with pytest.raises(PerfLensError) as captured:
        _build(parsed)

    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert "991122" not in str(captured.value)
    assert "991123" not in str(captured.value)


def test_every_parser_degradation_is_preserved_as_an_explicit_limitation() -> None:
    migration = domain.SchedMigrateEvent(
        event_id="migration-with-degraded-input",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=domain.TraceScope.TARGET,
        origin_cpu=0,
        destination_cpu=1,
    )
    diagnostic = TraceParseDiagnostic(
        code="BOUNDED_DIAGNOSTIC",
        line_number=1,
        message="bounded parser diagnostic",
    )
    statistics = TraceParseStatistics(
        input_bytes=128,
        input_line_count=9,
        input_event_count=9,
        emitted_event_count=1,
        lost_event_count=1,
        malformed_event_count=1,
        duplicate_event_count=1,
        out_of_order_event_count=1,
        unsupported_event_count=1,
        truncated_event_count=1,
        foreign_event_dropped_count=1,
        provisional_enrichment_event_count=1,
        lock_phase_enrichment_event_count=1,
        diagnostic_count=2,
        diagnostics=(diagnostic,),
        diagnostics_truncated=True,
    )
    parsed = TraceStreamParseResult(
        events=(migration,),
        observed_target_tids=(4242,),
        statistics=statistics,
    )

    evidence = _build(parsed)

    assert isinstance(evidence.events[0], public.SchedMigrateEvent)
    assert evidence.status == "partial"
    assert evidence.quality.quality_status == "partial"
    assert evidence.quality.merged_enrichment_event_count == 2
    assert evidence.quality.lost_event_count == 1
    assert evidence.quality.malformed_event_count == 1
    assert evidence.quality.duplicate_event_count == 1
    assert evidence.quality.out_of_order_event_count == 1
    assert evidence.quality.unsupported_event_count == 1
    assert evidence.quality.truncated_event_count == 1
    assert evidence.quality.foreign_event_dropped_count == 1
    assert evidence.quality.diagnostics_truncated is True
    assert len(evidence.quality.limitations) == 9
    validate_trace_evidence_invariants(evidence)


def test_builder_rejects_wrong_adapter_source_cpu_stack_and_observed_tid_set() -> None:
    migration = domain.SchedMigrateEvent(
        event_id="bounded-migration",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=domain.TraceScope.TARGET,
        origin_cpu=0,
        destination_cpu=1,
    )
    parsed = TraceStreamParseResult(
        events=(migration,),
        observed_target_tids=(4242,),
        statistics=_statistics(emitted=1),
    )
    source = _source().model_copy(update={"output_format": "target_filtered_trace_ndjson"})
    with pytest.raises(PerfLensError, match="source format"):
        build_trace_evidence(
            source=source,
            verified_raw=_snapshot(),
            parsed=parsed,
            conversion=_conversion(),
            target=TARGET,
            observation_window=public.TraceObservationWindow(
                start_timestamp_ns=0,
                end_timestamp_ns=100,
                source="collector_monotonic_bounds",
            ),
            limits=public.TraceResourceLimits(),
            perflens_version="0.3.0",
        )

    for unsafe_event in (
        replace(migration, cpu=None),
        replace(migration, stack=("private unreviewed frame",)),
    ):
        unsafe = TraceStreamParseResult(
            events=(unsafe_event,),
            observed_target_tids=(4242,),
            statistics=_statistics(emitted=1),
        )
        with pytest.raises(PerfLensError) as captured:
            _build(unsafe)
        assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED

    noncanonical_tids = TraceStreamParseResult(
        events=(migration,),
        observed_target_tids=(4242, 4242),
        statistics=_statistics(emitted=1),
    )
    with pytest.raises(PerfLensError, match="non-canonical"):
        _build(noncanonical_tids)


@pytest.mark.parametrize(
    ("limits", "expected"),
    (
        (public.TraceResourceLimits(max_input_bytes=1), "raw trace"),
        (public.TraceResourceLimits(max_input_lines=1), "input_lines"),
        (public.TraceResourceLimits(max_input_events=1), "input_events"),
        (public.TraceResourceLimits(max_diagnostics=1), "diagnostics"),
    ),
)
def test_builder_enforces_each_private_transcript_limit(
    limits: public.TraceResourceLimits,
    expected: str,
) -> None:
    migration = domain.SchedMigrateEvent(
        event_id="bounded-limit-migration",
        sequence=0,
        timestamp_ns=10,
        cpu=0,
        target=TARGET,
        semantics=domain.EvidenceSemantics.EXACT,
        task=TARGET_TASK,
        task_scope=domain.TraceScope.TARGET,
        origin_cpu=0,
        destination_cpu=1,
    )
    diagnostic = TraceParseDiagnostic(
        code="LIMIT_DIAGNOSTIC",
        line_number=1,
        message="bounded",
    )
    parsed = TraceStreamParseResult(
        events=(migration,),
        observed_target_tids=(4242,),
        statistics=TraceParseStatistics(
            input_bytes=128,
            input_line_count=2,
            input_event_count=2,
            emitted_event_count=1,
            lost_event_count=0,
            malformed_event_count=1,
            duplicate_event_count=0,
            out_of_order_event_count=0,
            unsupported_event_count=0,
            truncated_event_count=0,
            foreign_event_dropped_count=0,
            provisional_enrichment_event_count=0,
            lock_phase_enrichment_event_count=0,
            diagnostic_count=2,
            diagnostics=(diagnostic,),
            diagnostics_truncated=True,
        ),
    )

    with pytest.raises(PerfLensError) as captured:
        _build(parsed, limits=limits)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert expected in captured.value.message
