from __future__ import annotations

import json
from typing import Any, cast

import pytest
from pydantic import ValidationError

from perflens.contracts.artifacts import VerificationCheck
from perflens.contracts.trace import (
    LockAggregate,
    LockAnalysisArtifact,
    LockWaitInterval,
    LockWaitOutcomeCount,
    NanosecondDistribution,
    OffCpuAnalysisArtifact,
    OffCpuInterval,
    OffCpuThreadAggregate,
    RunnableLatencyInterval,
    SchedMigrateEvent,
    SchedulerAnalysisArtifact,
    SchedulerThreadAggregate,
    TraceAnalysisVerificationArtifact,
    TraceCaptureManifest,
    TraceConversionManifest,
    TraceEventAccounting,
    TraceEvidenceArtifact,
    TraceQuality,
    TraceTargetIdentity,
    WaitCategoryCount,
    event_id_ledger_sha256,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _quality(*, input_events: int = 2, emitted_events: int = 2) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "quality_status": "verified",
        "input_event_count": input_events,
        "emitted_event_count": emitted_events,
        "lost_event_count": 0,
        "malformed_event_count": 0,
        "duplicate_event_count": 0,
        "out_of_order_event_count": 0,
        "unpaired_event_count": 0,
        "unsupported_event_count": 0,
        "truncated_event_count": 0,
        "foreign_event_dropped_count": 0,
        "diagnostics_truncated": False,
        "limitations": [],
    }


def _common(
    *,
    input_sha256: str = SHA_A,
    mode: str = "sched",
    quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recipe = {"sched": "sched-v1", "off_cpu": "off-cpu-v1", "lock": "lock-v1"}[mode]
    return {
        "schema_version": "1.0",
        "perflens_version": "0.3.0",
        "mode": mode,
        "status": "complete",
        "input_sha256": input_sha256,
        "input_bytes": 100,
        "source": {
            "collection_id": "collection-aaaaaaaaaaaaaaaa",
            "mode": mode,
            "collection_artifact_sha256": SHA_B,
            "output_sha256": SHA_A,
            "output_bytes": 100,
            "output_format": "perf_data",
            "capture": {
                "schema_version": "1.0",
                "mode": mode,
                "backend_id": "target_filtered_kernel_v1",
                "backend_version": "test-v1",
                "producer_path": "/usr/lib/perflens/perflens-trace-helper",
                "producer_sha256": SHA_C,
                "kernel_release": "6.12-test",
                "architecture": "x86_64",
                "byte_order": "little",
                "pointer_size_bits": 64,
                "target_scope": "kernel_tgid_filtered",
                "dynamic_thread_coverage": "complete",
                "switch_in_visibility": (
                    "not_applicable" if mode == "lock" else "complete"
                ),
                "external_wakeup_visibility": (
                    "not_applicable" if mode == "lock" else "complete"
                ),
                "foreign_metadata_before_userspace": False,
                "event_formats": [
                    {"event_name": "perflens:typed_trace", "format_sha256": SHA_B}
                ],
                "capture_fingerprint": SHA_D,
            },
        },
        "target": {
            "target_pid": 123,
            "target_uid": 1000,
            "target_start_time_ticks": 456,
            "observed_target_tids": [123],
        },
        "conversion": {
            "schema_version": "1.0",
            "adapter": "perf_script_trace",
            "recipe_id": recipe,
            "converter_path": "/usr/bin/perf",
            "converter_sha256": SHA_C,
            "converter_version": "perf version 1",
            "parser_version": "1",
            "normalization_version": "1",
            "argv": [
                "/usr/bin/perf",
                "script",
                "--force",
                "--ns",
                "--show-lost-events",
                "-F",
                "trace:pid,tid,cpu,time,event,trace",
                "-i",
                "<private-input>",
            ],
            "locale": "C",
            "output_format": "perflens_trace_ndjson_v1",
            "conversion_fingerprint": SHA_D,
        },
        "clock": {
            "clock": "monotonic",
            "unit": "nanoseconds",
            "source": "linux_perf",
        },
        "observation_window": {
            "start_timestamp_ns": 0,
            "end_timestamp_ns": 50,
            "source": "collector_monotonic_bounds",
        },
        "quality": quality or _quality(),
        "limits": {
            "max_duration_seconds": 10,
            "max_input_bytes": 1024,
            "max_input_lines": 100,
            "max_input_events": 100,
            "max_line_bytes": 4096,
            "max_stack_depth": 127,
            "max_exported_events": 100,
            "max_exported_intervals": 20,
            "max_unique_target_tids": 100,
            "max_unique_locks": 100,
            "max_diagnostics": 100,
            "max_warnings": 100,
            "max_output_bytes": 2048,
        },
        "allowed_conclusions": ["bounded trace timing distribution"],
        "forbidden_conclusions": ["unqualified performance root cause"],
        "content_sha256": SHA_B,
    }


def _distribution(*, count: int = 1, total: int = 10) -> dict[str, Any]:
    value = total if count else 0
    return {
        "sample_count": count,
        "total_ns": total,
        "minimum_ns": value,
        "mean_ns": total // count if count else 0,
        "p50_ns": value,
        "p95_ns": value,
        "p99_ns": value,
        "maximum_ns": value,
        "percentiles_stable": False,
    }


def _events() -> list[dict[str, Any]]:
    return [
        {
            "event_type": "sched_wakeup",
            "event_id": "event-aaaaaaaaaaaaaaaa",
            "event_index": 0,
            "source_sequence": 10,
            "timestamp_ns": 10,
            "cpu": 0,
            "target_pid": 123,
            "target_tid": 123,
            "semantics": "exact",
            "source_event": "sched_wakeup",
            "waker_relation": "unavailable",
            "waker_target_tid": None,
        },
        {
            "event_type": "sched_switch",
            "event_id": "event-bbbbbbbbbbbbbbbb",
            "event_index": 1,
            "source_sequence": 11,
            "timestamp_ns": 20,
            "cpu": 1,
            "target_pid": 123,
            "target_tid": 123,
            "semantics": "exact",
            "direction": "switch_in",
            "previous_state": None,
            "call_stack": [],
        },
    ]


def _ledger(event_ids: tuple[str, ...]) -> dict[str, Any]:
    return {
        "total_count": len(event_ids),
        "sample_event_ids": event_ids,
        "all_event_ids_sha256": event_id_ledger_sha256(event_ids),
        "sample_truncated": False,
    }


def _accounting(event_ids: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "observed_event_count": len(event_ids),
        "consumed": _ledger(event_ids),
        "unpaired": _ledger(()),
        "ignored": _ledger(()),
        "warning_count": 0,
        "warnings": [],
        "warnings_truncated": False,
    }


def test_trace_evidence_is_strict_frozen_and_discriminated() -> None:
    data: dict[str, Any] = {
        **_common(),
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "evidence_fingerprint": SHA_C,
        "normalized_ndjson_sha256": SHA_D,
        "normalized_ndjson_bytes": 200,
        "input_line_count": 2,
        "diagnostic_count": 0,
        "events": _events(),
    }
    artifact = TraceEvidenceArtifact.model_validate(data)

    assert artifact.schema_version == "1.0"
    assert artifact.events[0].event_type == "sched_wakeup"
    with pytest.raises(ValidationError):
        artifact.status = "partial"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        TraceEvidenceArtifact.model_validate({**data, "unexpected": True})
    with pytest.raises(ValidationError, match="raw output size"):
        TraceEvidenceArtifact.model_validate({**data, "input_bytes": 99})

    invalid_event = {**data, "events": [{**_events()[0], "event_type": "unknown"}]}
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        TraceEvidenceArtifact.model_validate(invalid_event)

    public_schema = json.dumps(TraceEvidenceArtifact.model_json_schema(), sort_keys=True)
    assert "raw_path" not in public_schema
    assert "foreign_tid" not in public_schema
    assert "foreign_pid" not in public_schema


def test_trace_quality_rejects_nonconservation_and_false_verified_status() -> None:
    nonconserved = _quality(input_events=3, emitted_events=2)
    with pytest.raises(ValidationError, match="not conserved"):
        TraceQuality.model_validate(nonconserved)

    degraded = {**_quality(), "lost_event_count": 1}
    with pytest.raises(ValidationError, match="verified trace quality"):
        TraceQuality.model_validate(degraded)

    unpaired = {
        **_quality(),
        "quality_status": "partial",
        "unpaired_event_count": 1,
        "limitations": ["one event was not paired"],
    }
    assert TraceQuality.model_validate(unpaired).emitted_event_count == 2

    unsupported = {
        **_quality(input_events=2, emitted_events=1),
        "quality_status": "partial",
        "unsupported_event_count": 1,
        "limitations": ["one event kind was unsupported"],
    }
    assert TraceQuality.model_validate(unsupported).unsupported_event_count == 1

    enrichment = {
        **_quality(input_events=3, emitted_events=2),
        "merged_enrichment_event_count": 1,
    }
    enriched = TraceQuality.model_validate(enrichment)
    assert enriched.quality_status == "verified"
    assert enriched.merged_enrichment_event_count == 1

    expanded = {
        **_quality(input_events=1, emitted_events=2),
        "expanded_derived_event_count": 1,
    }
    expanded_quality = TraceQuality.model_validate(expanded)
    assert expanded_quality.quality_status == "verified"
    assert expanded_quality.expanded_derived_event_count == 1


def test_public_conversion_manifest_rejects_private_absolute_paths() -> None:
    manifest = _common()["conversion"]
    assert isinstance(manifest, dict)
    with pytest.raises(ValidationError, match=r"private|paths"):
        TraceConversionManifest.model_validate(
            {**manifest, "argv": ["/usr/bin/perf", "script", "-i", "/private/input.data"]}
        )
    with pytest.raises(ValidationError, match=r"private|paths"):
        TraceConversionManifest.model_validate(
            {**manifest, "argv": ["/usr/bin/perf", "script", "--output=/private/result"]}
        )
    with pytest.raises(ValidationError, match=r"private|paths"):
        TraceConversionManifest.model_validate(
            {**manifest, "argv": ["/usr/bin/perf", "script", "-i", "input"]}
        )


def test_public_conversion_manifest_rejects_debug_only_perf_script_mode() -> None:
    manifest = _common()["conversion"]
    assert isinstance(manifest, dict)
    argv = list(cast(list[str], manifest["argv"]))
    argv.insert(argv.index("-F"), "--debug-mode")
    with pytest.raises(ValidationError, match="fixed versioned recipe"):
        TraceConversionManifest.model_validate({**manifest, "argv": argv})


def test_capture_manifest_rejects_false_complete_stock_pid_claims() -> None:
    capture = _common()["source"]["capture"]
    assert isinstance(capture, dict)
    with pytest.raises(ValidationError):
        TraceCaptureManifest.model_validate(
            {
                **capture,
                "backend_id": "stock_perf_pid_partial_v1",
                "target_scope": "per_task_partial",
                "dynamic_thread_coverage": "partial",
            }
        )


def test_capture_manifest_requires_kernel_filter_before_userspace() -> None:
    capture = _common()["source"]["capture"]
    assert isinstance(capture, dict)
    with pytest.raises(ValidationError):
        TraceCaptureManifest.model_validate(
            {**capture, "foreign_metadata_before_userspace": True}
        )


def test_target_tid_allowlist_is_unique_sorted_and_positive() -> None:
    base = {
        "target_pid": 123,
        "target_uid": 1000,
        "target_start_time_ticks": 456,
    }
    with pytest.raises(ValidationError, match="sorted"):
        TraceTargetIdentity.model_validate({**base, "observed_target_tids": [124, 123]})
    with pytest.raises(ValidationError, match="unique"):
        TraceTargetIdentity.model_validate({**base, "observed_target_tids": [123, 123]})


def test_trace_evidence_rejects_out_of_order_or_foreign_events() -> None:
    events = _events()
    data: dict[str, Any] = {
        **_common(),
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "evidence_fingerprint": SHA_C,
        "normalized_ndjson_sha256": SHA_D,
        "normalized_ndjson_bytes": 200,
        "input_line_count": 2,
        "diagnostic_count": 0,
        "events": events,
    }
    reversed_time = [events[0], {**events[1], "timestamp_ns": 9}]
    with pytest.raises(ValidationError, match="canonical source ordering"):
        TraceEvidenceArtifact.model_validate({**data, "events": reversed_time})

    foreign = [events[0], {**events[1], "target_pid": 999}]
    with pytest.raises(ValidationError, match="authorized target PID"):
        TraceEvidenceArtifact.model_validate({**data, "events": foreign})

    duplicate_id = [events[0], {**events[1], "event_id": events[0]["event_id"]}]
    with pytest.raises(ValidationError, match="event IDs must be unique"):
        TraceEvidenceArtifact.model_validate({**data, "events": duplicate_id})

    index_gap = [events[0], {**events[1], "event_index": 2}]
    with pytest.raises(ValidationError, match="contiguous from zero"):
        TraceEvidenceArtifact.model_validate({**data, "events": index_gap})

    reversed_source = [
        {**events[0], "timestamp_ns": 10, "source_sequence": 11},
        {**events[1], "timestamp_ns": 10, "cpu": 0, "source_sequence": 10},
    ]
    with pytest.raises(ValidationError, match="canonical source ordering"):
        TraceEvidenceArtifact.model_validate({**data, "events": reversed_source})

    escaped_tid = [{**events[0], "target_tid": 124}, events[1]]
    with pytest.raises(ValidationError, match="observed target TID"):
        TraceEvidenceArtifact.model_validate({**data, "events": escaped_tid})

    lock_common = _common(mode="lock")
    with pytest.raises(ValidationError, match="lock trace mode"):
        TraceEvidenceArtifact.model_validate({**data, **lock_common, "events": events})


def test_partial_evidence_requires_limits_and_nonempty_ndjson() -> None:
    quality = {
        **_quality(input_events=2, emitted_events=1),
        "quality_status": "partial",
        "unsupported_event_count": 1,
    }
    data = {
        **_common(quality=quality),
        "status": "partial",
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "evidence_fingerprint": SHA_C,
        "normalized_ndjson_sha256": SHA_D,
        "normalized_ndjson_bytes": 200,
        "input_line_count": 2,
        "diagnostic_count": 0,
        "events": [_events()[0]],
    }
    with pytest.raises(ValidationError, match="explicit limitation"):
        TraceEvidenceArtifact.model_validate(data)

    limited_quality = {**quality, "limitations": ["unsupported event omitted"]}
    with pytest.raises(ValidationError, match="non-empty NDJSON"):
        TraceEvidenceArtifact.model_validate(
            {**data, "quality": limited_quality, "normalized_ndjson_bytes": 0}
        )


def test_empty_evidence_cannot_claim_verified_quality() -> None:
    quality = _quality(input_events=0, emitted_events=0)
    with pytest.raises(ValidationError, match="requires emitted evidence"):
        TraceQuality.model_validate(quality)

    partial_quality = {
        **quality,
        "quality_status": "partial",
        "limitations": ["no target-scoped trace events were emitted"],
    }
    data: dict[str, Any] = {
        **_common(quality=partial_quality),
        "status": "partial",
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "evidence_fingerprint": SHA_C,
        "normalized_ndjson_sha256": SHA_D,
        "normalized_ndjson_bytes": 0,
        "input_line_count": 0,
        "diagnostic_count": 0,
        "events": [],
    }
    assert TraceEvidenceArtifact.model_validate(data).status == "partial"


def test_wakeup_and_lock_wait_completion_semantics_are_strict() -> None:
    wakeup = _events()[0]
    with pytest.raises(ValidationError, match=r"sched_wakeup|sched_wakeup_new"):
        TraceEvidenceArtifact.model_validate(
            {
                **_common(quality=_quality(input_events=1, emitted_events=1)),
                "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
                "evidence_fingerprint": SHA_C,
                "normalized_ndjson_sha256": SHA_D,
                "normalized_ndjson_bytes": 1,
                "input_line_count": 1,
                "diagnostic_count": 0,
                "events": [{**wakeup, "source_event": "sched_waking"}],
            }
        )

    lock_event: dict[str, Any] = {
        "event_type": "lock_wait_ended",
        "event_id": "event-aaaaaaaaaaaaaaaa",
        "event_index": 0,
        "source_sequence": 1,
        "timestamp_ns": 10,
        "cpu": 0,
        "target_pid": 123,
        "target_tid": 123,
        "semantics": "exact",
        "lock_id": "lock-aaaaaaaaaaaaaaaaaaaa",
        "lock_kind": "kernel_lock",
        "outcome": "timed_out",
        "call_stack": [],
    }
    artifact = TraceEvidenceArtifact.model_validate(
        {
            **_common(
                mode="lock",
                quality=_quality(input_events=1, emitted_events=1),
            ),
            "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
            "evidence_fingerprint": SHA_C,
            "normalized_ndjson_sha256": SHA_D,
            "normalized_ndjson_bytes": 1,
            "input_line_count": 1,
            "diagnostic_count": 0,
            "events": [lock_event],
        }
    )
    assert artifact.events[0].event_type == "lock_wait_ended"
    assert artifact.events[0].outcome == "timed_out"  # type: ignore[union-attr]

    migration = SchedMigrateEvent(
        event_id="event-bbbbbbbbbbbbbbbb",
        event_index=0,
        source_sequence=2,
        timestamp_ns=20,
        cpu=0,
        target_pid=123,
        target_tid=123,
        origin_cpu=0,
        destination_cpu=1,
    )
    assert migration.origin_cpu == 0
    with pytest.raises(ValidationError, match="must change CPU"):
        SchedMigrateEvent.model_validate(
            {**migration.model_dump(mode="json"), "destination_cpu": 0}
        )


def test_nanosecond_distribution_rejects_nonfinite_and_inconsistent_values() -> None:
    with pytest.raises(ValidationError):
        NanosecondDistribution.model_validate({**_distribution(), "mean_ns": float("inf")})
    with pytest.raises(ValidationError, match="quantiles must be ordered"):
        NanosecondDistribution.model_validate({**_distribution(), "p50_ns": 11})
    with pytest.raises(ValidationError, match="low-sample"):
        NanosecondDistribution.model_validate({**_distribution(), "percentiles_stable": True})


def test_analysis_event_accounting_requires_an_exact_bounded_partition() -> None:
    accounting = _accounting(("event-aaaaaaaaaaaaaaaa", "event-bbbbbbbbbbbbbbbb"))
    assert TraceEventAccounting.model_validate(accounting).observed_event_count == 2
    with pytest.raises(ValidationError, match="not conserved"):
        TraceEventAccounting.model_validate({**accounting, "observed_event_count": 3})
    with pytest.raises(ValidationError, match="categories overlap"):
        TraceEventAccounting.model_validate(
            {
                **accounting,
                "ignored": _ledger(("event-aaaaaaaaaaaaaaaa",)),
                "observed_event_count": 3,
            }
        )


def test_scheduler_analysis_enforces_aggregate_conservation() -> None:
    interval = RunnableLatencyInterval(
        target_tid=123,
        wakeup_timestamp_ns=10,
        switch_in_timestamp_ns=20,
        duration_ns=10,
    )
    thread = SchedulerThreadAggregate(
        target_tid=123,
        runtime_ns=30,
        run_interval_count=2,
        context_switch_count=2,
        migration_count=1,
        runnable_latency=NanosecondDistribution.model_validate(_distribution()),
        worst_runnable_intervals=(interval,),
    )
    data = {
        **_common(input_sha256=SHA_B),
        "scheduler_analysis_id": "scheduler-analysis-aaaaaaaaaaaaaaaa",
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "trace_evidence_content_sha256": SHA_B,
        "trace_evidence_content_bytes": 100,
        "analysis_fingerprint": SHA_C,
        "analyzer_version": "scheduler-analyzer-v1",
        "event_accounting": _accounting(("event-aaaaaaaaaaaaaaaa", "event-bbbbbbbbbbbbbbbb")),
        "threads": [thread.model_dump(mode="json")],
        "total_runtime_ns": 30,
        "total_run_interval_count": 2,
        "total_runnable_wait_ns": 10,
        "total_runnable_interval_count": 1,
        "total_context_switch_count": 2,
        "total_migration_count": 1,
    }
    assert SchedulerAnalysisArtifact.model_validate(data).total_runtime_ns == 30
    with pytest.raises(ValidationError, match="not conserved"):
        SchedulerAnalysisArtifact.model_validate({**data, "total_runtime_ns": 29})
    with pytest.raises(ValidationError, match="trace evidence content hash"):
        SchedulerAnalysisArtifact.model_validate({**data, "input_sha256": SHA_D})
    with pytest.raises(ValidationError, match="trace evidence content size"):
        SchedulerAnalysisArtifact.model_validate({**data, "input_bytes": 99})


def test_off_cpu_analysis_enforces_interval_and_aggregate_conservation() -> None:
    interval = OffCpuInterval(
        target_tid=123,
        switch_out_timestamp_ns=10,
        wakeup_timestamp_ns=15,
        switch_in_timestamp_ns=20,
        off_cpu_duration_ns=10,
        blocked_duration_ns=5,
        runnable_duration_ns=5,
        task_state="interruptible_sleep",
        candidate_wait_category="sleep",
        unknown_duration_ns=0,
        total_complete=True,
        split_complete=True,
    )
    thread = OffCpuThreadAggregate(
        target_tid=123,
        off_cpu_duration=NanosecondDistribution.model_validate(_distribution()),
        blocked_duration=NanosecondDistribution.model_validate(_distribution(total=5)),
        runnable_duration=NanosecondDistribution.model_validate(_distribution(total=5)),
        unknown_duration=NanosecondDistribution.model_validate(_distribution(count=0, total=0)),
        total_complete_interval_count=1,
        split_complete_interval_count=1,
        total_incomplete_interval_count=0,
        candidate_categories=(WaitCategoryCount(category="sleep", interval_count=1),),
        worst_intervals=(interval,),
    )
    data = {
        **_common(input_sha256=SHA_B, mode="off_cpu"),
        "off_cpu_analysis_id": "off-cpu-analysis-aaaaaaaaaaaaaaaa",
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "trace_evidence_content_sha256": SHA_B,
        "trace_evidence_content_bytes": 100,
        "analysis_fingerprint": SHA_C,
        "analyzer_version": "off-cpu-analyzer-v1",
        "event_accounting": _accounting(("event-aaaaaaaaaaaaaaaa", "event-bbbbbbbbbbbbbbbb")),
        "threads": [thread.model_dump(mode="json")],
        "total_off_cpu_ns": 10,
        "total_blocked_ns": 5,
        "total_runnable_ns": 5,
        "total_unknown_ns": 0,
        "total_complete_interval_count": 1,
        "split_complete_interval_count": 1,
        "total_incomplete_interval_count": 0,
    }
    assert OffCpuAnalysisArtifact.model_validate(data).total_off_cpu_ns == 10
    with pytest.raises(ValidationError, match="not conserved"):
        OffCpuAnalysisArtifact.model_validate({**data, "total_off_cpu_ns": 11})

    unsplit = OffCpuInterval(
        target_tid=123,
        switch_out_timestamp_ns=10,
        switch_in_timestamp_ns=20,
        off_cpu_duration_ns=10,
        unknown_duration_ns=10,
        task_state="interruptible_sleep",
        candidate_wait_category="unknown",
        total_complete=True,
        split_complete=False,
        incomplete_reason="missing_wakeup",
    )
    assert unsplit.unknown_duration_ns == unsplit.off_cpu_duration_ns
    with pytest.raises(ValidationError, match="classify all time as unknown"):
        OffCpuInterval.model_validate({**unsplit.model_dump(mode="json"), "unknown_duration_ns": 9})


def test_lock_analysis_preserves_candidate_semantics_and_conservation() -> None:
    empty = NanosecondDistribution.model_validate(_distribution(count=0, total=0))
    lock = LockAggregate(
        lock_id="lock-aaaaaaaaaaaaaaaaaaaa",
        lock_kind="futex_candidate",
        exact_wait_count=0,
        waiter_thread_count=0,
        owner_observed_count=0,
        exact_wait_duration=empty,
        exact_wait_outcomes=(),
        exact_hold_count=0,
        exact_hold_duration=empty,
        candidate_wait_event_count=1,
        candidate_wake_event_count=0,
    )
    thread_projection: dict[str, Any] = {
        "projection_type": "thread",
        "target_tid": 123,
        "call_path": [],
        "path_resolved": False,
        "exact_wait_duration": empty.model_dump(mode="json"),
        "exact_hold_duration": empty.model_dump(mode="json"),
        "candidate_wait_event_count": 1,
        "candidate_wake_event_count": 0,
    }
    path_projection: dict[str, Any] = {
        **thread_projection,
        "projection_type": "call_path",
        "target_tid": None,
    }
    data: dict[str, Any] = {
        **_common(input_sha256=SHA_B, mode="lock"),
        "lock_analysis_id": "lock-analysis-aaaaaaaaaaaaaaaa",
        "trace_evidence_id": "trace-evidence-aaaaaaaaaaaaaaaa",
        "trace_evidence_content_sha256": SHA_B,
        "trace_evidence_content_bytes": 100,
        "analysis_fingerprint": SHA_C,
        "analyzer_version": "lock-analyzer-v1",
        "event_accounting": _accounting(("event-aaaaaaaaaaaaaaaa", "event-bbbbbbbbbbbbbbbb")),
        "locks": [lock.model_dump(mode="json")],
        "thread_projections": [thread_projection],
        "call_path_projections": [path_projection],
        "total_exact_wait_count": 0,
        "total_exact_wait_ns": 0,
        "total_exact_hold_count": 0,
        "total_exact_hold_ns": 0,
        "total_candidate_wait_event_count": 1,
        "total_candidate_wake_event_count": 0,
    }
    assert LockAnalysisArtifact.model_validate(data).total_candidate_wait_event_count == 1
    invalid_lock = {
        **lock.model_dump(mode="json"),
        "exact_wait_count": 1,
        "exact_wait_duration": _distribution(),
        "exact_wait_outcomes": [{"outcome": "acquired", "interval_count": 1}],
    }
    with pytest.raises(ValidationError, match="cannot claim exact"):
        LockAnalysisArtifact.model_validate({**data, "locks": [invalid_lock]})


def test_timed_out_lock_wait_preserves_duration_without_claiming_hold() -> None:
    empty = NanosecondDistribution.model_validate(_distribution(count=0, total=0))
    wait = LockWaitInterval(
        lock_id="lock-aaaaaaaaaaaaaaaaaaaa",
        lock_kind="kernel_lock",
        waiter_tid=123,
        wait_begin_timestamp_ns=10,
        wait_end_timestamp_ns=20,
        wait_duration_ns=10,
        outcome="timed_out",
    )
    lock = LockAggregate(
        lock_id=wait.lock_id,
        lock_kind="kernel_lock",
        exact_wait_count=1,
        waiter_thread_count=1,
        owner_observed_count=0,
        exact_wait_duration=NanosecondDistribution.model_validate(_distribution()),
        exact_wait_outcomes=(
            LockWaitOutcomeCount(outcome="timed_out", interval_count=1),
        ),
        exact_hold_count=0,
        exact_hold_duration=empty,
        candidate_wait_event_count=0,
        candidate_wake_event_count=0,
        worst_waits=(wait,),
    )
    assert lock.exact_wait_outcomes[0].outcome == "timed_out"
    assert lock.exact_hold_count == 0


def test_trace_verification_status_is_derived_without_changing_profile_check() -> None:
    names = [
        "raw_evidence_identity",
        "conversion_manifest",
        "target_scope",
        "event_count_conservation",
        "time_interval_conservation",
        "analysis_aggregate_conservation",
        "loss_truncation_consistency",
        "agent_visible_content_sha256",
    ]
    checks = [{"name": name, "status": "passed", "detail": "ok"} for name in names]
    data = {
        **_common(input_sha256=SHA_B),
        "verification_id": "trace-verification-aaaaaaaaaaaaaaaa",
        "verification_fingerprint": SHA_C,
        "verifier_version": "trace-verifier-v1",
        "analysis_artifact_type": "SchedulerAnalysisArtifact",
        "analysis_id": "scheduler-analysis-aaaaaaaaaaaaaaaa",
        "analysis_content_sha256": SHA_B,
        "analysis_content_bytes": 100,
        "agent_visible_content_sha256": SHA_D,
        "verification_status": "verified",
        "checks": checks,
        "warnings": [],
    }
    artifact = TraceAnalysisVerificationArtifact.model_validate(data)
    assert artifact.verification_status == "verified"
    with pytest.raises(ValidationError, match="analysis content size"):
        TraceAnalysisVerificationArtifact.model_validate({**data, "input_bytes": 99})

    failed_checks = [
        {**check, "status": "failed"} if index == 0 else check for index, check in enumerate(checks)
    ]
    partial_quality = {**_quality(), "limitations": ["verification check failed"]}
    partial_common = {
        **data,
        "status": "partial",
        "quality": partial_quality,
        "verification_status": "failed",
    }
    assert (
        TraceAnalysisVerificationArtifact.model_validate(
            {**partial_common, "checks": failed_checks}
        ).verification_status
        == "failed"
    )

    with pytest.raises(ValidationError):
        VerificationCheck(name="legacy", status="failed", detail="must stay invalid")  # type: ignore[arg-type]
