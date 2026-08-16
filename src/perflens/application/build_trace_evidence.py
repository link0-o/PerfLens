"""Build privacy-bounded public trace evidence from verified private inputs.

The streaming adapter deliberately returns domain objects rather than public contracts.  This
module is the only projection boundary between those objects and the Agent-visible evidence
artifact.  It revalidates all identities and limits, expands target-to-target scheduler switches
deterministically, and binds the result to the immutable raw receipt and fixed converter manifest.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, TypedDict, cast

from pydantic import ValidationError

from perflens.application.trace_evidence import (
    VerifiedPrivateRawSnapshot,
    canonical_trace_json_sha256,
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    compute_trace_evidence_content_sha256,
    compute_trace_evidence_fingerprint,
    normalized_trace_ndjson_identity,
    validate_trace_evidence_invariants,
)
from perflens.contracts import trace as public
from perflens.domain import trace as domain
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.profiles.trace_stream import TraceParseStatistics, TraceStreamParseResult

TraceMode = Literal["sched", "off_cpu", "lock"]


class _PublicEventCommon(TypedDict):
    event_id: str
    event_index: int
    source_sequence: int
    timestamp_ns: int
    cpu: int
    target_pid: int

_MODE_ALLOWED_CONCLUSIONS: dict[TraceMode, tuple[str, ...]] = {
    "sched": (
        "trace_evidence_quality_and_identity",
        "target_scheduler_transition_distribution",
    ),
    "off_cpu": (
        "trace_evidence_quality_and_identity",
        "target_off_cpu_interval_reconstruction",
    ),
    "lock": (
        "trace_evidence_quality_and_identity",
        "target_kernel_lock_wait_distribution",
        "target_futex_wait_candidates",
    ),
}
_EMPTY_ALLOWED_CONCLUSIONS = ("trace_evidence_quality_and_identity",)
_FORBIDDEN_CONCLUSIONS = (
    "performance_root_cause",
    "verified_improvement",
    "unqualified_complete_trace_conclusion",
    "system_wide_or_cross_target_behavior",
    "exact_high_level_lock_identity_from_futex_candidates",
)


def build_trace_evidence(
    *,
    source: public.TraceRawArtifactReference,
    verified_raw: VerifiedPrivateRawSnapshot,
    parsed: TraceStreamParseResult,
    conversion: public.TraceConversionManifest,
    target: domain.TargetIdentity,
    observation_window: public.TraceObservationWindow,
    limits: public.TraceResourceLimits,
    perflens_version: str,
) -> public.TraceEvidenceArtifact:
    """Project one fixed-parser result into a content-addressed public artifact.

    ``source`` is the public-safe receipt while ``verified_raw`` proves that the private file was
    re-opened and re-hashed safely.  Neither a private path nor parser diagnostics are copied into
    the returned model.
    """

    mode = source.mode
    _validate_raw_binding(source, verified_raw)
    _validate_capture(source)
    _validate_conversion(mode, conversion)
    if (
        conversion.adapter == "kernel_trace_ndjson"
        and (
            source.output_format != "target_filtered_trace_ndjson"
            or source.capture.backend_id != "target_filtered_kernel_v1"
        )
    ) or (
        conversion.adapter == "perf_script_trace" and source.output_format != "perf_data"
    ):
        raise _invalid_evidence("trace source format does not match its fixed adapter")
    _validate_parser_result(parsed, target=target, limits=limits)
    _validate_window(observation_window, limits)

    try:
        projected = _project_events(parsed.events, mode=mode, target=target)
        projected = tuple(
            event.model_copy(update={"event_index": index})
            for index, event in enumerate(projected)
        )
        observed_tids = _observed_public_tids(projected)
        authorized_tids = set(parsed.observed_target_tids)
        if not set(observed_tids).issubset(authorized_tids):
            raise _invalid_evidence("normalized trace escaped authenticated target TIDs")

        expanded_count = len(projected) - len(parsed.events)
        if expanded_count < 0:
            raise _invalid_evidence("normalized trace unexpectedly discarded parsed events")
        _validate_export_limits(
            source=source,
            parsed=parsed,
            events=projected,
            observed_tids=observed_tids,
            observation_window=observation_window,
            limits=limits,
        )

        quality = _quality(
            parsed.statistics,
            emitted_event_count=len(projected),
            expanded_derived_event_count=expanded_count,
            complete_capture=(source.capture.backend_id == "target_filtered_kernel_v1"),
        )
        status: Literal["complete", "partial"] = (
            "partial" if quality.quality_status == "partial" else "complete"
        )
        normalized_sha256, normalized_bytes = normalized_trace_ndjson_identity(projected)
        if normalized_bytes > limits.max_output_bytes:
            raise _resource_error("normalized trace output exceeds max_output_bytes")

        common = {
            "schema_version": "1.0",
            "perflens_version": perflens_version,
            "mode": mode,
            "status": status,
            "input_sha256": source.output_sha256,
            "input_bytes": source.output_bytes,
            "source": source,
            "target": public.TraceTargetIdentity(
                target_pid=target.pid,
                target_uid=target.uid,
                target_start_time_ticks=target.start_time_ticks,
                observed_target_tids=observed_tids,
            ),
            "conversion": conversion,
            "clock": public.TraceClock(
                source=(
                    "linux_bpf"
                    if source.capture.backend_id == "target_filtered_kernel_v1"
                    else "linux_perf"
                )
            ),
            "observation_window": observation_window,
            "quality": quality,
            "limits": limits,
            "allowed_conclusions": (
                _MODE_ALLOWED_CONCLUSIONS[mode] if projected else _EMPTY_ALLOWED_CONCLUSIONS
            ),
            "forbidden_conclusions": _FORBIDDEN_CONCLUSIONS,
            "content_sha256": "0" * 64,
            "trace_evidence_id": "trace-evidence-0000000000000000",
            "evidence_fingerprint": "0" * 64,
            "normalized_ndjson_sha256": normalized_sha256,
            "normalized_ndjson_bytes": normalized_bytes,
            "input_line_count": parsed.statistics.input_line_count,
            "diagnostic_count": parsed.statistics.diagnostic_count,
            "events": projected,
        }
        provisional = public.TraceEvidenceArtifact.model_validate(common)
        fingerprint = compute_trace_evidence_fingerprint(provisional)
        identified = provisional.model_copy(
            update={
                "trace_evidence_id": f"trace-evidence-{fingerprint[:16]}",
                "evidence_fingerprint": fingerprint,
            }
        )
        evidence = public.TraceEvidenceArtifact.model_validate(
            {
                **identified.model_dump(mode="json"),
                "content_sha256": compute_trace_evidence_content_sha256(identified),
            }
        )
        validate_trace_evidence_invariants(evidence)
        return evidence
    except PerfLensError:
        raise
    except (TypeError, ValueError, ValidationError):
        # Pydantic errors may contain user-controlled values.  The public error deliberately
        # suppresses both their text and exception chain so no foreign identity or path leaks.
        raise _invalid_evidence("trace evidence projection failed strict validation") from None


def _validate_raw_binding(
    source: public.TraceRawArtifactReference,
    snapshot: VerifiedPrivateRawSnapshot,
) -> None:
    if (
        snapshot.collection_id != source.collection_id
        or snapshot.mode != source.mode
        or snapshot.collection_artifact_sha256 != source.collection_artifact_sha256
        or snapshot.output_sha256 != source.output_sha256
        or snapshot.output_bytes != source.output_bytes
        or snapshot.capture_fingerprint != source.capture.capture_fingerprint
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "trace_evidence",
            "Verified private trace identity differs from its public receipt",
            recoverable=True,
            suggested_actions=(
                "Retain the private source and repeat descriptor-based source verification.",
            ),
        )


def _validate_conversion(
    mode: TraceMode,
    conversion: public.TraceConversionManifest,
) -> None:
    expected_recipe = {
        "sched": "sched-v1",
        "off_cpu": "off-cpu-v1",
        "lock": "lock-v1",
    }[mode]
    if (
        conversion.recipe_id != expected_recipe
        or conversion.conversion_fingerprint
        != compute_trace_conversion_fingerprint(conversion)
        or (
            conversion.adapter == "kernel_trace_ndjson"
            and conversion.output_format != "perflens_trace_ndjson_v1"
        )
    ):
        raise _invalid_evidence("fixed trace conversion manifest failed integrity validation")


def _validate_capture(source: public.TraceRawArtifactReference) -> None:
    capture = source.capture
    if capture.capture_fingerprint != compute_trace_capture_fingerprint(capture):
        raise _invalid_evidence("fixed trace capture manifest failed integrity validation")


def _validate_parser_result(
    parsed: TraceStreamParseResult,
    *,
    target: domain.TargetIdentity,
    limits: public.TraceResourceLimits,
) -> None:
    statistics = parsed.statistics
    if statistics.emitted_event_count != len(parsed.events):
        raise _invalid_evidence("parser event count differs from its disposition accounting")
    if tuple(sorted(set(parsed.observed_target_tids))) != parsed.observed_target_tids or any(
        isinstance(tid, bool) or tid <= 0 for tid in parsed.observed_target_tids
    ):
        raise _invalid_evidence("authenticated target TID set is non-canonical")
    if parsed.events and not parsed.observed_target_tids:
        raise _invalid_evidence("authenticated target TID set is absent or non-canonical")
    resource_limits = domain.ResourceLimits(
        max_events=limits.max_input_events,
        max_input_lines=limits.max_input_lines,
        max_line_chars=limits.max_line_bytes,
        max_stack_depth=limits.max_stack_depth,
        max_unique_tids=limits.max_unique_target_tids,
        max_unique_locks=limits.max_unique_locks,
        max_warnings=limits.max_warnings,
        max_output_bytes=limits.max_output_bytes,
    )
    try:
        domain.validate_trace_sequence(
            parsed.events,
            expected_target=target,
            input_line_count=statistics.input_line_count,
            output_bytes=statistics.input_bytes,
            limits=resource_limits,
        )
    except ValueError:
        raise _invalid_evidence("parsed trace failed independent domain validation") from None
    for event in parsed.events:
        if event.stack:
            # The current fixed event-only recipe does not define a structured, privacy-reviewed
            # stack representation.  Never reinterpret an arbitrary string as a public frame.
            raise _invalid_evidence("parsed trace contains an unsupported stack representation")


def _validate_window(
    observation_window: public.TraceObservationWindow,
    limits: public.TraceResourceLimits,
) -> None:
    duration_ns = (
        observation_window.end_timestamp_ns - observation_window.start_timestamp_ns
    )
    if duration_ns > limits.max_duration_seconds * 1_000_000_000:
        raise _resource_error("trace observation window exceeds max_duration_seconds")


def _validate_export_limits(
    *,
    source: public.TraceRawArtifactReference,
    parsed: TraceStreamParseResult,
    events: tuple[public.TraceEvent, ...],
    observed_tids: tuple[int, ...],
    observation_window: public.TraceObservationWindow,
    limits: public.TraceResourceLimits,
) -> None:
    statistics = parsed.statistics
    if source.output_bytes > limits.max_input_bytes:
        raise _resource_error("private raw trace exceeds max_input_bytes")
    if statistics.input_line_count > limits.max_input_lines:
        raise _resource_error("trace transcript exceeds max_input_lines")
    if statistics.input_event_count > limits.max_input_events:
        raise _resource_error("trace transcript exceeds max_input_events")
    if statistics.diagnostic_count > limits.max_diagnostics:
        raise _resource_error("trace diagnostics exceed max_diagnostics")
    if len(events) > limits.max_exported_events:
        raise _resource_error("normalized trace exceeds max_exported_events")
    if len(observed_tids) > limits.max_unique_target_tids:
        raise _resource_error("normalized trace exceeds max_unique_target_tids")
    unique_locks = {
        event.lock_id
        for event in events
        if isinstance(
            event,
            (
                public.LockWaitEvent,
                public.LockWaitEndedEvent,
                public.LockReleasedEvent,
                public.FutexWaitEvent,
                public.FutexWakeEvent,
            ),
        )
    }
    if len(unique_locks) > limits.max_unique_locks:
        raise _resource_error("normalized trace exceeds max_unique_locks")
    for event in events:
        if not (
            observation_window.start_timestamp_ns
            <= event.timestamp_ns
            <= observation_window.end_timestamp_ns
        ):
            raise _invalid_evidence("normalized event lies outside the observation window")
    if observation_window.source == "observed_event_bounds" and (
        not events
        or (
            events[0].timestamp_ns != observation_window.start_timestamp_ns
            or events[-1].timestamp_ns != observation_window.end_timestamp_ns
        )
    ):
        raise _invalid_evidence("observed event bounds do not match normalized evidence")


def _project_events(
    events: Iterable[domain.TraceEvent],
    *,
    mode: TraceMode,
    target: domain.TargetIdentity,
) -> tuple[public.TraceEvent, ...]:
    projected: list[public.TraceEvent] = []
    for event in events:
        if mode in {"sched", "off_cpu"}:
            if not isinstance(
                event,
                (domain.SchedSwitchEvent, domain.SchedWakeupEvent, domain.SchedMigrateEvent),
            ):
                raise _invalid_evidence("scheduler trace contains a non-scheduler event")
        elif isinstance(
            event,
            (domain.SchedSwitchEvent, domain.SchedWakeupEvent, domain.SchedMigrateEvent),
        ):
            raise _invalid_evidence("lock trace contains a scheduler event")

        source_events = _project_event(event, target=target)
        for ordinal, source_event in enumerate(source_events):
            event_id = _public_event_id(event, ordinal)
            projected.append(
                source_event.model_copy(
                    update={
                        "event_id": event_id,
                        "event_index": len(projected),
                    }
                )
            )
    return tuple(projected)


def _project_event(
    event: domain.TraceEvent,
    *,
    target: domain.TargetIdentity,
) -> tuple[public.TraceEvent, ...]:
    cpu = event.cpu
    if cpu is None:
        raise _invalid_evidence("trace event lacks a bounded CPU identity")
    common: _PublicEventCommon = {
        "event_id": "event-0000000000000000",
        "event_index": 0,
        "source_sequence": event.sequence,
        "timestamp_ns": event.timestamp_ns,
        "cpu": cpu,
        "target_pid": target.pid,
    }
    if isinstance(event, domain.SchedSwitchEvent):
        output: list[public.TraceEvent] = []
        if event.previous_scope is domain.TraceScope.TARGET:
            output.append(
                public.SchedSwitchEvent(
                    **common,
                    target_tid=_target_tid(event.previous),
                    direction="switch_out",
                    previous_state=_public_task_state(event.previous_state),
                    call_stack=(),
                )
            )
        if event.next_scope is domain.TraceScope.TARGET:
            output.append(
                public.SchedSwitchEvent(
                    **common,
                    target_tid=_target_tid(event.next),
                    direction="switch_in",
                )
            )
        if not output:
            raise _invalid_evidence("scheduler switch does not involve the authorized target")
        return tuple(output)
    if isinstance(event, domain.SchedWakeupEvent):
        if event.source is domain.WakeupSource.WAKING:
            raise _invalid_evidence("sched_waking cannot become a canonical public wakeup")
        relation: Literal["same_target", "redacted", "unavailable"]
        waker_tid: int | None
        if event.waker is None or event.waker_scope is None:
            relation, waker_tid = "unavailable", None
        elif event.waker_scope is domain.TraceScope.TARGET:
            relation, waker_tid = "same_target", _target_tid(event.waker)
        else:
            relation, waker_tid = "redacted", None
        return (
            public.SchedWakeupEvent(
                **common,
                target_tid=_target_tid(event.woken),
                source_event=(
                    "sched_wakeup_new"
                    if event.source is domain.WakeupSource.WAKEUP_NEW
                    else "sched_wakeup"
                ),
                waker_relation=relation,
                waker_target_tid=waker_tid,
            ),
        )
    if isinstance(event, domain.SchedMigrateEvent):
        return (
            public.SchedMigrateEvent(
                **common,
                target_tid=_target_tid(event.task),
                origin_cpu=event.origin_cpu,
                destination_cpu=event.destination_cpu,
            ),
        )
    if isinstance(event, domain.LockEvent):
        task_tid = _target_tid(event.task)
        if event.action is domain.LockAction.WAIT:
            owner_tid = (
                _target_tid(event.owner)
                if event.owner is not None
                and event.owner_scope is domain.TraceScope.TARGET
                else None
            )
            return (
                public.LockWaitEvent(
                    **common,
                    target_tid=task_tid,
                    lock_id=event.lock_id,
                    lock_kind="kernel_lock",
                    owner_target_tid=owner_tid,
                    call_stack=(),
                ),
            )
        if event.action in {domain.LockAction.ACQUIRED, domain.LockAction.WAIT_ENDED}:
            outcome = (
                domain.LockWaitOutcome.ACQUIRED
                if event.action is domain.LockAction.ACQUIRED
                else event.wait_outcome
            )
            if outcome is None:
                raise _invalid_evidence("lock wait completion lacks an explicit outcome")
            return (
                public.LockWaitEndedEvent(
                    **common,
                    target_tid=task_tid,
                    lock_id=event.lock_id,
                    lock_kind="kernel_lock",
                    outcome=outcome.value,
                    call_stack=(),
                ),
            )
        return (
            public.LockReleasedEvent(
                **common,
                target_tid=task_tid,
                lock_id=event.lock_id,
                lock_kind="kernel_lock",
                call_stack=(),
            ),
        )
    task_tid = _target_tid(event.task)
    if event.action is domain.FutexAction.WAIT:
        return (
            public.FutexWaitEvent(
                **common,
                target_tid=task_tid,
                lock_id=event.futex_id,
                operation=cast(
                    Literal["wait", "wait_bitset", "wait_requeue_pi", "unknown"],
                    event.operation.value,
                ),
                call_stack=(),
            ),
        )
    return (
        public.FutexWakeEvent(
            **common,
            target_tid=task_tid,
            lock_id=event.futex_id,
            operation=cast(
                Literal["wake", "wake_bitset", "requeue", "unknown"],
                event.operation.value,
            ),
            woken_count=event.wake_count,
        ),
    )


def _public_event_id(event: domain.TraceEvent, ordinal: int) -> str:
    if ordinal < 0 or ordinal > 255:
        raise _invalid_evidence("trace event expansion ordinal exceeds its fixed range")
    prefix = canonical_trace_json_sha256(
        {
            "domain": "perflens.public-trace-event.v1",
            "source_event_id": event.event_id,
            "source_sequence": event.sequence,
        }
    )[:22]
    return f"event-{prefix}{ordinal:02x}"


def _observed_public_tids(events: Iterable[public.TraceEvent]) -> tuple[int, ...]:
    tids: set[int] = set()
    for event in events:
        tids.add(event.target_tid)
        if isinstance(event, public.SchedWakeupEvent) and event.waker_target_tid is not None:
            tids.add(event.waker_target_tid)
        if isinstance(event, public.LockWaitEvent) and event.owner_target_tid is not None:
            tids.add(event.owner_target_tid)
    return tuple(sorted(tids))


def _quality(
    statistics: TraceParseStatistics,
    *,
    emitted_event_count: int,
    expanded_derived_event_count: int,
    complete_capture: bool,
) -> public.TraceQuality:
    limitations: list[str] = []
    if emitted_event_count == 0 or statistics.input_event_count == 0:
        limitations.append("No target-scoped trace event was available for analysis.")
    if statistics.lost_event_count:
        limitations.append("The kernel reported lost trace events.")
    if statistics.malformed_event_count:
        limitations.append("Malformed trace records were excluded.")
    if statistics.duplicate_event_count:
        limitations.append("Duplicate trace records were excluded.")
    if statistics.out_of_order_event_count:
        limitations.append("Out-of-order trace records were excluded.")
    if statistics.unsupported_event_count:
        limitations.append("Unsupported or unpaired trace records were excluded.")
    if statistics.truncated_event_count:
        limitations.append("Trace records were truncated by a resource limit.")
    if statistics.foreign_event_dropped_count:
        limitations.append("Foreign-task-only records were dropped before publication.")
    if statistics.diagnostic_count:
        limitations.append("The fixed parser reported one or more bounded diagnostics.")
    if statistics.diagnostics_truncated:
        limitations.append("The diagnostic sample was truncated.")
    if not complete_capture:
        limitations.append(
            "The capture backend did not prove complete target-filtered event coverage."
        )
    quality_status: Literal["verified", "partial"] = (
        "partial" if statistics.partial or not complete_capture else "verified"
    )
    return public.TraceQuality(
        quality_status=quality_status,
        input_event_count=statistics.input_event_count,
        emitted_event_count=emitted_event_count,
        expanded_derived_event_count=expanded_derived_event_count,
        merged_enrichment_event_count=(
            statistics.provisional_enrichment_event_count
            + statistics.lock_phase_enrichment_event_count
        ),
        lost_event_count=statistics.lost_event_count,
        malformed_event_count=statistics.malformed_event_count,
        duplicate_event_count=statistics.duplicate_event_count,
        out_of_order_event_count=statistics.out_of_order_event_count,
        unpaired_event_count=0,
        unsupported_event_count=statistics.unsupported_event_count,
        truncated_event_count=statistics.truncated_event_count,
        foreign_event_dropped_count=statistics.foreign_event_dropped_count,
        diagnostics_truncated=statistics.diagnostics_truncated,
        limitations=tuple(limitations),
    )


def _target_tid(task: domain.TaskIdentity) -> int:
    if task.pid is None or task.tid is None:
        raise _invalid_evidence("required target task identity was redacted")
    return task.tid


def _public_task_state(
    value: str,
) -> Literal[
    "running",
    "interruptible_sleep",
    "uninterruptible_sleep",
    "stopped",
    "traced",
    "dead",
    "parked",
    "idle",
    "unknown",
]:
    if value in {
        "running",
        "interruptible_sleep",
        "uninterruptible_sleep",
        "stopped",
        "traced",
        "dead",
        "parked",
        "idle",
    }:
        return cast(
            Literal[
                "running",
                "interruptible_sleep",
                "uninterruptible_sleep",
                "stopped",
                "traced",
                "dead",
                "parked",
                "idle",
                "unknown",
            ],
            value,
        )
    return "unknown"


def _invalid_evidence(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "trace_evidence",
        message,
        recoverable=True,
        suggested_actions=(
            "Retain the private source and do not expose this trace to an Agent.",
        ),
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "trace_evidence",
        message,
        recoverable=True,
    )
