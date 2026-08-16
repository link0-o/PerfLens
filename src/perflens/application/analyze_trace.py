"""Build public trace analyses by replaying normalized evidence through pure analyzers."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import Any, Literal, cast

from perflens.application.trace_evidence import validate_trace_evidence_invariants
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts import trace as public
from perflens.domain import trace as domain
from perflens.domain import trace_analysis as temporal
from perflens.domain import trace_lock_analysis as lock_domain
from perflens.domain.errors import ErrorCode, PerfLensError

type TraceAnalysisArtifact = (
    public.SchedulerAnalysisArtifact
    | public.OffCpuAnalysisArtifact
    | public.LockAnalysisArtifact
)

_ANALYZER_VERSION = {
    "sched": "scheduler-analyzer-v1",
    "off_cpu": "off-cpu-analyzer-v1",
    "lock": "lock-analyzer-v1",
}


def build_trace_analysis(evidence: public.TraceEvidenceArtifact) -> TraceAnalysisArtifact:
    """Run the fixed deterministic analyzer and build a content-addressed public artifact."""

    validate_trace_evidence_invariants(evidence)
    try:
        events, frames = _to_domain_events(evidence)
        resource_limits = _resource_limits(evidence.limits)
        if evidence.mode == "sched":
            result = temporal.analyze_scheduler(
                events,
                limits=_temporal_limits(evidence.limits),
                resource_limits=resource_limits,
            )
            provisional = _scheduler_artifact(evidence, result)
        elif evidence.mode == "off_cpu":
            result = temporal.analyze_off_cpu(
                events,
                limits=_temporal_limits(evidence.limits),
                resource_limits=resource_limits,
            )
            provisional = _off_cpu_artifact(evidence, result, frames)
        else:
            result = lock_domain.analyze_locks(
                events,
                limits=_lock_limits(evidence.limits),
                resource_limits=resource_limits,
            )
            provisional = _lock_artifact(evidence, result, frames)
    except PerfLensError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "trace_analysis",
            "Normalized trace evidence could not be analyzed deterministically",
            details={"trace_evidence_id": evidence.trace_evidence_id},
            suggested_actions=(
                "Retain the private source and normalized evidence; do not expose partial totals.",
            ),
        ) from exc
    return _identify_analysis(provisional, evidence)


def _to_domain_events(
    evidence: public.TraceEvidenceArtifact,
) -> tuple[tuple[domain.TraceEvent, ...], dict[str, public.TraceStackFrame]]:
    target = domain.TargetIdentity(
        pid=evidence.target.target_pid,
        uid=evidence.target.target_uid,
        start_time_ticks=evidence.target.target_start_time_ticks,
    )
    frames: dict[str, public.TraceStackFrame] = {}

    def task(tid: int) -> domain.TaskIdentity:
        return domain.TaskIdentity(pid=target.pid, tid=tid)

    def stack(values: Sequence[public.TraceStackFrame]) -> tuple[str, ...]:
        keys: list[str] = []
        for frame in values:
            from perflens.application.trace_evidence import canonical_trace_json_sha256

            key = f"frame-{canonical_trace_json_sha256(frame)}"
            existing = frames.get(key)
            if existing is not None and existing != frame:
                raise ValueError("trace frame digest collision")
            frames[key] = frame
            keys.append(key)
        return tuple(keys)

    common: dict[str, Any]
    converted: list[domain.TraceEvent] = []
    for event in evidence.events:
        common = {
            "event_id": event.event_id,
            "sequence": event.event_index,
            "timestamp_ns": event.timestamp_ns,
            "target": target,
            "semantics": domain.EvidenceSemantics(event.semantics),
            "cpu": event.cpu,
        }
        if isinstance(event, public.SchedSwitchEvent):
            target_task = task(event.target_tid)
            redacted = domain.TaskIdentity.external_redacted()
            switch_out = event.direction == "switch_out"
            converted.append(
                domain.SchedSwitchEvent(
                    **common,
                    stack=stack(event.call_stack),
                    previous=target_task if switch_out else redacted,
                    previous_scope=(
                        domain.TraceScope.TARGET
                        if switch_out
                        else domain.TraceScope.FOREIGN
                    ),
                    next=redacted if switch_out else target_task,
                    next_scope=(
                        domain.TraceScope.FOREIGN
                        if switch_out
                        else domain.TraceScope.TARGET
                    ),
                    previous_state=event.previous_state or "unknown",
                )
            )
            continue
        if isinstance(event, public.SchedWakeupEvent):
            waker: domain.TaskIdentity | None
            waker_scope: domain.TraceScope | None
            if event.waker_relation == "same_target":
                assert event.waker_target_tid is not None
                waker = task(event.waker_target_tid)
                waker_scope = domain.TraceScope.TARGET
            elif event.waker_relation == "redacted":
                waker = domain.TaskIdentity.external_redacted()
                waker_scope = domain.TraceScope.FOREIGN
            else:
                waker = None
                waker_scope = None
            converted.append(
                domain.SchedWakeupEvent(
                    **common,
                    woken=task(event.target_tid),
                    woken_scope=domain.TraceScope.TARGET,
                    source=(
                        domain.WakeupSource.WAKEUP_NEW
                        if event.source_event == "sched_wakeup_new"
                        else domain.WakeupSource.WAKEUP
                    ),
                    waker=waker,
                    waker_scope=waker_scope,
                )
            )
            continue
        if isinstance(event, public.SchedMigrateEvent):
            converted.append(
                domain.SchedMigrateEvent(
                    **common,
                    task=task(event.target_tid),
                    task_scope=domain.TraceScope.TARGET,
                    origin_cpu=event.origin_cpu,
                    destination_cpu=event.destination_cpu,
                )
            )
            continue

        target_task = task(event.target_tid)
        if isinstance(event, public.FutexWaitEvent):
            converted.append(
                domain.FutexEvent(
                    **common,
                    stack=stack(event.call_stack),
                    task=target_task,
                    task_scope=domain.TraceScope.TARGET,
                    action=domain.FutexAction.WAIT,
                    futex_id=event.lock_id,
                    operation=domain.FutexOperation(event.operation),
                )
            )
            continue
        if isinstance(event, public.FutexWakeEvent):
            converted.append(
                domain.FutexEvent(
                    **common,
                    task=target_task,
                    task_scope=domain.TraceScope.TARGET,
                    action=domain.FutexAction.WAKE,
                    futex_id=event.lock_id,
                    operation=domain.FutexOperation(event.operation),
                    wake_count=event.woken_count,
                )
            )
            continue
        if isinstance(event, public.LockWaitEvent):
            owner = (
                None
                if event.owner_target_tid is None
                else task(event.owner_target_tid)
            )
            converted.append(
                domain.LockEvent(
                    **common,
                    stack=stack(event.call_stack),
                    task=target_task,
                    task_scope=domain.TraceScope.TARGET,
                    action=domain.LockAction.WAIT,
                    lock_id=event.lock_id,
                    owner=owner,
                    owner_scope=(None if owner is None else domain.TraceScope.TARGET),
                )
            )
            continue
        if isinstance(event, public.LockWaitEndedEvent):
            converted.append(
                domain.LockEvent(
                    **common,
                    stack=stack(event.call_stack),
                    task=target_task,
                    task_scope=domain.TraceScope.TARGET,
                    action=domain.LockAction.WAIT_ENDED,
                    lock_id=event.lock_id,
                    wait_outcome=domain.LockWaitOutcome(event.outcome),
                )
            )
            continue
        released = event
        converted.append(
            domain.LockEvent(
                **common,
                stack=stack(released.call_stack),
                task=target_task,
                task_scope=domain.TraceScope.TARGET,
                action=domain.LockAction.RELEASED,
                lock_id=released.lock_id,
            )
        )
    return tuple(converted), frames


def _resource_limits(limits: public.TraceResourceLimits) -> domain.ResourceLimits:
    return domain.ResourceLimits(
        max_events=limits.max_input_events,
        max_input_lines=limits.max_input_lines,
        max_line_chars=limits.max_line_bytes,
        max_stack_depth=limits.max_stack_depth,
        max_unique_tids=limits.max_unique_target_tids,
        max_unique_locks=limits.max_unique_locks,
        max_warnings=limits.max_warnings,
        max_output_bytes=limits.max_output_bytes,
    )


def _temporal_limits(limits: public.TraceResourceLimits) -> temporal.AnalysisLimits:
    return temporal.AnalysisLimits(
        max_intervals=limits.max_exported_intervals,
        max_worst_intervals=limits.max_exported_intervals,
        max_event_ids=min(limits.max_diagnostics, limits.max_exported_events),
        max_warnings=min(limits.max_warnings, limits.max_diagnostics),
    )


def _lock_limits(limits: public.TraceResourceLimits) -> lock_domain.LockAnalysisLimits:
    return lock_domain.LockAnalysisLimits(
        max_intervals=limits.max_exported_intervals,
        max_worst_intervals=limits.max_exported_intervals,
        max_incomplete_intervals=limits.max_diagnostics,
        max_candidate_observations=limits.max_diagnostics,
        max_projection_rows=limits.max_exported_events * 3,
        max_event_ids=min(limits.max_diagnostics, limits.max_exported_events),
        max_warnings=min(limits.max_warnings, limits.max_diagnostics),
    )


def _distribution(value: temporal.DurationDistribution) -> public.NanosecondDistribution:
    return public.NanosecondDistribution(
        sample_count=value.sample_count,
        total_ns=value.total_ns,
        minimum_ns=value.minimum_ns,
        mean_ns=value.mean_ns,
        p50_ns=value.p50_ns or 0,
        p95_ns=value.p95_ns or 0,
        p99_ns=value.p99_ns or 0,
        maximum_ns=value.max_ns or 0,
        percentiles_stable=value.sample_count >= 20,
    )


def _accounting(value: temporal.EventAccounting) -> public.TraceEventAccounting:
    def ledger(item: temporal.EventIdLedger) -> public.TraceEventIdLedger:
        return public.TraceEventIdLedger(
            total_count=item.total_count,
            sample_event_ids=item.ids,
            all_event_ids_sha256=item.all_event_ids_sha256,
            sample_truncated=item.truncated,
        )

    return public.TraceEventAccounting(
        observed_event_count=value.observed_event_count,
        consumed=ledger(value.consumed),
        unpaired=ledger(value.unpaired),
        ignored=ledger(value.ignored),
        warning_count=value.warning_count,
        warnings=tuple(
            public.TraceAnalysisWarning(
                code=warning.code,
                message=warning.message,
                event_id=warning.event_id,
                target_tid=warning.tid,
            )
            for warning in value.warnings
        ),
        warnings_truncated=value.warnings_truncated,
    )


def _analysis_quality(
    evidence: public.TraceEvidenceArtifact,
    accounting: temporal.EventAccounting,
    *,
    semantic_limitations: Iterable[str] = (),
) -> tuple[public.TraceQuality, Literal["complete", "partial"]]:
    semantic_limitations = tuple(semantic_limitations)
    unpaired = max(evidence.quality.unpaired_event_count, accounting.unpaired.total_count)
    limitations = list(evidence.quality.limitations)
    if unpaired > evidence.quality.unpaired_event_count:
        limitations.append("The deterministic analyzer found unpaired normalized events.")
    limitations.extend(semantic_limitations)
    partial = evidence.status == "partial" or unpaired > 0 or bool(semantic_limitations)
    quality = public.TraceQuality.model_validate(
        {
            **evidence.quality.model_dump(mode="json"),
            "quality_status": "partial" if partial else "verified",
            "unpaired_event_count": unpaired,
            "limitations": tuple(dict.fromkeys(limitations)),
        }
    )
    return quality, "partial" if partial else "complete"


def _common_data(
    evidence: public.TraceEvidenceArtifact,
    accounting: temporal.EventAccounting,
    *,
    semantic_limitations: Iterable[str] = (),
) -> dict[str, object]:
    quality, status = _analysis_quality(
        evidence,
        accounting,
        semantic_limitations=semantic_limitations,
    )
    evidence_bytes = len(serialize_json(evidence))
    return {
        "schema_version": evidence.schema_version,
        "perflens_version": evidence.perflens_version,
        "mode": evidence.mode,
        "status": status,
        "input_sha256": evidence.content_sha256,
        "input_bytes": evidence_bytes,
        "source": evidence.source,
        "target": evidence.target,
        "conversion": evidence.conversion,
        "clock": evidence.clock,
        "observation_window": evidence.observation_window,
        "quality": quality,
        "limits": evidence.limits,
        "allowed_conclusions": evidence.allowed_conclusions,
        "forbidden_conclusions": evidence.forbidden_conclusions,
        "content_sha256": "0" * 64,
        "trace_evidence_id": evidence.trace_evidence_id,
        "trace_evidence_content_sha256": evidence.content_sha256,
        "trace_evidence_content_bytes": evidence_bytes,
        "analysis_fingerprint": "0" * 64,
        "analyzer_version": _ANALYZER_VERSION[evidence.mode],
        "event_accounting": _accounting(accounting),
    }


def _scheduler_artifact(
    evidence: public.TraceEvidenceArtifact,
    result: temporal.SchedulerAnalysis,
) -> public.SchedulerAnalysisArtifact:
    event_by_id = {event.event_id: event for event in evidence.events}
    threads: list[public.SchedulerThreadAggregate] = []
    for item in result.threads:
        worst = tuple(
            public.RunnableLatencyInterval(
                target_tid=interval.tid,
                wakeup_timestamp_ns=interval.wakeup_timestamp_ns,
                switch_in_timestamp_ns=interval.switch_in_timestamp_ns,
                duration_ns=interval.duration_ns,
                waker_target_tid=_waker_tid(event_by_id.get(interval.wakeup_event_id)),
            )
            for interval in result.worst_runnable_latencies
            if interval.tid == item.tid
        )
        threads.append(
            public.SchedulerThreadAggregate(
                target_tid=item.tid,
                runtime_ns=item.runtime.total_ns,
                run_interval_count=item.runtime.sample_count,
                context_switch_count=item.switch_in_count + item.switch_out_count,
                migration_count=item.migration_count,
                runnable_latency=_distribution(item.runnable_latency),
                worst_runnable_intervals=worst,
            )
        )
    common = _common_data(
        evidence,
        result.event_accounting,
        semantic_limitations=(
            ("Scheduler transitions were incomplete or ambiguous.",)
            if any(item.incomplete_transition_count for item in result.threads)
            else ()
        ),
    )
    return public.SchedulerAnalysisArtifact.model_validate(
        {
            **common,
            "scheduler_analysis_id": "scheduler-analysis-0000000000000000",
            "threads": threads,
            "total_runtime_ns": sum(item.runtime.total_ns for item in result.threads),
            "total_run_interval_count": result.runtime_interval_count,
            "total_runnable_wait_ns": sum(
                item.runnable_latency.total_ns for item in result.threads
            ),
            "total_runnable_interval_count": result.runnable_latency_interval_count,
            "total_context_switch_count": sum(
                item.switch_in_count + item.switch_out_count for item in result.threads
            ),
            "total_migration_count": sum(item.migration_count for item in result.threads),
        }
    )


def _off_cpu_artifact(
    evidence: public.TraceEvidenceArtifact,
    result: temporal.OffCpuAnalysis,
    frames: dict[str, public.TraceStackFrame],
) -> public.OffCpuAnalysisArtifact:
    event_by_id = {event.event_id: event for event in evidence.events}
    threads: list[public.OffCpuThreadAggregate] = []
    for item in result.threads:
        worst = tuple(
            _off_cpu_interval(interval, event_by_id, frames)
            for interval in result.worst_intervals
            if interval.tid == item.tid
        )
        categories = tuple(
            public.WaitCategoryCount(
                category=category.category.value,
                interval_count=category.interval_count,
            )
            for category in item.candidate_categories
        )
        threads.append(
            public.OffCpuThreadAggregate(
                target_tid=item.tid,
                off_cpu_duration=_distribution(item.off_cpu),
                blocked_duration=_distribution(item.blocked),
                runnable_duration=_distribution(item.runnable),
                unknown_duration=_distribution(item.unknown),
                total_complete_interval_count=item.total_complete_interval_count,
                split_complete_interval_count=item.split_complete_interval_count,
                total_incomplete_interval_count=item.total_incomplete_interval_count,
                candidate_categories=categories,
                worst_intervals=worst,
            )
        )
    limitations: list[str] = []
    if result.total_incomplete_interval_count:
        limitations.append("Some off-CPU intervals lacked a switch-out or switch-in endpoint.")
    if result.split_complete_interval_count < result.total_complete_interval_count:
        limitations.append(
            "Some total-complete off-CPU intervals lacked an exact blocked/runnable split."
        )
    common = _common_data(
        evidence,
        result.event_accounting,
        semantic_limitations=limitations,
    )
    return public.OffCpuAnalysisArtifact.model_validate(
        {
            **common,
            "off_cpu_analysis_id": "off-cpu-analysis-0000000000000000",
            "threads": threads,
            "total_off_cpu_ns": sum(item.off_cpu.total_ns for item in result.threads),
            "total_blocked_ns": sum(item.blocked.total_ns for item in result.threads),
            "total_runnable_ns": sum(item.runnable.total_ns for item in result.threads),
            "total_unknown_ns": sum(item.unknown.total_ns for item in result.threads),
            "total_complete_interval_count": result.total_complete_interval_count,
            "split_complete_interval_count": result.split_complete_interval_count,
            "total_incomplete_interval_count": result.total_incomplete_interval_count,
        }
    )


def _off_cpu_interval(
    interval: temporal.OffCpuInterval,
    event_by_id: dict[str, public.TraceEvent],
    frames: dict[str, public.TraceStackFrame],
) -> public.OffCpuInterval:
    wakeup = (
        event_by_id.get(interval.wakeup_event_ids[0])
        if len(interval.wakeup_event_ids) == 1
        else None
    )
    return public.OffCpuInterval(
        target_tid=interval.tid,
        switch_out_timestamp_ns=interval.switch_out_timestamp_ns,
        wakeup_timestamp_ns=interval.wakeup_timestamp_ns,
        switch_in_timestamp_ns=interval.switch_in_timestamp_ns,
        off_cpu_duration_ns=interval.total_duration_ns,
        blocked_duration_ns=interval.blocked_duration_ns,
        runnable_duration_ns=interval.runnable_duration_ns,
        unknown_duration_ns=interval.unknown_duration_ns,
        observed_blocked_prefix_ns=interval.observed_blocked_prefix_ns,
        observed_runnable_suffix_ns=interval.observed_runnable_suffix_ns,
        task_state=interval.previous_state,
        candidate_wait_category=interval.candidate_wait_category.value,
        waker_target_tid=_waker_tid(wakeup),
        switch_out_call_stack=_decode_path(interval.switch_out_stack, frames),
        total_complete=interval.completeness is temporal.IntervalCompleteness.COMPLETE,
        split_complete=interval.split_complete,
        incomplete_reason=(
            None if interval.incomplete_reason is None else interval.incomplete_reason.value
        ),
    )


def _lock_artifact(
    evidence: public.TraceEvidenceArtifact,
    result: lock_domain.LockAnalysis,
    frames: dict[str, public.TraceStackFrame],
) -> public.LockAnalysisArtifact:
    source_events = tuple(evidence.events)
    wait_by_lock: dict[str, list[lock_domain.ExactLockWaitInterval]] = defaultdict(list)
    hold_by_lock: dict[str, list[lock_domain.ExactLockHoldInterval]] = defaultdict(list)
    for interval in result.worst_wait_intervals:
        wait_by_lock[interval.lock_id].append(interval)
    for interval in result.worst_hold_intervals:
        hold_by_lock[interval.lock_id].append(interval)

    locks: list[public.LockAggregate] = []
    for item in result.locks:
        waits = wait_by_lock[item.lock_id]
        holds = hold_by_lock[item.lock_id]
        path_counts = Counter(interval.path for interval in waits if interval.path)
        locks.append(
            public.LockAggregate(
                lock_id=item.lock_id,
                lock_kind=_lock_kind(source_events, item.lock_id),
                exact_wait_count=item.exact_wait.sample_count,
                waiter_thread_count=len({interval.tid for interval in waits}),
                owner_observed_count=sum(
                    interval.owner_evidence is not lock_domain.OwnerEvidence.UNAVAILABLE
                    for interval in waits
                ),
                exact_wait_duration=_distribution(item.exact_wait),
                exact_wait_outcomes=tuple(
                    public.LockWaitOutcomeCount(
                        outcome=entry.outcome.value,
                        interval_count=entry.count,
                    )
                    for entry in item.wait_outcomes
                ),
                exact_hold_count=item.exact_hold.sample_count,
                exact_hold_duration=_distribution(item.exact_hold),
                candidate_wait_event_count=item.candidate_wait_count,
                candidate_wake_event_count=item.candidate_wake_count,
                worst_waits=tuple(
                    _lock_wait_interval(interval, source_events, frames) for interval in waits
                ),
                worst_holds=tuple(_lock_hold_interval(interval, frames) for interval in holds),
                call_paths=tuple(
                    public.TraceCallPathAggregate(
                        frames=_decode_path(path, frames),
                        occurrence_count=count,
                    )
                    for path, count in sorted(path_counts.items())
                ),
            )
        )

    thread_projections = tuple(
        public.LockProjectionAggregate(
            projection_type="thread",
            target_tid=item.tid,
            path_resolved=False,
            exact_wait_duration=_distribution(item.exact_wait),
            exact_hold_duration=_distribution(item.exact_hold),
            candidate_wait_event_count=item.candidate_wait_count,
            candidate_wake_event_count=item.candidate_wake_count,
        )
        for item in result.threads
    )
    call_path_projections = tuple(
        public.LockProjectionAggregate(
            projection_type="call_path",
            call_path=_decode_path(item.path, frames),
            path_resolved=item.path_resolved,
            exact_wait_duration=_distribution(item.exact_wait),
            exact_hold_duration=_distribution(item.exact_hold),
            candidate_wait_event_count=item.candidate_wait_count,
            candidate_wake_event_count=item.candidate_wake_count,
        )
        for item in result.paths
    )
    limitations: list[str] = []
    if result.incomplete_pairing_count:
        limitations.append("Some lock events could not be paired exactly.")
    if result.candidate_event_count:
        limitations.append("Futex observations remain user-lock candidates, not exact locks.")
    if any(entry.outcome is domain.LockWaitOutcome.UNKNOWN for entry in result.wait_outcomes):
        limitations.append("Some exact lock waits ended with an unknown outcome.")
    common = _common_data(
        evidence,
        result.event_accounting,
        semantic_limitations=limitations,
    )
    return public.LockAnalysisArtifact.model_validate(
        {
            **common,
            "lock_analysis_id": "lock-analysis-0000000000000000",
            "locks": locks,
            "thread_projections": thread_projections,
            "call_path_projections": call_path_projections,
            "total_exact_wait_count": result.exact_wait_interval_count,
            "total_exact_wait_ns": result.exact_wait.total_ns,
            "total_exact_hold_count": result.exact_hold_interval_count,
            "total_exact_hold_ns": result.exact_hold.total_ns,
            "total_candidate_wait_event_count": result.candidate_wait_event_count,
            "total_candidate_wake_event_count": result.candidate_wake_event_count,
        }
    )


def _lock_wait_interval(
    interval: lock_domain.ExactLockWaitInterval,
    events: Sequence[public.TraceEvent],
    frames: dict[str, public.TraceStackFrame],
) -> public.LockWaitInterval:
    return public.LockWaitInterval(
        lock_id=interval.lock_id,
        lock_kind=_lock_kind(events, interval.lock_id),
        waiter_tid=interval.tid,
        owner_target_tid=(
            interval.owner_tid
            if interval.owner_evidence is lock_domain.OwnerEvidence.TARGET
            else None
        ),
        wait_begin_timestamp_ns=interval.wait_timestamp_ns,
        wait_end_timestamp_ns=interval.wait_end_timestamp_ns,
        wait_duration_ns=interval.duration_ns,
        outcome=interval.outcome.value,
        call_stack=_decode_path(interval.path, frames),
    )


def _lock_hold_interval(
    interval: lock_domain.ExactLockHoldInterval,
    frames: dict[str, public.TraceStackFrame],
) -> public.LockHoldInterval:
    return public.LockHoldInterval(
        lock_id=interval.lock_id,
        holder_tid=interval.tid,
        acquire_timestamp_ns=interval.acquired_timestamp_ns,
        release_timestamp_ns=interval.released_timestamp_ns,
        hold_duration_ns=interval.duration_ns,
        call_stack=_decode_path(interval.path, frames),
    )


def _lock_kind(
    events: Sequence[public.TraceEvent],
    lock_id: str,
) -> Literal["kernel_lock", "futex_candidate", "unknown"]:
    kinds: set[str] = set()
    for event in events:
        if getattr(event, "lock_id", None) != lock_id:
            continue
        if isinstance(event, (public.FutexWaitEvent, public.FutexWakeEvent)):
            kinds.add("futex_candidate")
        else:
            kinds.add(cast(str, getattr(event, "lock_kind", "unknown")))
    if len(kinds) == 1:
        return cast(Literal["kernel_lock", "futex_candidate", "unknown"], kinds.pop())
    return "unknown"


def _decode_path(
    path: Sequence[str],
    frames: dict[str, public.TraceStackFrame],
) -> tuple[public.TraceStackFrame, ...]:
    return tuple(frames[key] for key in path)


def _waker_tid(event: public.TraceEvent | None) -> int | None:
    return (
        event.waker_target_tid
        if isinstance(event, public.SchedWakeupEvent)
        and event.waker_relation == "same_target"
        else None
    )


def _identify_analysis(
    provisional: TraceAnalysisArtifact,
    evidence: public.TraceEvidenceArtifact,
) -> TraceAnalysisArtifact:
    # Local imports avoid a module cycle: verify_trace owns the canonical analysis identity,
    # while verification imports this builder to perform mandatory independent replay.
    from perflens.application.verify_trace import (
        compute_trace_analysis_content_sha256,
        compute_trace_analysis_fingerprint,
    )

    fingerprint = compute_trace_analysis_fingerprint(provisional, evidence)
    if isinstance(provisional, public.SchedulerAnalysisArtifact):
        identified = provisional.model_copy(
            update={
                "scheduler_analysis_id": f"scheduler-analysis-{fingerprint[:16]}",
                "analysis_fingerprint": fingerprint,
            }
        )
    elif isinstance(provisional, public.OffCpuAnalysisArtifact):
        identified = provisional.model_copy(
            update={
                "off_cpu_analysis_id": f"off-cpu-analysis-{fingerprint[:16]}",
                "analysis_fingerprint": fingerprint,
            }
        )
    else:
        identified = provisional.model_copy(
            update={
                "lock_analysis_id": f"lock-analysis-{fingerprint[:16]}",
                "analysis_fingerprint": fingerprint,
            }
        )
    content_sha256 = compute_trace_analysis_content_sha256(identified)
    data = {**identified.model_dump(mode="json"), "content_sha256": content_sha256}
    final: TraceAnalysisArtifact
    if isinstance(identified, public.SchedulerAnalysisArtifact):
        final = public.SchedulerAnalysisArtifact.model_validate(data)
    elif isinstance(identified, public.OffCpuAnalysisArtifact):
        final = public.OffCpuAnalysisArtifact.model_validate(data)
    else:
        final = public.LockAnalysisArtifact.model_validate(data)
    if len(serialize_json(final)) > evidence.limits.max_output_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "trace_analysis",
            "Trace analysis exceeds max_output_bytes",
            details={"trace_evidence_id": evidence.trace_evidence_id},
            suggested_actions=(
                "Reduce the trace duration or exported interval limit and collect again.",
            ),
        )
    return final
