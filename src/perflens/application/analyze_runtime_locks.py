"""Build deterministic public analyses from normalized Runtime Lock evidence."""

from __future__ import annotations

from typing import cast

from perflens.application.runtime_lock_evidence import (
    validate_runtime_lock_evidence_invariants,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts import runtime_locks as public
from perflens.domain import runtime_lock_analysis as domain
from perflens.domain.errors import ErrorCode, PerfLensError


def build_runtime_lock_analysis(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> public.RuntimeLockAnalysisArtifact:
    """Replay immutable evidence and identify one bounded Agent-visible Analysis."""

    validate_runtime_lock_evidence_invariants(evidence)
    try:
        events = runtime_lock_domain_events(evidence)
        result = domain.analyze_runtime_lock_events(
            events,
            max_exported_rows=evidence.limits.max_exported_locks,
        )
        provisional = _analysis_artifact(evidence, result)
    except PerfLensError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "runtime_lock_analysis",
            "Normalized Runtime Lock evidence could not be analyzed deterministically",
            details={"runtime_lock_evidence_id": evidence.runtime_lock_evidence_id},
            suggested_actions=(
                "Retain the immutable source and evidence; do not expose partial aggregates.",
            ),
        ) from exc
    return _identify_analysis(provisional, evidence)


def runtime_lock_domain_events(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> tuple[domain.RuntimeLockEvent, ...]:
    """Convert public contracts to domain values without adapter-specific interpretation."""

    contexts: dict[str, domain.RuntimeExecutionContext] = {
        context.context_id: domain.RuntimeExecutionContext(
            kind=domain.RuntimeContextKind(context.kind),
            context_id=context.context_id,
            target_tid=context.target_tid,
        )
        for context in evidence.execution_contexts
    }
    legacy_contexts: dict[int, domain.RuntimeExecutionContext] = {}

    def legacy_context(tid: int) -> domain.RuntimeExecutionContext:
        value = legacy_contexts.get(tid)
        if value is None:
            value = domain.RuntimeExecutionContext(
                kind=domain.RuntimeContextKind.OS_THREAD,
                context_id=f"legacy-runtime-tid-{tid}",
                target_tid=tid,
            )
            legacy_contexts[tid] = value
        return value

    def event_context(event: public.RuntimeLockEventBase) -> domain.RuntimeExecutionContext:
        if event.execution_context_id is not None:
            return contexts[event.execution_context_id]
        if event.target_tid is None:
            raise ValueError("runtime event omitted both context and legacy TID")
        return legacy_context(event.target_tid)

    def referenced_context(
        context_id: str | None,
        target_tid: int | None,
    ) -> domain.RuntimeExecutionContext | None:
        if context_id is not None:
            return contexts[context_id]
        return legacy_context(target_tid) if target_tid is not None else None

    def convert(
        event: public.RuntimeLockEvent,
        *,
        owner_context: domain.RuntimeExecutionContext | None = None,
        wait_begin_event_id: str | None = None,
        wait_end_event_id: str | None = None,
        acquire_event_id: str | None = None,
        duration_ns: int | None = None,
        hold_duration_ns: int | None = None,
        outcome: str | None = None,
        parked_context: domain.RuntimeExecutionContext | None = None,
        observed_count: int | None = None,
        estimated_count: float | None = None,
        cumulative_wait_ns: int | None = None,
    ) -> domain.RuntimeLockEvent:
        return domain.RuntimeLockEvent(
            event_id=event.event_id,
            event_index=event.event_index,
            timestamp_ns=event.timestamp_ns,
            context=event_context(event),
            event_kind=domain.RuntimeEventKind(event.event_kind),
            measurement_semantics=domain.RuntimeMeasurementSemantics(event.measurement_semantics),
            lock_id=event.lock_id,
            lock_kind=event.lock_kind,
            stack_id=event.stack_id,
            owner_context=owner_context,
            wait_begin_event_id=wait_begin_event_id,
            wait_end_event_id=wait_end_event_id,
            acquire_event_id=acquire_event_id,
            duration_ns=duration_ns,
            hold_duration_ns=hold_duration_ns,
            outcome=outcome,
            parked_context=parked_context,
            observed_count=observed_count,
            estimated_count=estimated_count,
            cumulative_wait_ns=cumulative_wait_ns,
        )

    converted: list[domain.RuntimeLockEvent] = []
    for event in evidence.events:
        if isinstance(event, public.RuntimeWaitBeginEvent):
            converted.append(
                convert(
                    event,
                    owner_context=referenced_context(
                        event.owner_execution_context_id,
                        event.owner_target_tid,
                    ),
                )
            )
        elif isinstance(event, public.RuntimeWaitEndEvent):
            converted.append(
                convert(
                    event,
                    owner_context=referenced_context(
                        event.owner_execution_context_id,
                        event.owner_target_tid,
                    ),
                    wait_begin_event_id=event.wait_begin_event_id,
                    duration_ns=event.duration_ns,
                    outcome=event.outcome,
                )
            )
        elif isinstance(event, public.RuntimeAcquireEvent):
            converted.append(
                convert(
                    event,
                    wait_end_event_id=event.wait_end_event_id,
                )
            )
        elif isinstance(event, public.RuntimeReleaseEvent):
            converted.append(
                convert(
                    event,
                    acquire_event_id=event.acquire_event_id,
                    hold_duration_ns=event.hold_duration_ns,
                )
            )
        elif isinstance(event, public.RuntimeUnparkEvent):
            converted.append(
                convert(
                    event,
                    parked_context=referenced_context(
                        event.parked_execution_context_id,
                        event.parked_target_tid,
                    ),
                )
            )
        elif isinstance(event, public.RuntimeParkEvent):
            converted.append(convert(event))
        else:
            converted.append(
                convert(
                    event,
                    observed_count=event.observed_count,
                    estimated_count=event.estimated_count,
                    cumulative_wait_ns=event.cumulative_wait_ns,
                )
            )
    return tuple(converted)


def _distribution(
    value: domain.RuntimeDurationDistribution,
) -> public.RuntimeNanosecondDistribution:
    return public.RuntimeNanosecondDistribution(
        sample_count=value.sample_count,
        total_ns=value.total_ns,
        minimum_ns=value.minimum_ns,
        mean_ns=value.mean_ns,
        p50_ns=value.p50_ns,
        p95_ns=value.p95_ns,
        p99_ns=value.p99_ns,
        maximum_ns=value.maximum_ns,
    )


def _metrics(value: domain.RuntimeProjectionMetrics) -> dict[str, object]:
    return {
        "exact_waits": _distribution(value.exact_waits),
        "thresholded_waits": _distribution(value.thresholded_waits),
        "sampled_observation_count": value.sampled_observation_count,
        "cumulative_observation_count": value.cumulative_observation_count,
        "observed_or_estimated_wait_ns": value.observed_or_estimated_wait_ns,
        "exact_holds": _distribution(value.exact_holds),
        "owner_observed_count": value.owner_observed_count,
    }


def _coverage(page: domain.RuntimeProjectionPage) -> public.RuntimeProjectionCoverage:
    value = page.omission
    return public.RuntimeProjectionCoverage(
        total_row_count=value.total_row_count,
        exported_row_count=value.exported_row_count,
        omitted_row_count=value.omitted_row_count,
        omitted_exact_wait_count=value.omitted_exact_wait_count,
        omitted_exact_wait_ns=value.omitted_exact_wait_ns,
        omitted_thresholded_wait_count=value.omitted_thresholded_wait_count,
        omitted_thresholded_wait_ns=value.omitted_thresholded_wait_ns,
        omitted_sampled_observation_count=value.omitted_sampled_observation_count,
        omitted_cumulative_observation_count=value.omitted_cumulative_observation_count,
        omitted_observed_or_estimated_wait_ns=(value.omitted_observed_or_estimated_wait_ns),
        omitted_exact_hold_count=value.omitted_hold_count,
        omitted_exact_hold_ns=value.omitted_hold_ns,
        omitted_owner_observed_count=value.omitted_owner_observed_count,
    )


def _analysis_artifact(
    evidence: public.RuntimeLockEvidenceArtifact,
    result: domain.RuntimeLockAnalysis,
) -> public.RuntimeLockAnalysisArtifact:
    lock_rows = cast(tuple[domain.RuntimeLockProjection, ...], result.locks.rows)
    context_rows = cast(tuple[domain.RuntimeContextProjection, ...], result.contexts.rows)
    path_rows = cast(tuple[domain.RuntimeCallPathProjection, ...], result.call_paths.rows)
    outcome_rows = cast(tuple[domain.RuntimeOutcomeProjection, ...], result.outcomes.rows)
    kind_rows = cast(tuple[domain.RuntimeLockKindProjection, ...], result.lock_kinds.rows)

    aggregates = tuple(
        public.RuntimeLockAggregate.model_validate(
            {
                **_metrics(row.metrics),
                "lock_id": row.lock_id,
                "lock_kind": row.lock_kind,
                (
                    "waiter_thread_count"
                    if evidence.schema_version == "1.0"
                    else "waiter_execution_context_count"
                ): row.waiter_context_count,
                "top_stack_ids": row.top_stack_ids,
            }
        )
        for row in lock_rows
    )
    if evidence.schema_version == "1.0" and result.locks.omission.omitted_row_count:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "runtime_lock_analysis",
            "Schema 1.0 cannot conserve omitted Runtime Lock aggregate weights",
            details={
                "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
                "omitted_lock_count": result.locks.omission.omitted_row_count,
            },
            suggested_actions=("Re-import the immutable source as Runtime Lock schema 1.1.",),
        )

    partial = evidence.quality.status == "partial" or bool(result.replay.issues)
    forbidden = list(evidence.forbidden_conclusions)
    if partial and "unqualified_runtime_lock_conclusion" not in forbidden:
        forbidden.append("unqualified_runtime_lock_conclusion")
    allowed = tuple(
        conclusion for conclusion in evidence.allowed_conclusions if conclusion not in forbidden
    )
    totals = result.totals
    data: dict[str, object] = {
        "schema_version": evidence.schema_version,
        "runtime_lock_analysis_id": "runtime-lock-analysis-0000000000000000",
        "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
        "runtime_lock_evidence_content_sha256": evidence.content_sha256,
        "runtime_lock_evidence_content_bytes": len(serialize_json(evidence)),
        "created_at": evidence.created_at,
        "runtime": evidence.source.runtime,
        "measurement_semantics": evidence.source.measurement_semantics,
        "quality_status": "partial" if partial else "complete",
        "limits": evidence.limits,
        "aggregates": aggregates,
        "total_exact_wait_count": totals.exact_waits.sample_count,
        "total_exact_wait_ns": totals.exact_waits.total_ns,
        "total_thresholded_wait_count": totals.thresholded_waits.sample_count,
        "total_thresholded_wait_ns": totals.thresholded_waits.total_ns,
        "total_sampled_observation_count": totals.sampled_observation_count,
        "total_cumulative_observation_count": totals.cumulative_observation_count,
        "total_observed_or_estimated_wait_ns": totals.observed_or_estimated_wait_ns,
        "total_exact_hold_count": totals.exact_holds.sample_count,
        "total_exact_hold_ns": totals.exact_holds.total_ns,
        "total_owner_observed_count": totals.owner_observed_count,
        "omitted_lock_count": result.locks.omission.omitted_row_count,
        "allowed_conclusions": allowed,
        "forbidden_conclusions": tuple(forbidden),
        "analysis_fingerprint": "0" * 64,
        "content_sha256": "0" * 64,
        "content_bytes": 1,
    }
    if evidence.schema_version == "1.1":
        data.update(
            {
                "execution_context_aggregates": tuple(
                    public.RuntimeExecutionContextAggregate.model_validate(
                        {
                            **_metrics(row.metrics),
                            "execution_context_id": row.context.context_id,
                            "lock_count": row.lock_count,
                        }
                    )
                    for row in context_rows
                ),
                "call_path_aggregates": tuple(
                    public.RuntimeCallPathAggregate.model_validate(
                        {
                            **_metrics(row.metrics),
                            "stack_id": row.stack_id,
                            "lock_count": row.lock_count,
                            "execution_context_count": row.execution_context_count,
                        }
                    )
                    for row in path_rows
                ),
                "wait_outcome_aggregates": tuple(
                    public.RuntimeWaitOutcomeAggregate.model_validate(
                        {
                            **_metrics(row.metrics),
                            "wait_outcome": row.outcome,
                            "lock_count": row.lock_count,
                            "execution_context_count": row.execution_context_count,
                        }
                    )
                    for row in outcome_rows
                ),
                "lock_kind_aggregates": tuple(
                    public.RuntimeLockKindAggregate.model_validate(
                        {
                            **_metrics(row.metrics),
                            "lock_kind": row.lock_kind,
                            "lock_count": row.lock_count,
                            "execution_context_count": row.execution_context_count,
                        }
                    )
                    for row in kind_rows
                ),
                "lock_coverage": _coverage(result.locks),
                "execution_context_coverage": _coverage(result.contexts),
                "call_path_coverage": _coverage(result.call_paths),
                "wait_outcome_coverage": _coverage(result.outcomes),
                "lock_kind_coverage": _coverage(result.lock_kinds),
            }
        )
    return public.RuntimeLockAnalysisArtifact.model_validate(data)


def _identify_analysis(
    provisional: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
) -> public.RuntimeLockAnalysisArtifact:
    # The verifier owns canonical identity functions and imports this builder only inside replay.
    from perflens.application.verify_runtime_locks import (
        compute_runtime_lock_analysis_content_sha256,
        compute_runtime_lock_analysis_fingerprint,
    )

    fingerprint = compute_runtime_lock_analysis_fingerprint(provisional, evidence)
    data = _identity_payload(provisional)
    data.update(
        {
            "runtime_lock_analysis_id": f"runtime-lock-analysis-{fingerprint[:16]}",
            "analysis_fingerprint": fingerprint,
        }
    )
    content_bytes = 1
    for _attempt in range(8):
        candidate = public.RuntimeLockAnalysisArtifact.model_validate(
            {**data, "content_bytes": content_bytes, "content_sha256": "0" * 64}
        )
        digest = compute_runtime_lock_analysis_content_sha256(candidate)
        final = public.RuntimeLockAnalysisArtifact.model_validate(
            {
                **_identity_payload(candidate),
                "content_sha256": digest,
            }
        )
        actual_bytes = len(serialize_json(final))
        if actual_bytes == content_bytes:
            if actual_bytes > evidence.limits.max_output_bytes:
                break
            return final
        content_bytes = actual_bytes
    raise PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_lock_analysis",
        "Runtime Lock analysis exceeds its output budget",
        details={
            "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
            "max_output_bytes": evidence.limits.max_output_bytes,
        },
        suggested_actions=("Reduce the exported Runtime Lock projection limit and collect again.",),
    )


def _identity_payload(
    analysis: public.RuntimeLockAnalysisArtifact,
) -> dict[str, object]:
    """Preserve required nullable projection keys in canonical analysis payloads."""

    payload = analysis.model_dump(mode="json", exclude_none=True)
    lock_rows = payload.get("aggregates")
    if isinstance(lock_rows, list):
        typed_lock_rows = cast(list[dict[str, object]], lock_rows)
        for dumped, source in zip(typed_lock_rows, analysis.aggregates, strict=True):
            dumped["lock_id"] = source.lock_id
    call_path_rows = payload.get("call_path_aggregates")
    if isinstance(call_path_rows, list):
        typed_call_path_rows = cast(list[dict[str, object]], call_path_rows)
        for dumped, source in zip(
            typed_call_path_rows,
            analysis.call_path_aggregates,
            strict=True,
        ):
            dumped["stack_id"] = source.stack_id
    return payload
