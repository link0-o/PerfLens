"""Independent, bounded verification for deterministic trace analyses."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Literal

from perflens.application.evidence import contract_content_sha256
from perflens.application.trace_evidence import (
    VerifiedPrivateRawSnapshot,
    canonical_trace_json_sha256,
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    compute_trace_evidence_content_sha256,
    compute_trace_evidence_fingerprint,
    normalized_trace_ndjson_identity,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    LockHoldInterval,
    LockProjectionAggregate,
    NanosecondDistribution,
    OffCpuAnalysisArtifact,
    OffCpuInterval,
    RunnableLatencyInterval,
    SchedulerAnalysisArtifact,
    TraceAnalysisVerificationArtifact,
    TraceEvidenceArtifact,
    TraceQuality,
    TraceVerificationCheck,
    TraceVerificationCheckName,
    event_id_ledger_sha256,
)
from perflens.domain.errors import ErrorCode, PerfLensError

type TraceAnalysisArtifact = (
    SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact
)
type VerificationStatus = Literal["passed", "failed", "skipped"]
_ANALYSIS_FINGERPRINT_DOMAIN = "perflens.trace-analysis.v1"
_VERIFICATION_FINGERPRINT_DOMAIN = "perflens.trace-verification.v1"
_VERIFIER_VERSION = "trace-verifier-v1"
_CHECK_ORDER: tuple[TraceVerificationCheckName, ...] = (
    "raw_evidence_identity",
    "conversion_manifest",
    "target_scope",
    "event_count_conservation",
    "time_interval_conservation",
    "analysis_aggregate_conservation",
    "loss_truncation_consistency",
    "agent_visible_content_sha256",
)


def compute_trace_analysis_fingerprint(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> str:
    """Bind an analyzer kind and policy to one immutable TraceEvidence snapshot."""
    material = {
        "domain": _ANALYSIS_FINGERPRINT_DOMAIN,
        "schema_version": analysis.schema_version,
        "analysis_artifact_type": type(analysis).__name__,
        "analyzer_version": analysis.analyzer_version,
        "mode": analysis.mode,
        "trace_evidence_id": evidence.trace_evidence_id,
        "trace_evidence_fingerprint": evidence.evidence_fingerprint,
        "trace_evidence_content_sha256": evidence.content_sha256,
        "trace_evidence_content_bytes": len(serialize_json(evidence)),
        "normalized_ndjson_sha256": evidence.normalized_ndjson_sha256,
        "target": analysis.target,
        "conversion_fingerprint": compute_trace_conversion_fingerprint(
            analysis.conversion
        ),
        "clock": analysis.clock,
        "observation_window": analysis.observation_window,
        "limits": analysis.limits,
        "allowed_conclusions": analysis.allowed_conclusions,
        "forbidden_conclusions": analysis.forbidden_conclusions,
        "verifier_semantics": _VERIFIER_VERSION,
    }
    return canonical_trace_json_sha256(material)


def compute_trace_analysis_content_sha256(analysis: TraceAnalysisArtifact) -> str:
    """Bind every Agent-visible Analysis field except the digest itself."""
    return contract_content_sha256(analysis, exclude={"content_sha256"})


def compute_trace_verification_fingerprint(
    *,
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
    agent_visible_content_sha256: str,
    checks: Sequence[TraceVerificationCheck],
) -> str:
    material = {
        "domain": _VERIFICATION_FINGERPRINT_DOMAIN,
        "verifier_version": _VERIFIER_VERSION,
        "analysis_artifact_type": type(analysis).__name__,
        "analysis_id": _analysis_id(analysis),
        "analysis_content_sha256": analysis.content_sha256,
        "agent_visible_content_sha256": agent_visible_content_sha256,
        "trace_evidence_id": evidence.trace_evidence_id,
        "trace_evidence_content_sha256": evidence.content_sha256,
        "checks": checks,
    }
    return canonical_trace_json_sha256(material)


def compute_trace_verification_content_sha256(
    verification: TraceAnalysisVerificationArtifact,
) -> str:
    return contract_content_sha256(verification, exclude={"content_sha256"})


def verify_trace_analysis_artifact(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
    *,
    private_raw_snapshot: VerifiedPrivateRawSnapshot | None = None,
) -> TraceAnalysisVerificationArtifact:
    """Return every deterministic check; callers separately gate failed evidence.

    ``private_raw_snapshot`` can only be produced by the safe Broker-side descriptor re-hash.
    Ordinary MCP callers pass ``None`` and receive an explicit skipped raw-identity check rather
    than a false success.  Aggregate verification always rebuilds the Analysis from public
    normalized events through the fixed deterministic analyzer; callers cannot inject a replay
    result or ask the verifier to trust stored aggregates.
    """
    check_results: dict[TraceVerificationCheckName, tuple[VerificationStatus, str]] = {}

    raw_failures = _raw_identity_failures(analysis, evidence)
    if private_raw_snapshot is not None:
        raw_failures = (
            *raw_failures,
            *_private_snapshot_failures(private_raw_snapshot, evidence),
        )
    if raw_failures:
        check_results["raw_evidence_identity"] = (
            "failed",
            _bounded_detail(raw_failures),
        )
    elif private_raw_snapshot is None:
        check_results["raw_evidence_identity"] = (
            "skipped",
            "Public digest binding passed; private raw snapshot re-hash was unavailable.",
        )
    else:
        check_results["raw_evidence_identity"] = (
            "passed",
            "Private raw identity and public digest binding match.",
        )

    _record_check(
        check_results,
        "conversion_manifest",
        _conversion_failures(analysis, evidence),
        "Conversion manifest identity and fingerprint match the evidence.",
    )
    _record_check(
        check_results,
        "target_scope",
        _target_scope_failures(analysis, evidence),
        "Every public event and aggregate remains inside the authorized target scope.",
    )
    _record_check(
        check_results,
        "event_count_conservation",
        _event_count_failures(evidence),
        "Input dispositions, normalized events, and NDJSON identity are conserved.",
    )
    _record_check(
        check_results,
        "time_interval_conservation",
        _time_interval_failures(analysis, evidence),
        "Exported trace intervals and nanosecond distributions are internally consistent.",
    )
    aggregate_failures = list(_aggregate_failures(analysis, evidence))
    aggregate_failures.extend(_replay_failures(analysis, evidence))
    _record_check(
        check_results,
        "analysis_aggregate_conservation",
        aggregate_failures,
        "Independent analyzer replay and exported aggregates match the TraceEvidence.",
    )
    quality_failures = _quality_failures(analysis, evidence)
    _record_check(
        check_results,
        "loss_truncation_consistency",
        quality_failures,
        "Loss, drops, truncation, status, and conclusion gates are consistent.",
    )

    agent_digest = compute_trace_analysis_content_sha256(analysis)
    content_failures: list[str] = []
    if analysis.content_sha256 != agent_digest:
        content_failures.append("Agent-visible Analysis SHA-256 mismatch")
    expected_fingerprint = compute_trace_analysis_fingerprint(analysis, evidence)
    if analysis.analysis_fingerprint != expected_fingerprint:
        content_failures.append("Analysis fingerprint mismatch")
    expected_id = f"{_analysis_id_prefix(analysis)}-{expected_fingerprint[:16]}"
    if _analysis_id(analysis) != expected_id:
        content_failures.append("Analysis identifier does not match its fingerprint")
    _record_check(
        check_results,
        "agent_visible_content_sha256",
        content_failures,
        "Every Agent-visible Analysis field matches its canonical content digest.",
    )

    checks = tuple(
        TraceVerificationCheck(
            name=name,
            status=check_results[name][0],
            detail=check_results[name][1],
        )
        for name in _CHECK_ORDER
    )
    statuses = {check.status for check in checks}
    verification_status: Literal["verified", "partial", "failed"]
    if "failed" in statuses:
        verification_status = "failed"
    elif "skipped" in statuses:
        verification_status = "partial"
    else:
        verification_status = "verified"

    verification_fingerprint = compute_trace_verification_fingerprint(
        analysis=analysis,
        evidence=evidence,
        agent_visible_content_sha256=agent_digest,
        checks=checks,
    )
    quality = _verification_quality(analysis.quality, verification_status)
    data = {
        "schema_version": analysis.schema_version,
        "perflens_version": analysis.perflens_version,
        "mode": analysis.mode,
        "status": analysis.status if verification_status == "verified" else "partial",
        "input_sha256": analysis.content_sha256,
        "input_bytes": len(serialize_json(analysis)),
        "source": analysis.source,
        "target": analysis.target,
        "conversion": analysis.conversion,
        "clock": analysis.clock,
        "observation_window": analysis.observation_window,
        "quality": quality,
        "limits": analysis.limits,
        "allowed_conclusions": ("trace_verification_result",),
        "forbidden_conclusions": ("performance_root_cause", "verified_improvement"),
        "content_sha256": "0" * 64,
        "verification_id": f"trace-verification-{verification_fingerprint[:16]}",
        "verification_fingerprint": verification_fingerprint,
        "verifier_version": _VERIFIER_VERSION,
        "analysis_artifact_type": type(analysis).__name__,
        "analysis_id": _analysis_id(analysis),
        "analysis_content_sha256": analysis.content_sha256,
        "analysis_content_bytes": len(serialize_json(analysis)),
        "agent_visible_content_sha256": agent_digest,
        "verification_status": verification_status,
        "checks": checks,
        "warnings": _verification_warnings(checks),
    }
    verification = TraceAnalysisVerificationArtifact.model_validate(data)
    content_sha256 = compute_trace_verification_content_sha256(verification)
    return TraceAnalysisVerificationArtifact.model_validate(
        {**verification.model_dump(mode="json"), "content_sha256": content_sha256}
    )


def require_usable_trace_analysis(
    verification: TraceAnalysisVerificationArtifact,
) -> None:
    """Prevent a failed Analysis from reaching Agent-facing tools or pagination."""
    if verification.verification_status != "failed":
        return
    failed_checks = tuple(
        check.name for check in verification.checks if check.status == "failed"
    )
    raise PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        "Trace analysis failed deterministic verification",
        details={
            "analysis_id": verification.analysis_id,
            "failed_checks": failed_checks,
        },
        suggested_actions=(
            "Do not expose this trace analysis to the Agent; rebuild it from retained evidence.",
        ),
    )


def _raw_identity_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    if evidence.input_sha256 != evidence.source.output_sha256:
        failures.append("evidence input hash differs from the private receipt")
    if evidence.input_bytes != evidence.source.output_bytes:
        failures.append("evidence input size differs from the private receipt")
    if evidence.evidence_fingerprint != compute_trace_evidence_fingerprint(evidence):
        failures.append("evidence fingerprint mismatch")
    if evidence.content_sha256 != compute_trace_evidence_content_sha256(evidence):
        failures.append("evidence Agent-visible content digest mismatch")
    if evidence.trace_evidence_id != (
        f"trace-evidence-{evidence.evidence_fingerprint[:16]}"
    ):
        failures.append("evidence identifier mismatch")
    if analysis.source != evidence.source:
        failures.append("Analysis raw-source receipt differs from TraceEvidence")
    if analysis.trace_evidence_id != evidence.trace_evidence_id:
        failures.append("Analysis TraceEvidence identifier mismatch")
    if analysis.trace_evidence_content_sha256 != evidence.content_sha256:
        failures.append("Analysis TraceEvidence content digest mismatch")
    if analysis.input_sha256 != evidence.content_sha256:
        failures.append("Analysis input digest differs from TraceEvidence content")
    evidence_bytes = len(serialize_json(evidence))
    if analysis.trace_evidence_content_bytes != evidence_bytes:
        failures.append("Analysis TraceEvidence content byte count mismatch")
    if analysis.input_bytes != evidence_bytes:
        failures.append("Analysis input byte count differs from TraceEvidence content")
    return tuple(failures)


def _private_snapshot_failures(
    snapshot: VerifiedPrivateRawSnapshot,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    expected = (
        evidence.source.collection_id,
        evidence.source.mode,
        evidence.source.collection_artifact_sha256,
        evidence.source.output_sha256,
        evidence.source.output_bytes,
        evidence.source.capture.capture_fingerprint,
    )
    actual = (
        snapshot.collection_id,
        snapshot.mode,
        snapshot.collection_artifact_sha256,
        snapshot.output_sha256,
        snapshot.output_bytes,
        snapshot.capture_fingerprint,
    )
    return () if actual == expected else ("private raw snapshot receipt mismatch",)


def _conversion_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    expected = compute_trace_conversion_fingerprint(evidence.conversion)
    if evidence.conversion.conversion_fingerprint != expected:
        failures.append("TraceEvidence conversion fingerprint mismatch")
    expected_capture = compute_trace_capture_fingerprint(evidence.source.capture)
    if evidence.source.capture.capture_fingerprint != expected_capture:
        failures.append("TraceEvidence capture fingerprint mismatch")
    if analysis.conversion != evidence.conversion:
        failures.append("Analysis conversion manifest differs from TraceEvidence")
    return tuple(failures)


def _target_scope_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    if analysis.mode != evidence.mode:
        failures.append("Analysis mode differs from TraceEvidence mode")
    if analysis.target != evidence.target:
        failures.append("Analysis target identity differs from TraceEvidence")
    allowed_tids = set(evidence.target.observed_target_tids)
    for event in evidence.events:
        if event.target_pid != evidence.target.target_pid:
            failures.append("event escaped target PID")
        if event.target_tid not in allowed_tids:
            failures.append("event escaped target TID allowlist")
        waker_tid = getattr(event, "waker_target_tid", None)
        owner_tid = getattr(event, "owner_target_tid", None)
        if waker_tid is not None and waker_tid not in allowed_tids:
            failures.append("waker escaped target TID allowlist")
        if owner_tid is not None and owner_tid not in allowed_tids:
            failures.append("owner escaped target TID allowlist")
    if isinstance(analysis, SchedulerAnalysisArtifact):
        for thread in analysis.threads:
            if thread.target_tid not in allowed_tids:
                failures.append("thread aggregate escaped target TID allowlist")
            for interval in thread.worst_runnable_intervals:
                waker_tid = interval.waker_target_tid
                if waker_tid is not None and waker_tid not in allowed_tids:
                    failures.append("derived waker escaped target TID allowlist")
    elif isinstance(analysis, OffCpuAnalysisArtifact):
        for thread in analysis.threads:
            if thread.target_tid not in allowed_tids:
                failures.append("thread aggregate escaped target TID allowlist")
            for interval in thread.worst_intervals:
                waker_tid = interval.waker_target_tid
                if waker_tid is not None and waker_tid not in allowed_tids:
                    failures.append("derived waker escaped target TID allowlist")
    else:
        for lock in analysis.locks:
            for interval in lock.worst_waits:
                if interval.waiter_tid not in allowed_tids:
                    failures.append("lock waiter escaped target TID allowlist")
                if (
                    interval.owner_target_tid is not None
                    and interval.owner_target_tid not in allowed_tids
                ):
                    failures.append("lock owner escaped target TID allowlist")
            for interval in lock.worst_holds:
                if interval.holder_tid not in allowed_tids:
                    failures.append("lock holder escaped target TID allowlist")
    return tuple(dict.fromkeys(failures))


def _event_count_failures(evidence: TraceEvidenceArtifact) -> tuple[str, ...]:
    failures: list[str] = []
    quality = evidence.quality
    dropped = (
        quality.malformed_event_count
        + quality.duplicate_event_count
        + quality.out_of_order_event_count
        + quality.unsupported_event_count
        + quality.truncated_event_count
        + quality.foreign_event_dropped_count
    )
    if quality.input_event_count + quality.expanded_derived_event_count != (
        quality.emitted_event_count + quality.merged_enrichment_event_count + dropped
    ):
        failures.append("input event dispositions do not conserve the input count")
    if quality.emitted_event_count != len(evidence.events):
        failures.append("emitted event count differs from public normalized events")
    if quality.unpaired_event_count > quality.emitted_event_count:
        failures.append("unpaired event count exceeds emitted events")
    event_ids = [event.event_id for event in evidence.events]
    if len(event_ids) != len(set(event_ids)):
        failures.append("normalized event IDs are not unique")
    if tuple(event.event_index for event in evidence.events) != tuple(
        range(len(evidence.events))
    ):
        failures.append("normalized event indexes are not contiguous")
    digest, byte_count = normalized_trace_ndjson_identity(evidence.events)
    if evidence.normalized_ndjson_sha256 != digest:
        failures.append("normalized NDJSON digest mismatch")
    if evidence.normalized_ndjson_bytes != byte_count:
        failures.append("normalized NDJSON byte count mismatch")
    if evidence.normalized_ndjson_bytes > evidence.limits.max_output_bytes:
        failures.append("normalized NDJSON exceeds max_output_bytes")
    return tuple(failures)


def _time_interval_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    sort_keys = tuple(
        (event.timestamp_ns, event.cpu, event.source_sequence, event.event_id)
        for event in evidence.events
    )
    if sort_keys != tuple(sorted(sort_keys)):
        failures.append("normalized events violate canonical source ordering")
    lower = evidence.observation_window.start_timestamp_ns
    upper = evidence.observation_window.end_timestamp_ns

    if isinstance(analysis, SchedulerAnalysisArtifact):
        for thread in analysis.threads:
            failures.extend(_distribution_failures(thread.runnable_latency))
            for interval in thread.worst_runnable_intervals:
                failures.extend(_runnable_interval_failures(interval, lower, upper))
    elif isinstance(analysis, OffCpuAnalysisArtifact):
        for thread in analysis.threads:
            failures.extend(_distribution_failures(thread.off_cpu_duration))
            failures.extend(_distribution_failures(thread.blocked_duration))
            failures.extend(_distribution_failures(thread.runnable_duration))
            failures.extend(_distribution_failures(thread.unknown_duration))
            for interval in thread.worst_intervals:
                failures.extend(_off_cpu_interval_failures(interval, lower, upper))
    else:
        for lock in analysis.locks:
            failures.extend(_distribution_failures(lock.exact_wait_duration))
            failures.extend(_distribution_failures(lock.exact_hold_duration))
            for interval in lock.worst_waits:
                if interval.wait_end_timestamp_ns < interval.wait_begin_timestamp_ns:
                    failures.append("lock wait interval ends before it starts")
                if interval.wait_duration_ns != (
                    interval.wait_end_timestamp_ns - interval.wait_begin_timestamp_ns
                ):
                    failures.append("lock wait duration is inconsistent")
                failures.extend(
                    _bounds_failures(
                        interval.wait_begin_timestamp_ns,
                        interval.wait_end_timestamp_ns,
                        lower,
                        upper,
                    )
                )
            for interval in lock.worst_holds:
                failures.extend(_lock_hold_interval_failures(interval, lower, upper))
        for projection in (*analysis.thread_projections, *analysis.call_path_projections):
            failures.extend(_distribution_failures(projection.exact_wait_duration))
            failures.extend(_distribution_failures(projection.exact_hold_duration))
    return tuple(dict.fromkeys(failures))


def _aggregate_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures = list(_accounting_failures(analysis, evidence))
    if isinstance(analysis, SchedulerAnalysisArtifact):
        expected = (
            sum(thread.runtime_ns for thread in analysis.threads),
            sum(thread.run_interval_count for thread in analysis.threads),
            sum(thread.runnable_latency.total_ns for thread in analysis.threads),
            sum(thread.runnable_latency.sample_count for thread in analysis.threads),
            sum(thread.context_switch_count for thread in analysis.threads),
            sum(thread.migration_count for thread in analysis.threads),
        )
        actual = (
            analysis.total_runtime_ns,
            analysis.total_run_interval_count,
            analysis.total_runnable_wait_ns,
            analysis.total_runnable_interval_count,
            analysis.total_context_switch_count,
            analysis.total_migration_count,
        )
        if expected != actual:
            failures.append("scheduler thread aggregates do not conserve totals")
        if len({thread.target_tid for thread in analysis.threads}) != len(
            analysis.threads
        ):
            failures.append("scheduler thread aggregates are duplicated")
        exported = sum(len(thread.worst_runnable_intervals) for thread in analysis.threads)
    elif isinstance(analysis, OffCpuAnalysisArtifact):
        expected = (
            sum(thread.off_cpu_duration.total_ns for thread in analysis.threads),
            sum(thread.blocked_duration.total_ns for thread in analysis.threads),
            sum(thread.runnable_duration.total_ns for thread in analysis.threads),
            sum(thread.unknown_duration.total_ns for thread in analysis.threads),
            sum(thread.total_complete_interval_count for thread in analysis.threads),
            sum(thread.split_complete_interval_count for thread in analysis.threads),
            sum(thread.total_incomplete_interval_count for thread in analysis.threads),
        )
        actual = (
            analysis.total_off_cpu_ns,
            analysis.total_blocked_ns,
            analysis.total_runnable_ns,
            analysis.total_unknown_ns,
            analysis.total_complete_interval_count,
            analysis.split_complete_interval_count,
            analysis.total_incomplete_interval_count,
        )
        if expected != actual:
            failures.append("off-CPU thread aggregates do not conserve totals")
        if len({thread.target_tid for thread in analysis.threads}) != len(
            analysis.threads
        ):
            failures.append("off-CPU thread aggregates are duplicated")
        if analysis.total_off_cpu_ns != (
            analysis.total_blocked_ns
            + analysis.total_runnable_ns
            + analysis.total_unknown_ns
        ):
            failures.append("off-CPU duration components do not conserve total time")
        for thread in analysis.threads:
            if thread.total_complete_interval_count != thread.off_cpu_duration.sample_count:
                failures.append("off-CPU total-complete interval count mismatch")
            if thread.split_complete_interval_count != thread.blocked_duration.sample_count:
                failures.append("off-CPU blocked split count mismatch")
            if thread.split_complete_interval_count != thread.runnable_duration.sample_count:
                failures.append("off-CPU runnable split count mismatch")
            if thread.unknown_duration.sample_count != (
                thread.total_complete_interval_count
                - thread.split_complete_interval_count
            ):
                failures.append("off-CPU unknown duration count mismatch")
            if thread.off_cpu_duration.total_ns != (
                thread.blocked_duration.total_ns
                + thread.runnable_duration.total_ns
                + thread.unknown_duration.total_ns
            ):
                failures.append("off-CPU thread duration components are not conserved")
            if sum(item.interval_count for item in thread.candidate_categories) != (
                thread.total_complete_interval_count
            ):
                failures.append("off-CPU category counts do not conserve intervals")
        exported = sum(len(thread.worst_intervals) for thread in analysis.threads)
    else:
        expected = (
            sum(lock.exact_wait_count for lock in analysis.locks),
            sum(lock.exact_wait_duration.total_ns for lock in analysis.locks),
            sum(lock.exact_hold_count for lock in analysis.locks),
            sum(lock.exact_hold_duration.total_ns for lock in analysis.locks),
            sum(lock.candidate_wait_event_count for lock in analysis.locks),
            sum(lock.candidate_wake_event_count for lock in analysis.locks),
        )
        actual = (
            analysis.total_exact_wait_count,
            analysis.total_exact_wait_ns,
            analysis.total_exact_hold_count,
            analysis.total_exact_hold_ns,
            analysis.total_candidate_wait_event_count,
            analysis.total_candidate_wake_event_count,
        )
        if expected != actual:
            failures.append("lock aggregates do not conserve totals")
        if len({lock.lock_id for lock in analysis.locks}) != len(analysis.locks):
            failures.append("anonymous lock IDs are duplicated")
        for lock in analysis.locks:
            if lock.exact_wait_count != lock.exact_wait_duration.sample_count:
                failures.append("exact lock wait count differs from wait samples")
            if lock.exact_hold_count != lock.exact_hold_duration.sample_count:
                failures.append("exact lock hold count differs from hold samples")
            outcomes = tuple(row.outcome for row in lock.exact_wait_outcomes)
            if len(set(outcomes)) != len(outcomes):
                failures.append("exact lock wait outcomes are duplicated")
            if sum(row.interval_count for row in lock.exact_wait_outcomes) != (
                lock.exact_wait_count
            ):
                failures.append("exact lock wait outcomes do not conserve wait intervals")
            if sum(path.occurrence_count for path in lock.call_paths) > lock.exact_wait_count:
                failures.append("lock call-path occurrences exceed exact waits")
            if lock.lock_kind == "futex_candidate" and (
                lock.exact_wait_count or lock.exact_hold_count
            ):
                failures.append("futex candidate claims exact high-level lock intervals")
        failures.extend(_lock_projection_failures(analysis))
        exported = sum(
            len(lock.worst_waits) + len(lock.worst_holds) for lock in analysis.locks
        )
    if exported > analysis.limits.max_exported_intervals:
        failures.append("exported intervals exceed max_exported_intervals")
    return tuple(dict.fromkeys(failures))


def _accounting_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    accounting = analysis.event_accounting
    if accounting.observed_event_count != len(evidence.events):
        failures.append("analysis accounting does not cover every public event")
    if accounting.observed_event_count != analysis.quality.emitted_event_count:
        failures.append("analysis accounting differs from emitted_event_count")
    categorized = (
        accounting.consumed.total_count
        + accounting.unpaired.total_count
        + accounting.ignored.total_count
    )
    if categorized != accounting.observed_event_count:
        failures.append("analysis accounting categories do not conserve observed events")

    evidence_event_ids = {event.event_id for event in evidence.events}
    sampled_event_ids: list[str] = []
    for name, ledger in (
        ("consumed", accounting.consumed),
        ("unpaired", accounting.unpaired),
        ("ignored", accounting.ignored),
    ):
        sampled_event_ids.extend(ledger.sample_event_ids)
        if len(set(ledger.sample_event_ids)) != len(ledger.sample_event_ids):
            failures.append(f"{name} accounting sample contains duplicate event IDs")
        if not set(ledger.sample_event_ids).issubset(evidence_event_ids):
            failures.append(f"{name} accounting sample references an unknown event ID")
        expected_truncated = len(ledger.sample_event_ids) < ledger.total_count
        if ledger.sample_truncated != expected_truncated:
            failures.append(f"{name} accounting truncation flag is inconsistent")
        if not ledger.sample_truncated and ledger.all_event_ids_sha256 != (
            event_id_ledger_sha256(ledger.sample_event_ids)
        ):
            failures.append(f"{name} complete accounting ledger hash mismatch")
    if len(sampled_event_ids) != len(set(sampled_event_ids)):
        failures.append("analysis accounting samples overlap across categories")
    if analysis.quality.unpaired_event_count < accounting.unpaired.total_count:
        failures.append("analysis quality omits analyzer-discovered unpaired events")

    if accounting.warning_count < len(accounting.warnings):
        failures.append("analysis warning sample exceeds its total count")
    if accounting.warnings_truncated != (
        len(accounting.warnings) < accounting.warning_count
    ):
        failures.append("analysis warning truncation flag is inconsistent")
    if accounting.warning_count > analysis.limits.max_warnings:
        failures.append("analysis warning count exceeds max_warnings")
    if len(accounting.warnings) > analysis.limits.max_diagnostics:
        failures.append("analysis warning sample exceeds max_diagnostics")
    allowed_tids = set(evidence.target.observed_target_tids)
    for warning in accounting.warnings:
        if warning.event_id is not None and warning.event_id not in evidence_event_ids:
            failures.append("analysis warning references an unknown event ID")
        if warning.target_tid is not None and warning.target_tid not in allowed_tids:
            failures.append("analysis warning escaped the target TID scope")
    return tuple(dict.fromkeys(failures))


def _lock_projection_failures(analysis: LockAnalysisArtifact) -> tuple[str, ...]:
    failures: list[str] = []
    allowed_tids = set(analysis.target.observed_target_tids)
    thread_ids: set[int] = set()
    path_digests: set[str] = set()
    for row in analysis.thread_projections:
        if row.projection_type != "thread":
            failures.append("lock thread projection has the wrong projection type")
        if row.target_tid is None or row.target_tid not in allowed_tids:
            failures.append("lock thread projection escaped target scope")
        elif row.target_tid in thread_ids:
            failures.append("lock thread projections contain duplicate TIDs")
        else:
            thread_ids.add(row.target_tid)
        if row.call_path or row.path_resolved:
            failures.append("lock thread projection contains call-path metadata")
    for row in analysis.call_path_projections:
        if row.projection_type != "call_path":
            failures.append("lock call-path projection has the wrong projection type")
        if row.target_tid is not None:
            failures.append("lock call-path projection exposes a target TID field")
        if row.path_resolved != bool(row.call_path):
            failures.append("lock call-path resolution flag is inconsistent")
        path_digest = canonical_trace_json_sha256(row.call_path)
        if path_digest in path_digests:
            failures.append("lock call-path projections are duplicated")
        path_digests.add(path_digest)

    lock_totals = (
        sum(lock.exact_wait_duration.sample_count for lock in analysis.locks),
        sum(lock.exact_wait_duration.total_ns for lock in analysis.locks),
        sum(lock.exact_hold_duration.sample_count for lock in analysis.locks),
        sum(lock.exact_hold_duration.total_ns for lock in analysis.locks),
        sum(lock.candidate_wait_event_count for lock in analysis.locks),
        sum(lock.candidate_wake_event_count for lock in analysis.locks),
    )

    def projection_totals(
        rows: Sequence[LockProjectionAggregate],
    ) -> tuple[int, int, int, int, int, int]:
        return (
            sum(row.exact_wait_duration.sample_count for row in rows),
            sum(row.exact_wait_duration.total_ns for row in rows),
            sum(row.exact_hold_duration.sample_count for row in rows),
            sum(row.exact_hold_duration.total_ns for row in rows),
            sum(row.candidate_wait_event_count for row in rows),
            sum(row.candidate_wake_event_count for row in rows),
        )

    if projection_totals(analysis.thread_projections) != lock_totals:
        failures.append("lock thread projections do not conserve all aggregate fields")
    if projection_totals(analysis.call_path_projections) != lock_totals:
        failures.append("lock call-path projections do not conserve all aggregate fields")
    return tuple(dict.fromkeys(failures))


def _quality_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    failures: list[str] = []
    quality = evidence.quality
    analysis_quality = analysis.quality
    dropped = (
        quality.malformed_event_count
        + quality.duplicate_event_count
        + quality.out_of_order_event_count
        + quality.unsupported_event_count
        + quality.truncated_event_count
        + quality.foreign_event_dropped_count
    )
    degraded = bool(
        quality.input_event_count == 0
        or quality.emitted_event_count == 0
        or quality.lost_event_count
        or quality.unpaired_event_count
        or dropped
        or quality.diagnostics_truncated
        or evidence.diagnostic_count
        or evidence.source.capture.backend_id != "target_filtered_kernel_v1"
    )
    expected_quality = "partial" if degraded else "verified"
    expected_status = "partial" if degraded else "complete"
    if quality.quality_status != expected_quality:
        failures.append("TraceEvidence quality status contradicts loss/drop counters")
    if evidence.status != expected_status:
        failures.append("TraceEvidence status contradicts evidence quality")
    conversion_counter_fields = (
        "input_event_count",
        "emitted_event_count",
        "expanded_derived_event_count",
        "merged_enrichment_event_count",
        "lost_event_count",
        "malformed_event_count",
        "duplicate_event_count",
        "out_of_order_event_count",
        "unsupported_event_count",
        "truncated_event_count",
        "foreign_event_dropped_count",
        "diagnostics_truncated",
    )
    if any(
        getattr(analysis_quality, field) != getattr(quality, field)
        for field in conversion_counter_fields
    ):
        failures.append("Analysis changed a conversion-owned evidence counter")
    if analysis_quality.unpaired_event_count < quality.unpaired_event_count:
        failures.append("Analysis reduced the evidence unpaired-event count")
    if analysis_quality.unpaired_event_count > analysis_quality.emitted_event_count:
        failures.append("Analysis unpaired-event count exceeds emitted events")
    analysis_dropped = (
        analysis_quality.malformed_event_count
        + analysis_quality.duplicate_event_count
        + analysis_quality.out_of_order_event_count
        + analysis_quality.unsupported_event_count
        + analysis_quality.truncated_event_count
        + analysis_quality.foreign_event_dropped_count
    )
    analysis_degraded = bool(
        analysis_quality.input_event_count == 0
        or analysis_quality.emitted_event_count == 0
        or analysis_quality.lost_event_count
        or analysis_quality.unpaired_event_count
        or analysis_dropped
        or analysis_quality.diagnostics_truncated
    )
    analysis_partial = analysis_quality.quality_status == "partial"
    expected_analysis_status = "partial" if analysis_partial else "complete"
    if analysis_degraded and not analysis_partial:
        failures.append("Analysis quality status hides degraded counters")
    if analysis.status != expected_analysis_status:
        failures.append("Analysis status contradicts its quality status")
    if not set(quality.limitations).issubset(analysis_quality.limitations):
        failures.append("Analysis removed a TraceEvidence limitation")
    if degraded and not quality.limitations:
        failures.append("degraded evidence omits an explicit limitation")
    if analysis_partial and not analysis_quality.limitations:
        failures.append("partial Analysis omits an explicit limitation")
    forbidden = {item.lower() for item in analysis.forbidden_conclusions}
    allowed = {item.lower() for item in analysis.allowed_conclusions}
    if allowed & forbidden:
        failures.append("a conclusion is both allowed and forbidden")
    if any("root" in item and "cause" in item for item in allowed):
        failures.append("Analysis allows an unqualified root-cause claim")
    if any("improvement" in item for item in allowed):
        failures.append("Analysis allows an unverified improvement claim")
    if not any("root" in item and "cause" in item for item in forbidden):
        failures.append("Analysis does not forbid an unqualified root-cause claim")
    if not any("improvement" in item for item in forbidden):
        failures.append("Analysis does not forbid an unverified improvement claim")
    if analysis_partial and not any(
        "unqualified" in item or "complete" in item for item in forbidden
    ):
        failures.append("partial Analysis does not gate an unqualified conclusion")
    return tuple(failures)


def _replay_failures(
    analysis: TraceAnalysisArtifact,
    evidence: TraceEvidenceArtifact,
) -> tuple[str, ...]:
    try:
        # The local import avoids a module cycle: analyze_trace uses the canonical identity
        # helpers in this module only after it has rebuilt all aggregates from public events.
        from perflens.application.analyze_trace import build_trace_analysis

        replayed = build_trace_analysis(evidence)
    except PerfLensError as exc:
        return (f"deterministic analyzer replay failed: {exc.code}",)
    except (KeyError, TypeError, ValueError):
        return ("deterministic analyzer replay rejected normalized evidence",)
    if type(replayed) is not type(analysis):
        return ("deterministic analyzer replay returned the wrong artifact type",)
    if canonical_trace_json_sha256(_analysis_projection(replayed)) != (
        canonical_trace_json_sha256(_analysis_projection(analysis))
    ):
        return ("deterministic analyzer replay differs from the stored Analysis",)
    return ()


def _analysis_projection(analysis: TraceAnalysisArtifact) -> dict[str, object]:
    payload = analysis.model_dump(
        mode="json",
        exclude={
            "content_sha256",
            "analysis_fingerprint",
            "scheduler_analysis_id",
            "off_cpu_analysis_id",
            "lock_analysis_id",
        },
    )
    return {str(key): value for key, value in payload.items()}


def _distribution_failures(distribution: NanosecondDistribution) -> tuple[str, ...]:
    failures: list[str] = []
    values = (
        distribution.minimum_ns,
        distribution.p50_ns,
        distribution.p95_ns,
        distribution.p99_ns,
        distribution.maximum_ns,
    )
    if values != tuple(sorted(values)):
        failures.append("nanosecond distribution quantiles are not ordered")
    if distribution.sample_count == 0:
        if distribution.total_ns or distribution.mean_ns or any(values):
            failures.append("empty nanosecond distribution contains values")
        if distribution.percentiles_stable:
            failures.append("empty nanosecond distribution claims stable percentiles")
    else:
        if distribution.mean_ns != distribution.total_ns // distribution.sample_count:
            failures.append("nanosecond distribution mean mismatch")
        if distribution.total_ns < distribution.minimum_ns * distribution.sample_count:
            failures.append("nanosecond distribution total is below its minimum bound")
        if distribution.total_ns > distribution.maximum_ns * distribution.sample_count:
            failures.append("nanosecond distribution total exceeds its maximum bound")
        if distribution.sample_count < 20 and distribution.percentiles_stable:
            failures.append("low-sample distribution claims stable percentiles")
    return tuple(failures)


def _runnable_interval_failures(
    interval: RunnableLatencyInterval,
    lower: int | None,
    upper: int | None,
) -> tuple[str, ...]:
    failures: list[str] = []
    if interval.switch_in_timestamp_ns < interval.wakeup_timestamp_ns:
        failures.append("runnable interval ends before wakeup")
    if interval.duration_ns != (
        interval.switch_in_timestamp_ns - interval.wakeup_timestamp_ns
    ):
        failures.append("runnable interval duration mismatch")
    failures.extend(
        _bounds_failures(
            interval.wakeup_timestamp_ns,
            interval.switch_in_timestamp_ns,
            lower,
            upper,
        )
    )
    return tuple(failures)


def _off_cpu_interval_failures(
    interval: OffCpuInterval,
    lower: int | None,
    upper: int | None,
) -> tuple[str, ...]:
    failures: list[str] = []
    if not interval.total_complete:
        if any(
            value is not None
            for value in (
                interval.off_cpu_duration_ns,
                interval.blocked_duration_ns,
                interval.runnable_duration_ns,
                interval.unknown_duration_ns,
            )
        ):
            failures.append("total-incomplete off-CPU interval contains final durations")
        if interval.incomplete_reason is None:
            failures.append("total-incomplete off-CPU interval omits its reason")
        if interval.split_complete:
            failures.append("total-incomplete off-CPU interval claims a complete split")
    else:
        if (
            interval.switch_out_timestamp_ns is None
            or interval.switch_in_timestamp_ns is None
            or interval.off_cpu_duration_ns is None
            or interval.unknown_duration_ns is None
        ):
            failures.append("total-complete off-CPU interval omits endpoints or duration")
        else:
            expected_total = (
                interval.switch_in_timestamp_ns - interval.switch_out_timestamp_ns
            )
            if interval.off_cpu_duration_ns != expected_total:
                failures.append("off-CPU total duration mismatch")
            blocked = interval.blocked_duration_ns or 0
            runnable = interval.runnable_duration_ns or 0
            if interval.off_cpu_duration_ns != (
                blocked + runnable + interval.unknown_duration_ns
            ):
                failures.append("off-CPU blocked+runnable+unknown time is not conserved")
            failures.extend(
                _bounds_failures(
                    interval.switch_out_timestamp_ns,
                    interval.switch_in_timestamp_ns,
                    lower,
                    upper,
                )
            )
        if interval.split_complete:
            if (
                interval.wakeup_timestamp_ns is None
                or interval.blocked_duration_ns is None
                or interval.runnable_duration_ns is None
                or interval.unknown_duration_ns != 0
            ):
                failures.append("split-complete interval omits exact split components")
            elif (
                interval.switch_out_timestamp_ns is not None
                and interval.switch_in_timestamp_ns is not None
            ):
                if not (
                    interval.switch_out_timestamp_ns
                    <= interval.wakeup_timestamp_ns
                    <= interval.switch_in_timestamp_ns
                ):
                    failures.append("off-CPU wakeup lies outside its interval")
                if interval.blocked_duration_ns != (
                    interval.wakeup_timestamp_ns - interval.switch_out_timestamp_ns
                ):
                    failures.append("off-CPU blocked duration mismatch")
                if interval.runnable_duration_ns != (
                    interval.switch_in_timestamp_ns - interval.wakeup_timestamp_ns
                ):
                    failures.append("off-CPU runnable duration mismatch")
        elif interval.blocked_duration_ns is not None or interval.runnable_duration_ns is not None:
            failures.append("non-split interval contains blocked/runnable final durations")

    if interval.observed_blocked_prefix_ns is not None:
        if interval.switch_out_timestamp_ns is None or interval.wakeup_timestamp_ns is None:
            failures.append("observed blocked prefix omits an endpoint")
        elif interval.observed_blocked_prefix_ns != (
            interval.wakeup_timestamp_ns - interval.switch_out_timestamp_ns
        ):
            failures.append("observed blocked prefix is inconsistent")
    if interval.observed_runnable_suffix_ns is not None:
        if interval.wakeup_timestamp_ns is None or interval.switch_in_timestamp_ns is None:
            failures.append("observed runnable suffix omits an endpoint")
        elif interval.observed_runnable_suffix_ns != (
            interval.switch_in_timestamp_ns - interval.wakeup_timestamp_ns
        ):
            failures.append("observed runnable suffix is inconsistent")
    for timestamp in (
        interval.switch_out_timestamp_ns,
        interval.wakeup_timestamp_ns,
        interval.switch_in_timestamp_ns,
    ):
        if timestamp is not None and (
            lower is None or upper is None or timestamp < lower or timestamp > upper
        ):
            failures.append("off-CPU interval timestamp lies outside normalized evidence")
    return tuple(failures)


def _lock_hold_interval_failures(
    interval: LockHoldInterval,
    lower: int | None,
    upper: int | None,
) -> tuple[str, ...]:
    failures: list[str] = []
    if interval.release_timestamp_ns < interval.acquire_timestamp_ns:
        failures.append("lock hold interval ends before it starts")
    if interval.hold_duration_ns != (
        interval.release_timestamp_ns - interval.acquire_timestamp_ns
    ):
        failures.append("lock hold duration is inconsistent")
    failures.extend(
        _bounds_failures(
            interval.acquire_timestamp_ns,
            interval.release_timestamp_ns,
            lower,
            upper,
        )
    )
    return tuple(failures)


def _bounds_failures(
    start: int,
    end: int,
    lower: int | None,
    upper: int | None,
) -> tuple[str, ...]:
    if lower is None or upper is None:
        return ("analysis contains an interval but TraceEvidence has no events",)
    if start < lower or end > upper:
        return ("analysis interval lies outside the normalized trace window",)
    return ()


def _record_check(
    results: dict[TraceVerificationCheckName, tuple[VerificationStatus, str]],
    name: TraceVerificationCheckName,
    failures: Iterable[str],
    success: str,
) -> None:
    bounded = tuple(dict.fromkeys(failures))
    results[name] = ("failed", _bounded_detail(bounded)) if bounded else ("passed", success)


def _bounded_detail(failures: Iterable[str]) -> str:
    values = tuple(dict.fromkeys(failures))[:8]
    detail = "; ".join(values) if values else "verification failed"
    return detail[:2048]


def _analysis_id(analysis: TraceAnalysisArtifact) -> str:
    if isinstance(analysis, SchedulerAnalysisArtifact):
        return analysis.scheduler_analysis_id
    if isinstance(analysis, OffCpuAnalysisArtifact):
        return analysis.off_cpu_analysis_id
    return analysis.lock_analysis_id


def _analysis_id_prefix(analysis: TraceAnalysisArtifact) -> str:
    if isinstance(analysis, SchedulerAnalysisArtifact):
        return "scheduler-analysis"
    if isinstance(analysis, OffCpuAnalysisArtifact):
        return "off-cpu-analysis"
    return "lock-analysis"


def _verification_quality(
    quality: TraceQuality,
    verification_status: Literal["verified", "partial", "failed"],
) -> TraceQuality:
    if verification_status == "verified":
        return quality
    limitation = (
        "Trace verification failed; this Analysis is not Agent-usable."
        if verification_status == "failed"
        else "Private raw evidence was unavailable for independent re-hashing."
    )
    return TraceQuality.model_validate(
        {
            **quality.model_dump(mode="json"),
            "quality_status": "partial",
            "limitations": tuple(dict.fromkeys((*quality.limitations, limitation))),
        }
    )


def _verification_warnings(
    checks: Sequence[TraceVerificationCheck],
) -> tuple[str, ...]:
    return tuple(
        f"{check.name}: {check.detail}"
        for check in checks
        if check.status in {"failed", "skipped"}
    )
