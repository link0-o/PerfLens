"""Independent replay and integrity verification for Runtime Lock analyses."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from math import ceil
from tempfile import SpooledTemporaryFile
from typing import BinaryIO, Literal, cast

from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import (
    canonical_runtime_lock_json_sha256,
    compute_runtime_source_conversion_fingerprint,
    normalized_runtime_lock_records_identity,
    runtime_lock_evidence_invariant_failures,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts import runtime_locks as public
from perflens.domain import runtime_lock_analysis as domain
from perflens.domain.errors import ErrorCode, PerfLensError

type VerificationStatus = Literal["passed", "failed", "skipped"]
_ANALYSIS_FINGERPRINT_DOMAIN = "perflens.runtime-lock-analysis.v1.1"
_VERIFICATION_FINGERPRINT_DOMAIN = "perflens.runtime-lock-verification.v1.1"
_CHECK_ORDER = (
    "source_identity",
    "source_conversion_replay",
    "evidence_invariants",
    "conversion_replay",
    "target_scope",
    "semantic_count_conservation",
    "event_pairing",
    "wait_hold_conservation",
    "aggregate_projection_conservation",
    "agent_visible_content_sha256",
)


def compute_runtime_lock_analysis_fingerprint(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
) -> str:
    normalized_sha256, normalized_bytes = normalized_runtime_lock_records_identity(evidence)
    material = {
        "domain": _ANALYSIS_FINGERPRINT_DOMAIN,
        "schema_version": analysis.schema_version,
        "analyzer_version": (
            "runtime-lock-analyzer-v1"
            if analysis.schema_version == "1.0"
            else "runtime-lock-analyzer-v2"
        ),
        "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
        "runtime_lock_evidence_fingerprint": evidence.evidence_fingerprint,
        "runtime_lock_evidence_content_sha256": evidence.content_sha256,
        "runtime_lock_evidence_content_bytes": len(serialize_json(evidence)),
        "normalized_records_sha256": normalized_sha256,
        "normalized_records_bytes": normalized_bytes,
        "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(evidence.source),
        "runtime": analysis.runtime,
        "measurement_semantics": analysis.measurement_semantics,
        "quality_status": analysis.quality_status,
        "limits": analysis.limits,
        "allowed_conclusions": analysis.allowed_conclusions,
        "forbidden_conclusions": analysis.forbidden_conclusions,
        "projection_order": (
            "lock",
            "execution_context",
            "call_path",
            "wait_outcome",
            "lock_kind",
        ),
    }
    return canonical_runtime_lock_json_sha256(material)


def compute_runtime_lock_analysis_content_sha256(
    analysis: public.RuntimeLockAnalysisArtifact,
) -> str:
    return contract_content_sha256(analysis, exclude={"content_sha256"})


def compute_runtime_lock_verification_content_sha256(
    verification: public.RuntimeLockAnalysisVerificationArtifact,
) -> str:
    return contract_content_sha256(verification, exclude={"content_sha256"})


def build_runtime_lock_source_replay_receipt(
    evidence: public.RuntimeLockEvidenceArtifact,
    *,
    normalized_source_sha256: str | None = None,
    normalized_source_bytes: int | None = None,
) -> public.RuntimeLockSourceReplayReceipt:
    """Bind one successful private conversion replay to its public Evidence."""

    if evidence.schema_version != "1.1" or evidence.source.converter_version is None:
        raise ValueError("source replay receipts require schema 1.1 converter identity")
    if (normalized_source_sha256 is None) != (normalized_source_bytes is None):
        raise ValueError("normalized source replay identity must be supplied as one pair")
    replay_sha256, replay_bytes = normalized_runtime_lock_records_identity(evidence)
    if normalized_source_sha256 is None:
        normalized_source_sha256 = replay_sha256
    if normalized_source_bytes is None:
        normalized_source_bytes = replay_bytes
    return public.RuntimeLockSourceReplayReceipt(
        source_format=evidence.source.source_format,
        raw_source_sha256=evidence.source.source_sha256,
        raw_source_bytes=evidence.source.source_bytes,
        normalized_source_sha256=normalized_source_sha256,
        normalized_source_bytes=normalized_source_bytes,
        converter_version=evidence.source.converter_version,
        conversion_fingerprint=compute_runtime_source_conversion_fingerprint(evidence.source),
        adapter_execution_identity_sha256=(evidence.source.adapter_execution_identity_sha256),
        runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
        runtime_lock_evidence_content_sha256=evidence.content_sha256,
    )


def _verify_private_source_and_replay(
    evidence: public.RuntimeLockEvidenceArtifact,
    private_source_stream: BinaryIO,
    *,
    replay_source_format: str | None,
) -> tuple[
    list[str],
    VerificationStatus,
    str,
    public.RuntimeLockSourceReplayReceipt | None,
]:
    """Hash retained source bytes before any format-specific conversion replay."""

    failures: list[str] = []
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        with SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b") as retained:
            while True:
                chunk = private_source_stream.read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > evidence.limits.max_source_bytes:
                    failures.append("private source exceeds max_source_bytes")
                    return (
                        failures,
                        "failed",
                        "Private source conversion replay was blocked by an invalid "
                        "source receipt.",
                        None,
                    )
                digest.update(chunk)
                retained.write(chunk)
            if total_bytes != evidence.source.source_bytes:
                failures.append("private source byte count differs from immutable source receipt")
            if digest.hexdigest() != evidence.source.source_sha256:
                failures.append("private source SHA-256 differs from immutable source receipt")
            if failures:
                return (
                    failures,
                    "failed",
                    "Private source conversion replay was blocked by an invalid source receipt.",
                    None,
                )
            if replay_source_format is None:
                return (
                    failures,
                    "skipped",
                    "This source format has no Stage 1 private converter replay implementation.",
                    None,
                )

            retained.seek(0)
            retained_stream = cast(BinaryIO, retained)
            if replay_source_format == "perflens_runtime_lock_ndjson_v1":
                from perflens.runtime_locks import import_runtime_lock_ndjson

                replay_matches = (
                    import_runtime_lock_ndjson(
                        retained_stream,
                        created_at=evidence.created_at,
                        limits=evidence.limits,
                    )
                    == evidence
                )
            elif replay_source_format == "native_interposer_ndjson_v1":
                from perflens.runtime_locks.native_pthread_converter import (
                    replay_native_pthread_probe,
                )

                replay_matches = replay_native_pthread_probe(evidence, retained_stream)
            else:  # pragma: no cover - caller admits only registered formats
                raise AssertionError("unregistered Runtime Lock replay source format")
            if not replay_matches:
                return (
                    failures,
                    "failed",
                    "Private source conversion replay differs from public Runtime Lock evidence.",
                    None,
                )
            return (
                failures,
                "passed",
                "Private source conversion reproduced the complete public Runtime Lock evidence.",
                build_runtime_lock_source_replay_receipt(evidence),
            )
    except (OSError, PerfLensError, TypeError, ValueError) as exc:
        failures.append(f"private source identity replay failed: {type(exc).__name__}")
        return (
            failures,
            "failed",
            f"Private source conversion replay failed: {type(exc).__name__}.",
            None,
        )


def verify_runtime_lock_analysis_artifact(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
    *,
    private_source_stream: BinaryIO | None = None,
    source_replay_receipt: public.RuntimeLockSourceReplayReceipt | None = None,
    normalized_source_sha256: str | None = None,
    normalized_source_bytes: int | None = None,
) -> public.RuntimeLockAnalysisVerificationArtifact:
    """Rebuild every aggregate from public events and return all bounded checks."""

    results: dict[str, tuple[VerificationStatus, str]] = {}
    evidence_failures = runtime_lock_evidence_invariant_failures(evidence)

    source_failures = [
        failure
        for failure in evidence_failures
        if "fingerprint" in failure or "content" in failure or "source exceeds" in failure
    ]
    source_replay_format = (
        evidence.source.source_format
        if evidence.schema_version == "1.1"
        and evidence.source.source_format
        in {"perflens_runtime_lock_ndjson_v1", "native_interposer_ndjson_v1"}
        else None
    )
    source_conversion_status: VerificationStatus = "skipped"
    source_conversion_detail = "Private source conversion replay was unavailable."
    accepted_replay_receipt: public.RuntimeLockSourceReplayReceipt | None = None
    if private_source_stream is not None and source_replay_receipt is not None:
        source_failures.append("private source and replay receipt cannot be supplied together")
        source_conversion_status = "failed"
        source_conversion_detail = "Ambiguous private source replay inputs were rejected."
    elif private_source_stream is not None:
        raw_failures, source_conversion_status, source_conversion_detail, replay_receipt = (
            _verify_private_source_and_replay(
                evidence,
                private_source_stream,
                replay_source_format=source_replay_format,
            )
        )
        source_failures.extend(raw_failures)
        accepted_replay_receipt = (
            build_runtime_lock_source_replay_receipt(
                evidence,
                normalized_source_sha256=normalized_source_sha256,
                normalized_source_bytes=normalized_source_bytes,
            )
            if replay_receipt is not None
            else None
        )
    elif source_replay_receipt is not None:
        try:
            expected_receipt = build_runtime_lock_source_replay_receipt(
                evidence,
                normalized_source_sha256=source_replay_receipt.normalized_source_sha256,
                normalized_source_bytes=source_replay_receipt.normalized_source_bytes,
            )
            if source_replay_receipt != expected_receipt:
                raise ValueError("source replay receipt differs from immutable Evidence")
        except ValueError as exc:
            source_failures.append(f"source replay receipt validation failed: {type(exc).__name__}")
            source_conversion_status = "failed"
            source_conversion_detail = "Persisted source conversion replay receipt is invalid."
        else:
            accepted_replay_receipt = source_replay_receipt
            source_conversion_status = "passed"
            source_conversion_detail = (
                "Private source conversion reproduced the complete public Runtime Lock evidence."
            )
    if source_failures:
        results["source_identity"] = ("failed", _bounded(source_failures))
    elif accepted_replay_receipt is not None:
        results["source_identity"] = (
            "passed",
            "Raw source byte count and SHA-256 match the persisted replay receipt.",
        )
    elif private_source_stream is None:
        results["source_identity"] = (
            "skipped",
            "Public digest binding passed; private source conversion replay was unavailable.",
        )
    else:
        results["source_identity"] = (
            "passed",
            "Private source byte count and SHA-256 match the immutable source receipt.",
        )
    results["source_conversion_replay"] = (
        source_conversion_status,
        source_conversion_detail,
    )

    conversion_failures = [
        failure
        for failure in evidence_failures
        if "conversion" in failure or "stack" in failure or "ordering" in failure
    ]
    domain_events: tuple[domain.RuntimeLockEvent, ...] = ()
    replay: domain.RuntimeReplay | None = None
    try:
        domain_events = _verification_domain_events(evidence)
        replay = _independent_replay_runtime_lock_events(domain_events)
        if len(domain_events) != len(evidence.events):
            conversion_failures.append("normalized conversion changed the event count")
    except (KeyError, TypeError, ValueError) as exc:
        conversion_failures.append(f"normalized conversion replay failed: {type(exc).__name__}")
    _record(
        results,
        "conversion_replay",
        conversion_failures,
        "Conversion manifest and normalized context/stack/event replay are deterministic.",
    )

    target_failures = [
        failure for failure in evidence_failures if "target" in failure or "scope" in failure
    ]
    evidence_context_ids = {context.context_id for context in evidence.execution_contexts}
    if analysis.schema_version != evidence.schema_version:
        target_failures.append("analysis schema differs from Runtime Lock evidence")
    if analysis.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id:
        target_failures.append("analysis references another Runtime Lock evidence artifact")
    if analysis.runtime != evidence.source.runtime:
        target_failures.append("analysis runtime differs from source runtime")
    if any(
        row.execution_context_id not in evidence_context_ids
        for row in analysis.execution_context_aggregates
    ):
        target_failures.append("analysis context projection escaped the evidence scope")
    _record(
        results,
        "target_scope",
        target_failures,
        "Target PID/TID and runtime execution-context scope are preserved.",
    )

    semantic_failures = [
        failure
        for failure in evidence_failures
        if "record" in failure
        or "semantic" in failure
        or "emitted" in failure
        or "owner observations" in failure
    ]
    classified_evidence_failures = set(
        (*source_failures, *conversion_failures, *target_failures, *semantic_failures)
    )
    unclassified_evidence_failures = [
        failure for failure in evidence_failures if failure not in classified_evidence_failures
    ]
    _record(
        results,
        "evidence_invariants",
        unclassified_evidence_failures,
        "Every Evidence invariant was either satisfied or assigned to a specific failed check.",
    )
    if analysis.measurement_semantics != evidence.source.measurement_semantics:
        semantic_failures.append("analysis measurement semantics differs from evidence")
    _record(
        results,
        "semantic_count_conservation",
        semantic_failures,
        "Input dispositions and the single measurement semantics are conserved.",
    )

    pairing_failures: list[str] = []
    if replay is None:
        pairing_failures.append("event pairing replay was unavailable")
    else:
        categorized = (
            len(replay.consumed_event_ids)
            + len(replay.unpaired_event_ids)
            + len(replay.ignored_event_ids)
        )
        if categorized != len(evidence.events):
            pairing_failures.append("event pairing dispositions do not conserve events")
        if replay.issues and analysis.quality_status != "partial":
            pairing_failures.append("analysis hides incomplete or contradictory event pairs")
        if not replay.issues and analysis.quality_status != evidence.quality.status:
            pairing_failures.append("analysis quality differs from complete pairing replay")
    _record(
        results,
        "event_pairing",
        pairing_failures,
        "Wait/acquire/release and park/unpark pairs are ordered and identity-matched.",
    )

    wait_hold_failures: list[str] = []
    expected_domain: domain.RuntimeLockAnalysis | None = None
    if replay is not None:
        try:
            expected_domain = _independent_analyze_runtime_lock_events(
                domain_events,
                max_exported_rows=evidence.limits.max_exported_locks,
            )
        except (TypeError, ValueError) as exc:
            wait_hold_failures.append(f"wait/hold replay failed: {type(exc).__name__}")
    elif evidence.events:
        wait_hold_failures.append("wait/hold replay omitted public events")
    if expected_domain is not None:
        totals = expected_domain.totals
        expected_totals = (
            totals.exact_waits.sample_count,
            totals.exact_waits.total_ns,
            totals.thresholded_waits.sample_count,
            totals.thresholded_waits.total_ns,
            totals.sampled_observation_count,
            totals.cumulative_observation_count,
            totals.observed_or_estimated_wait_ns,
            totals.exact_holds.sample_count,
            totals.exact_holds.total_ns,
            totals.owner_observed_count,
        )
        if _analysis_totals(analysis) != expected_totals:
            wait_hold_failures.append("analysis wait/hold/profile totals differ from replay")
    _record(
        results,
        "wait_hold_conservation",
        wait_hold_failures,
        "Integer wait, hold, profile-weight, outcome, and owner totals match replay.",
    )

    projection_failures = (
        ["independent domain analysis replay was unavailable"]
        if expected_domain is None
        else _independent_projection_failures(analysis, evidence, expected_domain)
    )
    _record(
        results,
        "aggregate_projection_conservation",
        projection_failures,
        "All lock/context/path/outcome/kind projections and omissions match replay.",
    )

    content_failures: list[str] = []
    if analysis.runtime_lock_evidence_content_sha256 != evidence.content_sha256:
        content_failures.append("analysis evidence content digest binding mismatch")
    evidence_bytes = len(serialize_json(evidence))
    if analysis.runtime_lock_evidence_content_bytes != evidence_bytes:
        content_failures.append("analysis evidence byte binding mismatch")
    digest = compute_runtime_lock_analysis_content_sha256(analysis)
    if analysis.content_sha256 != digest:
        content_failures.append("analysis Agent-visible content digest mismatch")
    if analysis.content_bytes != len(serialize_json(analysis)):
        content_failures.append("analysis Agent-visible content byte count mismatch")
    fingerprint = compute_runtime_lock_analysis_fingerprint(analysis, evidence)
    if analysis.analysis_fingerprint != fingerprint:
        content_failures.append("analysis fingerprint mismatch")
    if analysis.runtime_lock_analysis_id != f"runtime-lock-analysis-{fingerprint[:16]}":
        content_failures.append("analysis identifier does not match its fingerprint")
    _record(
        results,
        "agent_visible_content_sha256",
        content_failures,
        "Every Agent-visible Analysis field matches its digest and input fingerprint.",
    )

    checks = tuple(
        public.RuntimeLockVerificationCheck(
            name=name,
            status=results[name][0],
            detail=results[name][1],
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
    verification_fingerprint = canonical_runtime_lock_json_sha256(
        {
            "domain": _VERIFICATION_FINGERPRINT_DOMAIN,
            "schema_version": analysis.schema_version,
            "analysis_id": analysis.runtime_lock_analysis_id,
            "analysis_content_sha256": analysis.content_sha256,
            "evidence_id": evidence.runtime_lock_evidence_id,
            "evidence_content_sha256": evidence.content_sha256,
            "checks": checks,
            "source_replay_receipt": accepted_replay_receipt,
        }
    )
    provisional = public.RuntimeLockAnalysisVerificationArtifact(
        schema_version=analysis.schema_version,
        runtime_lock_verification_id=(f"runtime-lock-verification-{verification_fingerprint[:16]}"),
        runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
        runtime_lock_evidence_content_sha256=evidence.content_sha256,
        runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
        runtime_lock_analysis_content_sha256=analysis.content_sha256,
        created_at=analysis.created_at,
        verification_status=verification_status,
        checks=checks,
        source_replay_receipt=accepted_replay_receipt,
        verifier_version=(
            "runtime-lock-verifier-v1"
            if analysis.schema_version == "1.0"
            else "runtime-lock-verifier-v2"
        ),
        content_sha256="0" * 64,
    )
    return public.RuntimeLockAnalysisVerificationArtifact.model_validate(
        {
            **provisional.model_dump(mode="json", exclude_none=True),
            "content_sha256": compute_runtime_lock_verification_content_sha256(provisional),
        }
    )


def require_usable_runtime_lock_analysis(
    verification: public.RuntimeLockAnalysisVerificationArtifact,
) -> None:
    if verification.verification_status != "failed":
        return
    raise PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "runtime_lock_verification",
        "Runtime Lock analysis failed deterministic verification",
        details={
            "runtime_lock_analysis_id": verification.runtime_lock_analysis_id,
            "failed_checks": tuple(
                check.name for check in verification.checks if check.status == "failed"
            ),
        },
        suggested_actions=(
            "Do not expose this analysis; rebuild it from retained Runtime Lock evidence.",
        ),
    )


@dataclass(slots=True)
class _IndependentEventStatus:
    used: bool = False
    invalid: bool = False


def _independent_replay_runtime_lock_events(
    events: tuple[domain.RuntimeLockEvent, ...],
) -> domain.RuntimeReplay:
    """Verifier-owned pairing state machine; never call the Analyzer replay."""

    event_ids = tuple(event.event_id for event in events)
    if len(set(event_ids)) != len(event_ids):
        raise ValueError("verification event IDs are not unique")
    if tuple(event.event_index for event in events) != tuple(range(len(events))):
        raise ValueError("verification event indexes are not contiguous")
    ordering = tuple((event.timestamp_ns, event.event_index) for event in events)
    if ordering != tuple(sorted(ordering)):
        raise ValueError("verification events are not canonically ordered")
    semantics = events[0].measurement_semantics if events else None
    if any(event.measurement_semantics != semantics for event in events):
        raise ValueError("verification events mixed measurement semantics")

    statuses = {event.event_id: _IndependentEventStatus() for event in events}
    by_id = {event.event_id: event for event in events}
    pending_waits: dict[
        tuple[domain.RuntimeExecutionContext, str | None, str], domain.RuntimeLockEvent
    ] = {}
    active_acquires: dict[
        tuple[domain.RuntimeExecutionContext, str | None, str], list[domain.RuntimeLockEvent]
    ] = {}
    pending_parks: dict[
        tuple[domain.RuntimeExecutionContext, str | None, str], domain.RuntimeLockEvent
    ] = {}
    waits: list[domain.RuntimeWaitObservation] = []
    holds: list[domain.RuntimeHoldObservation] = []
    profiles: list[domain.RuntimeProfileObservation] = []
    issues: list[domain.RuntimePairingIssue] = []
    paired_wait_begins: set[str] = set()
    linked_wait_ends: set[str] = set()
    released_acquires: set[str] = set()

    def key(
        event: domain.RuntimeLockEvent,
    ) -> tuple[domain.RuntimeExecutionContext, str | None, str]:
        return event.context, event.lock_id, event.lock_kind

    def same_subject(left: domain.RuntimeLockEvent, right: domain.RuntimeLockEvent) -> bool:
        return (
            left.context == right.context
            and left.lock_id == right.lock_id
            and left.lock_kind == right.lock_kind
            and left.measurement_semantics == right.measurement_semantics
        )

    def duration_matches(
        start: domain.RuntimeLockEvent,
        end: domain.RuntimeLockEvent,
        duration_ns: int,
    ) -> bool:
        return end.timestamp_ns >= start.timestamp_ns and (
            end.timestamp_ns - start.timestamp_ns == duration_ns
        )

    def mark_used(*paired: domain.RuntimeLockEvent) -> None:
        for item in paired:
            statuses[item.event_id].used = True

    def issue(
        phase: domain.RuntimePairingPhase,
        reason: domain.RuntimePairingReason,
        subject: domain.RuntimeLockEvent,
        *related: domain.RuntimeLockEvent,
    ) -> None:
        implicated = (subject, *related)
        for item in implicated:
            statuses[item.event_id].invalid = True
        issues.append(
            domain.RuntimePairingIssue(
                phase=phase,
                reason=reason,
                event_ids=tuple(item.event_id for item in implicated),
                context=subject.context,
                lock_id=subject.lock_id,
                lock_kind=subject.lock_kind,
            )
        )

    def record_wait(
        start: domain.RuntimeLockEvent,
        end: domain.RuntimeLockEvent,
        *,
        duration_ns: int,
        outcome: str,
        context: domain.RuntimeExecutionContext | None = None,
    ) -> None:
        waits.append(
            domain.RuntimeWaitObservation(
                context=context or start.context,
                lock_id=start.lock_id,
                lock_kind=start.lock_kind,
                stack_id=end.stack_id or start.stack_id,
                semantics=start.measurement_semantics,
                duration_ns=duration_ns,
                outcome=outcome,
                owner_observed=(start.owner_context is not None or end.owner_context is not None),
                event_ids=(start.event_id, end.event_id),
            )
        )
        if start.event_kind is domain.RuntimeEventKind.WAIT_BEGIN:
            paired_wait_begins.add(start.event_id)
        mark_used(start, end)

    for event in events:
        subject_key = key(event)
        if event.event_kind is domain.RuntimeEventKind.WAIT_BEGIN:
            previous = pending_waits.get(subject_key)
            if previous is None:
                pending_waits[subject_key] = event
            else:
                issue(
                    domain.RuntimePairingPhase.WAIT,
                    domain.RuntimePairingReason.DUPLICATE_WAIT_BEGIN,
                    previous,
                    event,
                )
                pending_waits.pop(subject_key)
            continue
        if event.event_kind is domain.RuntimeEventKind.WAIT_END:
            if event.duration_ns is None or event.outcome is None:
                raise ValueError("verification wait_end omitted duration or outcome")
            start: domain.RuntimeLockEvent | None = None
            if event.wait_begin_event_id is not None:
                referenced = by_id.get(event.wait_begin_event_id)
                if (
                    referenced is None
                    or referenced.event_kind is not domain.RuntimeEventKind.WAIT_BEGIN
                ):
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.UNKNOWN_WAIT_BEGIN,
                        event,
                    )
                    continue
                if referenced.event_id in paired_wait_begins:
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.REUSED_WAIT_BEGIN,
                        event,
                        referenced,
                    )
                    continue
                if statuses[referenced.event_id].invalid:
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.REUSED_WAIT_BEGIN,
                        event,
                        referenced,
                    )
                    continue
                if not same_subject(referenced, event):
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.WAIT_IDENTITY_MISMATCH,
                        event,
                        referenced,
                    )
                    pending_waits.pop(key(referenced), None)
                    continue
                start = referenced
            else:
                start = pending_waits.get(subject_key)
            if start is None:
                if event.measurement_semantics is domain.RuntimeMeasurementSemantics.THRESHOLDED:
                    waits.append(
                        domain.RuntimeWaitObservation(
                            context=event.context,
                            lock_id=event.lock_id,
                            lock_kind=event.lock_kind,
                            stack_id=event.stack_id,
                            semantics=event.measurement_semantics,
                            duration_ns=event.duration_ns,
                            outcome=event.outcome,
                            owner_observed=event.owner_context is not None,
                            event_ids=(event.event_id,),
                        )
                    )
                    mark_used(event)
                else:
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.WAIT_END_WITHOUT_BEGIN,
                        event,
                    )
                continue
            pending_waits.pop(key(start), None)
            if not duration_matches(start, event, event.duration_ns):
                issue(
                    domain.RuntimePairingPhase.WAIT,
                    domain.RuntimePairingReason.WAIT_DURATION_MISMATCH,
                    event,
                    start,
                )
                continue
            record_wait(start, event, duration_ns=event.duration_ns, outcome=event.outcome)
            continue
        if event.event_kind is domain.RuntimeEventKind.ACQUIRE:
            if event.wait_end_event_id is not None:
                referenced_end = by_id.get(event.wait_end_event_id)
                if (
                    referenced_end is None
                    or referenced_end.event_kind is not domain.RuntimeEventKind.WAIT_END
                    or referenced_end.outcome != "acquired"
                ):
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.UNKNOWN_WAIT_BEGIN,
                        event,
                    )
                    continue
                if referenced_end.event_id in linked_wait_ends:
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.REUSED_WAIT_END,
                        event,
                        referenced_end,
                    )
                    continue
                if statuses[referenced_end.event_id].invalid:
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.REUSED_WAIT_END,
                        event,
                        referenced_end,
                    )
                    continue
                if not same_subject(referenced_end, event) or (
                    referenced_end.timestamp_ns > event.timestamp_ns
                ):
                    issue(
                        domain.RuntimePairingPhase.WAIT,
                        domain.RuntimePairingReason.WAIT_IDENTITY_MISMATCH,
                        event,
                        referenced_end,
                    )
                    continue
                mark_used(referenced_end, event)
                linked_wait_ends.add(referenced_end.event_id)
            start = pending_waits.pop(subject_key, None)
            if start is not None:
                record_wait(
                    start,
                    event,
                    duration_ns=event.timestamp_ns - start.timestamp_ns,
                    outcome="acquired",
                )
            active = active_acquires.setdefault(subject_key, [])
            if active and event.lock_kind != "recursive_mutex":
                previous = active.pop()
                issue(
                    domain.RuntimePairingPhase.HOLD,
                    domain.RuntimePairingReason.DUPLICATE_ACQUIRE,
                    previous,
                    event,
                )
                if not active:
                    active_acquires.pop(subject_key, None)
            else:
                active.append(event)
            continue
        if event.event_kind is domain.RuntimeEventKind.RELEASE:
            acquire: domain.RuntimeLockEvent | None
            if event.acquire_event_id is not None:
                referenced = by_id.get(event.acquire_event_id)
                if (
                    referenced is None
                    or referenced.event_kind is not domain.RuntimeEventKind.ACQUIRE
                ):
                    issue(
                        domain.RuntimePairingPhase.HOLD,
                        domain.RuntimePairingReason.UNKNOWN_ACQUIRE,
                        event,
                    )
                    continue
                if referenced.event_id in released_acquires:
                    issue(
                        domain.RuntimePairingPhase.HOLD,
                        domain.RuntimePairingReason.REUSED_ACQUIRE,
                        event,
                        referenced,
                    )
                    continue
                if statuses[referenced.event_id].invalid:
                    issue(
                        domain.RuntimePairingPhase.HOLD,
                        domain.RuntimePairingReason.REUSED_ACQUIRE,
                        event,
                        referenced,
                    )
                    continue
                if not same_subject(referenced, event):
                    issue(
                        domain.RuntimePairingPhase.HOLD,
                        domain.RuntimePairingReason.HOLD_IDENTITY_MISMATCH,
                        event,
                        referenced,
                    )
                    active_acquires.pop(key(referenced), None)
                    continue
                acquire = referenced
            else:
                active = active_acquires.get(subject_key, [])
                acquire = active[-1] if active else None
            if acquire is None:
                issue(
                    domain.RuntimePairingPhase.HOLD,
                    domain.RuntimePairingReason.RELEASE_WITHOUT_ACQUIRE,
                    event,
                )
                continue
            active = active_acquires.get(key(acquire), [])
            if not active or acquire not in active:
                issue(
                    domain.RuntimePairingPhase.HOLD,
                    domain.RuntimePairingReason.REUSED_ACQUIRE,
                    event,
                    acquire,
                )
                continue
            if active[-1] is not acquire:
                issue(
                    domain.RuntimePairingPhase.HOLD,
                    domain.RuntimePairingReason.NON_LIFO_RELEASE,
                    event,
                    acquire,
                )
                active_acquires.pop(key(acquire), None)
                continue
            active.pop()
            if not active:
                active_acquires.pop(key(acquire), None)
            released_acquires.add(acquire.event_id)
            duration_ns = event.hold_duration_ns
            if duration_ns is None:
                mark_used(acquire, event)
                continue
            if not duration_matches(acquire, event, duration_ns):
                issue(
                    domain.RuntimePairingPhase.HOLD,
                    domain.RuntimePairingReason.HOLD_DURATION_MISMATCH,
                    event,
                    acquire,
                )
                continue
            if event.measurement_semantics is domain.RuntimeMeasurementSemantics.EXACT:
                holds.append(
                    domain.RuntimeHoldObservation(
                        context=event.context,
                        lock_id=event.lock_id,
                        lock_kind=event.lock_kind,
                        stack_id=event.stack_id or acquire.stack_id,
                        duration_ns=duration_ns,
                        event_ids=(acquire.event_id, event.event_id),
                    )
                )
            mark_used(acquire, event)
            continue
        if event.event_kind is domain.RuntimeEventKind.PARK:
            previous = pending_parks.get(subject_key)
            if previous is None:
                pending_parks[subject_key] = event
            else:
                issue(
                    domain.RuntimePairingPhase.PARK,
                    domain.RuntimePairingReason.DUPLICATE_WAIT_BEGIN,
                    previous,
                    event,
                )
                pending_parks.pop(subject_key)
            continue
        if event.event_kind is domain.RuntimeEventKind.UNPARK:
            if event.parked_context is None:
                issue(
                    domain.RuntimePairingPhase.PARK,
                    domain.RuntimePairingReason.UNPARK_WITHOUT_PARK,
                    event,
                )
                continue
            park = pending_parks.pop(
                (event.parked_context, event.lock_id, event.lock_kind),
                None,
            )
            if park is None or statuses[park.event_id].invalid:
                issue(
                    domain.RuntimePairingPhase.PARK,
                    domain.RuntimePairingReason.UNPARK_WITHOUT_PARK,
                    event,
                    *((park,) if park is not None else ()),
                )
                continue
            record_wait(
                park,
                event,
                duration_ns=event.timestamp_ns - park.timestamp_ns,
                outcome="unparked",
                context=park.context,
            )
            continue
        if event.event_kind is not domain.RuntimeEventKind.SAMPLED_CONTENTION:
            raise ValueError("verification received an unsupported event kind")
        if event.observed_count is None or event.cumulative_wait_ns is None:
            raise ValueError("verification profile event omitted count or weight")
        profiles.append(
            domain.RuntimeProfileObservation(
                context=event.context,
                lock_id=event.lock_id,
                lock_kind=event.lock_kind,
                stack_id=event.stack_id,
                semantics=event.measurement_semantics,
                observed_count=event.observed_count,
                estimated_count=event.estimated_count,
                cumulative_wait_ns=event.cumulative_wait_ns,
                event_id=event.event_id,
            )
        )
        mark_used(event)

    pending_groups = (
        (tuple(pending_waits.values()), domain.RuntimePairingPhase.WAIT),
        (
            tuple(event for active in active_acquires.values() for event in active),
            domain.RuntimePairingPhase.HOLD,
        ),
        (tuple(pending_parks.values()), domain.RuntimePairingPhase.PARK),
    )
    for pending, phase in pending_groups:
        for event in pending:
            issue(phase, domain.RuntimePairingReason.TRACE_END_BOUNDARY, event)
    consumed: list[str] = []
    unpaired: list[str] = []
    ignored: list[str] = []
    for event in events:
        status = statuses[event.event_id]
        if status.used:
            consumed.append(event.event_id)
        elif status.invalid:
            unpaired.append(event.event_id)
        else:
            ignored.append(event.event_id)
    return domain.RuntimeReplay(
        semantics=semantics,
        waits=tuple(waits),
        holds=tuple(holds),
        profiles=tuple(profiles),
        issues=tuple(issues),
        consumed_event_ids=tuple(consumed),
        unpaired_event_ids=tuple(unpaired),
        ignored_event_ids=tuple(ignored),
    )


def _independent_int_list() -> list[int]:
    return []


@dataclass(slots=True)
class _IndependentAccumulator:
    exact_wait_ns: list[int] = field(default_factory=_independent_int_list)
    thresholded_wait_ns: list[int] = field(default_factory=_independent_int_list)
    sampled_observation_count: int = 0
    cumulative_observation_count: int = 0
    observed_or_estimated_wait_ns: int = 0
    exact_hold_ns: list[int] = field(default_factory=_independent_int_list)
    owner_observed_count: int = 0

    def metrics(self) -> domain.RuntimeProjectionMetrics:
        return domain.RuntimeProjectionMetrics(
            exact_waits=_independent_distribution(self.exact_wait_ns),
            thresholded_waits=_independent_distribution(self.thresholded_wait_ns),
            sampled_observation_count=self.sampled_observation_count,
            cumulative_observation_count=self.cumulative_observation_count,
            observed_or_estimated_wait_ns=self.observed_or_estimated_wait_ns,
            exact_holds=_independent_distribution(self.exact_hold_ns),
            owner_observed_count=self.owner_observed_count,
        )


def _independent_distribution(values: list[int]) -> domain.RuntimeDurationDistribution:
    if not values:
        return domain.RuntimeDurationDistribution(0, 0, 0, 0, 0, 0, 0, 0)
    ordered = sorted(values)
    total = sum(ordered)

    def percentile(value: int) -> int:
        return ordered[ceil(value * len(ordered) / 100) - 1]

    return domain.RuntimeDurationDistribution(
        sample_count=len(ordered),
        total_ns=total,
        minimum_ns=ordered[0],
        mean_ns=total // len(ordered),
        p50_ns=percentile(50),
        p95_ns=percentile(95),
        p99_ns=percentile(99),
        maximum_ns=ordered[-1],
    )


def _independent_add_wait(
    target: _IndependentAccumulator,
    observation: domain.RuntimeWaitObservation,
) -> None:
    if observation.semantics is domain.RuntimeMeasurementSemantics.EXACT:
        target.exact_wait_ns.append(observation.duration_ns)
    elif observation.semantics is domain.RuntimeMeasurementSemantics.THRESHOLDED:
        target.thresholded_wait_ns.append(observation.duration_ns)
    else:
        raise ValueError("verification wait carried profile semantics")
    target.observed_or_estimated_wait_ns += observation.duration_ns
    target.owner_observed_count += int(observation.owner_observed)


def _independent_add_profile(
    target: _IndependentAccumulator,
    observation: domain.RuntimeProfileObservation,
) -> None:
    if observation.semantics is domain.RuntimeMeasurementSemantics.SAMPLED:
        target.sampled_observation_count += observation.observed_count
    elif observation.semantics is domain.RuntimeMeasurementSemantics.CUMULATIVE:
        target.cumulative_observation_count += observation.observed_count
    else:
        raise ValueError("verification profile carried event semantics")
    target.observed_or_estimated_wait_ns += observation.cumulative_wait_ns


def _independent_sort_key(
    metrics: domain.RuntimeProjectionMetrics,
    identity: str,
) -> tuple[int, int, int, str]:
    return (
        -metrics.total_wait_ns,
        -metrics.exact_holds.total_ns,
        -metrics.observation_count,
        identity,
    )


def _independent_lock_count(values: set[tuple[str | None, str]]) -> int | None:
    return None if any(lock_id is None for lock_id, _kind in values) else len(values)


def _independent_page(
    rows: list[object],
    *,
    limit: int,
) -> domain.RuntimeProjectionPage:
    exported = tuple(rows[:limit])
    omitted = rows[limit:]

    def metrics(row: object) -> domain.RuntimeProjectionMetrics:
        value = getattr(row, "metrics", None)
        if not isinstance(value, domain.RuntimeProjectionMetrics):
            raise TypeError("verification projection omitted metrics")
        return value

    omission = domain.RuntimeProjectionOmission(
        total_row_count=len(rows),
        exported_row_count=len(exported),
        omitted_row_count=len(omitted),
        omitted_exact_wait_count=sum(metrics(row).exact_waits.sample_count for row in omitted),
        omitted_exact_wait_ns=sum(metrics(row).exact_waits.total_ns for row in omitted),
        omitted_thresholded_wait_count=sum(
            metrics(row).thresholded_waits.sample_count for row in omitted
        ),
        omitted_thresholded_wait_ns=sum(metrics(row).thresholded_waits.total_ns for row in omitted),
        omitted_sampled_observation_count=sum(
            metrics(row).sampled_observation_count for row in omitted
        ),
        omitted_cumulative_observation_count=sum(
            metrics(row).cumulative_observation_count for row in omitted
        ),
        omitted_observed_or_estimated_wait_ns=sum(
            metrics(row).observed_or_estimated_wait_ns for row in omitted
        ),
        omitted_observation_count=sum(metrics(row).observation_count for row in omitted),
        omitted_wait_ns=sum(metrics(row).total_wait_ns for row in omitted),
        omitted_hold_count=sum(metrics(row).exact_holds.sample_count for row in omitted),
        omitted_hold_ns=sum(metrics(row).exact_holds.total_ns for row in omitted),
        omitted_owner_observed_count=sum(metrics(row).owner_observed_count for row in omitted),
    )
    return domain.RuntimeProjectionPage(rows=exported, omission=omission)


def _independent_analyze_runtime_lock_events(
    events: tuple[domain.RuntimeLockEvent, ...],
    *,
    max_exported_rows: int,
) -> domain.RuntimeLockAnalysis:
    """Verifier-owned aggregation and pagination over its independent replay."""

    replay = _independent_replay_runtime_lock_events(events)
    totals = _IndependentAccumulator()
    by_lock: dict[tuple[str | None, str], _IndependentAccumulator] = defaultdict(
        _IndependentAccumulator
    )
    lock_contexts: dict[tuple[str | None, str], set[domain.RuntimeExecutionContext]] = defaultdict(
        set
    )
    lock_stacks: dict[tuple[str | None, str], dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    by_context: dict[domain.RuntimeExecutionContext, _IndependentAccumulator] = defaultdict(
        _IndependentAccumulator
    )
    context_locks: dict[domain.RuntimeExecutionContext, set[tuple[str | None, str]]] = defaultdict(
        set
    )
    by_path: dict[str | None, _IndependentAccumulator] = defaultdict(_IndependentAccumulator)
    path_locks: dict[str | None, set[tuple[str | None, str]]] = defaultdict(set)
    path_contexts: dict[str | None, set[domain.RuntimeExecutionContext]] = defaultdict(set)
    by_outcome: dict[str, _IndependentAccumulator] = defaultdict(_IndependentAccumulator)
    outcome_locks: dict[str, set[tuple[str | None, str]]] = defaultdict(set)
    outcome_contexts: dict[str, set[domain.RuntimeExecutionContext]] = defaultdict(set)
    by_kind: dict[str, _IndependentAccumulator] = defaultdict(_IndependentAccumulator)
    kind_locks: dict[str, set[tuple[str | None, str]]] = defaultdict(set)
    kind_contexts: dict[str, set[domain.RuntimeExecutionContext]] = defaultdict(set)

    for observation in replay.waits:
        lock_key = observation.lock_id, observation.lock_kind
        for target in (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome[observation.outcome],
            by_kind[observation.lock_kind],
        ):
            _independent_add_wait(target, observation)
        lock_contexts[lock_key].add(observation.context)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks[observation.outcome].add(lock_key)
        outcome_contexts[observation.outcome].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.duration_ns

    for observation in replay.holds:
        lock_key = observation.lock_id, observation.lock_kind
        for target in (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome["acquired"],
            by_kind[observation.lock_kind],
        ):
            target.exact_hold_ns.append(observation.duration_ns)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks["acquired"].add(lock_key)
        outcome_contexts["acquired"].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.duration_ns

    for observation in replay.profiles:
        lock_key = observation.lock_id, observation.lock_kind
        for target in (
            totals,
            by_lock[lock_key],
            by_context[observation.context],
            by_path[observation.stack_id],
            by_outcome["unknown"],
            by_kind[observation.lock_kind],
        ):
            _independent_add_profile(target, observation)
        lock_contexts[lock_key].add(observation.context)
        context_locks[observation.context].add(lock_key)
        path_locks[observation.stack_id].add(lock_key)
        path_contexts[observation.stack_id].add(observation.context)
        outcome_locks["unknown"].add(lock_key)
        outcome_contexts["unknown"].add(observation.context)
        kind_locks[observation.lock_kind].add(lock_key)
        kind_contexts[observation.lock_kind].add(observation.context)
        if observation.stack_id is not None:
            lock_stacks[lock_key][observation.stack_id] += observation.cumulative_wait_ns

    locks: list[object] = [
        domain.RuntimeLockProjection(
            lock_id=lock_id,
            lock_kind=lock_kind,
            metrics=accumulator.metrics(),
            waiter_context_count=len(lock_contexts[(lock_id, lock_kind)]),
            top_stack_ids=tuple(
                stack_id
                for stack_id, _weight in sorted(
                    lock_stacks[(lock_id, lock_kind)].items(),
                    key=lambda item: (-item[1], item[0]),
                )[:10]
            ),
        )
        for (lock_id, lock_kind), accumulator in by_lock.items()
    ]
    locks.sort(
        key=lambda value: _independent_sort_key(
            cast(domain.RuntimeLockProjection, value).metrics,
            f"{cast(domain.RuntimeLockProjection, value).lock_id or '~aggregate'}\0"
            f"{cast(domain.RuntimeLockProjection, value).lock_kind}",
        )
    )
    contexts: list[object] = [
        domain.RuntimeContextProjection(
            context=context,
            metrics=accumulator.metrics(),
            lock_count=_independent_lock_count(context_locks[context]),
        )
        for context, accumulator in by_context.items()
    ]
    contexts.sort(
        key=lambda value: _independent_sort_key(
            cast(domain.RuntimeContextProjection, value).metrics,
            f"{cast(domain.RuntimeContextProjection, value).context.kind.value}\0"
            f"{cast(domain.RuntimeContextProjection, value).context.context_id}\0"
            f"{cast(domain.RuntimeContextProjection, value).context.target_tid or 0}",
        )
    )
    paths: list[object] = [
        domain.RuntimeCallPathProjection(
            stack_id=stack_id,
            metrics=accumulator.metrics(),
            lock_count=_independent_lock_count(path_locks[stack_id]),
            execution_context_count=len(path_contexts[stack_id]),
        )
        for stack_id, accumulator in by_path.items()
    ]
    paths.sort(
        key=lambda value: _independent_sort_key(
            cast(domain.RuntimeCallPathProjection, value).metrics,
            cast(domain.RuntimeCallPathProjection, value).stack_id or "~unknown",
        )
    )
    outcomes: list[object] = [
        domain.RuntimeOutcomeProjection(
            outcome=outcome,
            metrics=accumulator.metrics(),
            lock_count=_independent_lock_count(outcome_locks[outcome]),
            execution_context_count=len(outcome_contexts[outcome]),
        )
        for outcome, accumulator in by_outcome.items()
    ]
    outcomes.sort(
        key=lambda value: _independent_sort_key(
            cast(domain.RuntimeOutcomeProjection, value).metrics,
            cast(domain.RuntimeOutcomeProjection, value).outcome,
        )
    )
    kinds: list[object] = [
        domain.RuntimeLockKindProjection(
            lock_kind=lock_kind,
            metrics=accumulator.metrics(),
            lock_count=_independent_lock_count(kind_locks[lock_kind]),
            execution_context_count=len(kind_contexts[lock_kind]),
        )
        for lock_kind, accumulator in by_kind.items()
    ]
    kinds.sort(
        key=lambda value: _independent_sort_key(
            cast(domain.RuntimeLockKindProjection, value).metrics,
            cast(domain.RuntimeLockKindProjection, value).lock_kind,
        )
    )
    return domain.RuntimeLockAnalysis(
        replay=replay,
        totals=totals.metrics(),
        locks=_independent_page(locks, limit=max_exported_rows),
        contexts=_independent_page(contexts, limit=max_exported_rows),
        call_paths=_independent_page(paths, limit=max_exported_rows),
        outcomes=_independent_page(outcomes, limit=max_exported_rows),
        lock_kinds=_independent_page(kinds, limit=max_exported_rows),
    )


def _verification_domain_events(
    evidence: public.RuntimeLockEvidenceArtifact,
) -> tuple[domain.RuntimeLockEvent, ...]:
    """Independently convert public events; do not reuse the Analysis builder mapping."""

    contexts = {
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

    def primary_context(
        event: public.RuntimeLockEventBase,
    ) -> domain.RuntimeExecutionContext:
        if event.execution_context_id is not None:
            return contexts[event.execution_context_id]
        if event.target_tid is None:
            raise ValueError("runtime event omitted both context and legacy TID")
        return legacy_context(event.target_tid)

    def reference(
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
            context=primary_context(event),
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
                    owner_context=reference(
                        event.owner_execution_context_id,
                        event.owner_target_tid,
                    ),
                )
            )
        elif isinstance(event, public.RuntimeWaitEndEvent):
            converted.append(
                convert(
                    event,
                    owner_context=reference(
                        event.owner_execution_context_id,
                        event.owner_target_tid,
                    ),
                    wait_begin_event_id=event.wait_begin_event_id,
                    duration_ns=event.duration_ns,
                    outcome=event.outcome,
                )
            )
        elif isinstance(event, public.RuntimeAcquireEvent):
            converted.append(convert(event, wait_end_event_id=event.wait_end_event_id))
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
                    parked_context=reference(
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


def _independent_projection_failures(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
    expected: domain.RuntimeLockAnalysis,
) -> list[str]:
    """Map domain rows independently and compare every public projection field."""

    failures: list[str] = []
    expected_partial = evidence.quality.status == "partial" or bool(expected.replay.issues)
    expected_quality = "partial" if expected_partial else "complete"
    if analysis.quality_status != expected_quality:
        failures.append("analysis quality boundary differs from independent replay")
    if analysis.created_at != evidence.created_at:
        failures.append("analysis creation identity differs from evidence")
    if analysis.limits != evidence.limits:
        failures.append("analysis limits differ from evidence projection policy")
    if analysis.runtime != evidence.source.runtime:
        failures.append("analysis runtime differs from independent source mapping")
    if analysis.measurement_semantics != evidence.source.measurement_semantics:
        failures.append("analysis semantics differs from independent source mapping")
    totals = expected.totals
    expected_totals = (
        totals.exact_waits.sample_count,
        totals.exact_waits.total_ns,
        totals.thresholded_waits.sample_count,
        totals.thresholded_waits.total_ns,
        totals.sampled_observation_count,
        totals.cumulative_observation_count,
        totals.observed_or_estimated_wait_ns,
        totals.exact_holds.sample_count,
        totals.exact_holds.total_ns,
        totals.owner_observed_count,
    )
    if _analysis_totals(analysis) != expected_totals:
        failures.append("analysis totals differ from independent domain projection")

    expected_forbidden = list(evidence.forbidden_conclusions)
    if expected_partial and "unqualified_runtime_lock_conclusion" not in expected_forbidden:
        expected_forbidden.append("unqualified_runtime_lock_conclusion")
    expected_allowed = tuple(
        conclusion
        for conclusion in evidence.allowed_conclusions
        if conclusion not in expected_forbidden
    )
    if analysis.allowed_conclusions != expected_allowed:
        failures.append("analysis allowed conclusions differ from replay quality boundary")
    if analysis.forbidden_conclusions != tuple(expected_forbidden):
        failures.append("analysis forbidden conclusions differ from replay quality boundary")

    lock_rows = cast(tuple[domain.RuntimeLockProjection, ...], expected.locks.rows)
    expected_locks = tuple(
        {
            **_expected_metrics(row.metrics),
            "lock_id": row.lock_id,
            "lock_kind": row.lock_kind,
            (
                "waiter_thread_count"
                if evidence.schema_version == "1.0"
                else "waiter_execution_context_count"
            ): row.waiter_context_count,
            "top_stack_ids": list(row.top_stack_ids),
        }
        for row in lock_rows
    )
    if _public_projection_rows(analysis.aggregates) != expected_locks:
        failures.append("lock aggregate rows differ from independent domain projection")
    if analysis.omitted_lock_count != expected.locks.omission.omitted_row_count:
        failures.append("omitted lock count differs from independent domain projection")

    if evidence.schema_version == "1.0":
        if expected.locks.omission.omitted_row_count:
            failures.append("schema 1.0 cannot conserve omitted lock weights")
        if any(
            (
                analysis.execution_context_aggregates,
                analysis.call_path_aggregates,
                analysis.wait_outcome_aggregates,
                analysis.lock_kind_aggregates,
                analysis.lock_coverage,
                analysis.execution_context_coverage,
                analysis.call_path_coverage,
                analysis.wait_outcome_coverage,
                analysis.lock_kind_coverage,
            )
        ):
            failures.append("schema 1.0 analysis unexpectedly exposes 1.1 projections")
        return failures

    context_rows = cast(tuple[domain.RuntimeContextProjection, ...], expected.contexts.rows)
    expected_contexts = tuple(
        {
            **_expected_metrics(row.metrics),
            "execution_context_id": row.context.context_id,
            **({"lock_count": row.lock_count} if row.lock_count is not None else {}),
        }
        for row in context_rows
    )
    if _public_projection_rows(analysis.execution_context_aggregates) != expected_contexts:
        failures.append("execution-context rows differ from independent domain projection")

    path_rows = cast(tuple[domain.RuntimeCallPathProjection, ...], expected.call_paths.rows)
    expected_paths = tuple(
        {
            **_expected_metrics(row.metrics),
            "stack_id": row.stack_id,
            **({"lock_count": row.lock_count} if row.lock_count is not None else {}),
            "execution_context_count": row.execution_context_count,
        }
        for row in path_rows
    )
    if _public_projection_rows(analysis.call_path_aggregates) != expected_paths:
        failures.append("call-path rows differ from independent domain projection")

    outcome_rows = cast(tuple[domain.RuntimeOutcomeProjection, ...], expected.outcomes.rows)
    expected_outcomes = tuple(
        {
            **_expected_metrics(row.metrics),
            "wait_outcome": row.outcome,
            **({"lock_count": row.lock_count} if row.lock_count is not None else {}),
            "execution_context_count": row.execution_context_count,
        }
        for row in outcome_rows
    )
    if _public_projection_rows(analysis.wait_outcome_aggregates) != expected_outcomes:
        failures.append("wait-outcome rows differ from independent domain projection")

    kind_rows = cast(tuple[domain.RuntimeLockKindProjection, ...], expected.lock_kinds.rows)
    expected_kinds = tuple(
        {
            **_expected_metrics(row.metrics),
            "lock_kind": row.lock_kind,
            **({"lock_count": row.lock_count} if row.lock_count is not None else {}),
            "execution_context_count": row.execution_context_count,
        }
        for row in kind_rows
    )
    if _public_projection_rows(analysis.lock_kind_aggregates) != expected_kinds:
        failures.append("lock-kind rows differ from independent domain projection")

    for label, actual, page in (
        ("lock", analysis.lock_coverage, expected.locks),
        (
            "execution-context",
            analysis.execution_context_coverage,
            expected.contexts,
        ),
        ("call-path", analysis.call_path_coverage, expected.call_paths),
        ("wait-outcome", analysis.wait_outcome_coverage, expected.outcomes),
        ("lock-kind", analysis.lock_kind_coverage, expected.lock_kinds),
    ):
        expected_coverage = _expected_coverage(page)
        if actual is None or actual.model_dump(mode="json") != expected_coverage:
            failures.append(f"{label} coverage differs from independent domain omission ledger")
    return failures


def _expected_distribution(
    value: domain.RuntimeDurationDistribution,
) -> dict[str, int]:
    return {
        "sample_count": value.sample_count,
        "total_ns": value.total_ns,
        "minimum_ns": value.minimum_ns,
        "mean_ns": value.mean_ns,
        "p50_ns": value.p50_ns,
        "p95_ns": value.p95_ns,
        "p99_ns": value.p99_ns,
        "maximum_ns": value.maximum_ns,
    }


def _expected_metrics(value: domain.RuntimeProjectionMetrics) -> dict[str, object]:
    return {
        "exact_waits": _expected_distribution(value.exact_waits),
        "thresholded_waits": _expected_distribution(value.thresholded_waits),
        "sampled_observation_count": value.sampled_observation_count,
        "cumulative_observation_count": value.cumulative_observation_count,
        "observed_or_estimated_wait_ns": value.observed_or_estimated_wait_ns,
        "exact_holds": _expected_distribution(value.exact_holds),
        "owner_observed_count": value.owner_observed_count,
    }


def _expected_coverage(page: domain.RuntimeProjectionPage) -> dict[str, int]:
    value = page.omission
    return {
        "total_row_count": value.total_row_count,
        "exported_row_count": value.exported_row_count,
        "omitted_row_count": value.omitted_row_count,
        "omitted_exact_wait_count": value.omitted_exact_wait_count,
        "omitted_exact_wait_ns": value.omitted_exact_wait_ns,
        "omitted_thresholded_wait_count": value.omitted_thresholded_wait_count,
        "omitted_thresholded_wait_ns": value.omitted_thresholded_wait_ns,
        "omitted_sampled_observation_count": value.omitted_sampled_observation_count,
        "omitted_cumulative_observation_count": (value.omitted_cumulative_observation_count),
        "omitted_observed_or_estimated_wait_ns": (value.omitted_observed_or_estimated_wait_ns),
        "omitted_exact_hold_count": value.omitted_hold_count,
        "omitted_exact_hold_ns": value.omitted_hold_ns,
        "omitted_owner_observed_count": value.omitted_owner_observed_count,
    }


def _public_projection_rows(
    rows: tuple[public.RuntimeProjectionMetrics, ...],
) -> tuple[dict[str, object], ...]:
    projected: list[dict[str, object]] = []
    for row in rows:
        payload = row.model_dump(mode="json", exclude_none=True)
        if isinstance(row, public.RuntimeLockAggregate):
            payload["lock_id"] = row.lock_id
        if isinstance(row, public.RuntimeCallPathAggregate):
            payload["stack_id"] = row.stack_id
        projected.append(payload)
    return tuple(projected)


def _analysis_totals(
    analysis: public.RuntimeLockAnalysisArtifact,
) -> tuple[int, ...]:
    return (
        analysis.total_exact_wait_count,
        analysis.total_exact_wait_ns,
        analysis.total_thresholded_wait_count,
        analysis.total_thresholded_wait_ns,
        analysis.total_sampled_observation_count,
        analysis.total_cumulative_observation_count,
        analysis.total_observed_or_estimated_wait_ns,
        analysis.total_exact_hold_count,
        analysis.total_exact_hold_ns,
        analysis.total_owner_observed_count,
    )


def _record(
    results: dict[str, tuple[VerificationStatus, str]],
    name: str,
    failures: list[str],
    passed_detail: str,
) -> None:
    results[name] = ("failed", _bounded(failures)) if failures else ("passed", passed_detail)


def _bounded(failures: list[str]) -> str:
    detail = "; ".join(dict.fromkeys(failures))
    return detail[:1024] or "Runtime Lock verification failed without a diagnostic."
