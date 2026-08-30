"""Bounded Agent-facing queries over verified Runtime Lock analyses."""

from __future__ import annotations

from typing import Literal

from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import (
    validate_runtime_lock_evidence_invariants,
)
from perflens.application.verify_runtime_locks import (
    compute_runtime_lock_verification_content_sha256,
    require_usable_runtime_lock_analysis,
    verify_runtime_lock_analysis_artifact,
)
from perflens.contracts import runtime_locks as public
from perflens.domain.errors import ErrorCode, PerfLensError

type RuntimeLockSortKey = Literal[
    "observed_or_estimated_wait_ns",
    "exact_wait_count",
    "thresholded_wait_count",
    "sampled_observation_count",
    "cumulative_observation_count",
    "exact_hold_ns",
    "owner_observed_count",
]


def list_runtime_lock_hotspots(
    analysis: public.RuntimeLockAnalysisArtifact,
    *,
    projection: public.RuntimeLockProjectionName = "lock",
    sort_by: RuntimeLockSortKey = "observed_or_estimated_wait_ns",
    cursor: int = 0,
    limit: int = 30,
) -> public.RuntimeLockHotspotPage:
    """Return one deterministic page without changing projection accounting."""

    _page_bounds(cursor, limit)
    rows, coverage = _projection(analysis, projection)
    ordered = tuple(sorted(rows, key=lambda row: _sort_key(row, sort_by)))
    items = ordered[cursor : cursor + limit]
    next_cursor = cursor + len(items) if cursor + len(items) < len(ordered) else None
    return public.RuntimeLockHotspotPage(
        schema_version=analysis.schema_version,
        runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
        runtime_lock_evidence_id=analysis.runtime_lock_evidence_id,
        projection=projection,
        measurement_semantics=analysis.measurement_semantics,
        quality_status=analysis.quality_status,
        items=items,
        cursor=cursor,
        next_cursor=next_cursor,
        total_items=len(ordered),
        coverage=coverage,
        allowed_conclusions=analysis.allowed_conclusions,
        forbidden_conclusions=analysis.forbidden_conclusions,
    )


def get_runtime_lock_call_paths(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
    *,
    cursor: int = 0,
    limit: int = 20,
) -> public.RuntimeLockCallPathPage:
    """Join a bounded call-path projection page to redacted public stack frames."""

    _page_bounds(cursor, limit)
    _verify_source_chain(analysis, evidence)
    ordered = tuple(
        sorted(
            analysis.call_path_aggregates,
            key=lambda row: _sort_key(row, "observed_or_estimated_wait_ns"),
        )
    )
    items = ordered[cursor : cursor + limit]
    stacks_by_id = {stack.stack_id: stack for stack in evidence.stacks}
    stacks = tuple(
        stacks_by_id.get(item.stack_id) if item.stack_id is not None else None for item in items
    )
    next_cursor = cursor + len(items) if cursor + len(items) < len(ordered) else None
    return public.RuntimeLockCallPathPage(
        schema_version=analysis.schema_version,
        runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
        runtime_lock_evidence_id=analysis.runtime_lock_evidence_id,
        measurement_semantics=analysis.measurement_semantics,
        quality_status=analysis.quality_status,
        items=items,
        stacks=stacks,
        cursor=cursor,
        next_cursor=next_cursor,
        total_items=len(ordered),
        coverage=analysis.call_path_coverage,
        allowed_conclusions=analysis.allowed_conclusions,
        forbidden_conclusions=analysis.forbidden_conclusions,
    )


def build_runtime_lock_diagnosis_bundle(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
    verification: public.RuntimeLockAnalysisVerificationArtifact,
) -> public.RuntimeLockDiagnosisBundleArtifact:
    """Build a concise diagnosis without elevating an observation to a root cause."""

    _verify_source_chain(analysis, evidence, verification=verification)
    top_lock_ids = tuple(row.lock_id for row in analysis.aggregates[:32] if row.lock_id is not None)
    top_context_ids = tuple(
        row.execution_context_id for row in analysis.execution_context_aggregates[:32]
    )
    top_stack_ids = tuple(
        row.stack_id for row in analysis.call_path_aggregates[:32] if row.stack_id is not None
    )
    observations = (
        f"Observed {analysis.total_exact_wait_count} exact waits totaling "
        f"{analysis.total_exact_wait_ns} ns.",
        f"Observed {analysis.total_thresholded_wait_count} thresholded waits totaling "
        f"{analysis.total_thresholded_wait_ns} ns.",
        f"Observed {analysis.total_sampled_observation_count} sampled and "
        f"{analysis.total_cumulative_observation_count} cumulative observations.",
    )
    limitations = list(evidence.quality.limitations)
    limitations.extend(check.detail for check in verification.checks if check.status != "passed")
    bounded_limitations = tuple(dict.fromkeys(limitations))[:64]
    verification_sha256 = compute_runtime_lock_verification_content_sha256(verification)
    diagnosis_id = public.derive_runtime_lock_diagnosis_id(
        analysis.runtime_lock_analysis_id,
        analysis.content_sha256,
        verification_sha256,
    )
    provisional = public.RuntimeLockDiagnosisBundleArtifact(
        schema_version=analysis.schema_version,
        runtime_lock_diagnosis_id=diagnosis_id,
        runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
        runtime_lock_analysis_content_sha256=analysis.content_sha256,
        runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
        runtime_lock_evidence_content_sha256=evidence.content_sha256,
        runtime_lock_verification_id=verification.runtime_lock_verification_id,
        runtime_lock_verification_content_sha256=verification_sha256,
        created_at=analysis.created_at,
        runtime=analysis.runtime,
        measurement_semantics=analysis.measurement_semantics,
        quality_status=analysis.quality_status,
        observations=observations,
        limitations=bounded_limitations,
        top_lock_ids=top_lock_ids,
        top_execution_context_ids=top_context_ids,
        top_stack_ids=top_stack_ids,
        allowed_conclusions=analysis.allowed_conclusions,
        forbidden_conclusions=analysis.forbidden_conclusions,
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _projection(
    analysis: public.RuntimeLockAnalysisArtifact,
    name: public.RuntimeLockProjectionName,
) -> tuple[tuple[public.RuntimeLockProjectionItem, ...], public.RuntimeProjectionCoverage | None]:
    if name == "lock":
        return analysis.aggregates, analysis.lock_coverage
    if name == "execution_context":
        return analysis.execution_context_aggregates, analysis.execution_context_coverage
    if name == "call_path":
        return analysis.call_path_aggregates, analysis.call_path_coverage
    if name == "wait_outcome":
        return analysis.wait_outcome_aggregates, analysis.wait_outcome_coverage
    return analysis.lock_kind_aggregates, analysis.lock_kind_coverage


def _sort_key(
    row: public.RuntimeProjectionMetrics,
    sort_by: RuntimeLockSortKey,
) -> tuple[int, str]:
    value = {
        "observed_or_estimated_wait_ns": row.observed_or_estimated_wait_ns,
        "exact_wait_count": row.exact_waits.sample_count,
        "thresholded_wait_count": row.thresholded_waits.sample_count,
        "sampled_observation_count": row.sampled_observation_count,
        "cumulative_observation_count": row.cumulative_observation_count,
        "exact_hold_ns": row.exact_holds.total_ns,
        "owner_observed_count": row.owner_observed_count,
    }[sort_by]
    return -value, repr(row)


def _page_bounds(cursor: int, limit: int) -> None:
    if cursor < 0 or limit < 1 or limit > 100:
        raise ValueError("cursor must be non-negative and limit must be between 1 and 100")


def _verify_source_chain(
    analysis: public.RuntimeLockAnalysisArtifact,
    evidence: public.RuntimeLockEvidenceArtifact,
    *,
    verification: public.RuntimeLockAnalysisVerificationArtifact | None = None,
) -> public.RuntimeLockAnalysisVerificationArtifact:
    """Fail closed before joining or summarizing independently supplied Artifacts."""

    validate_runtime_lock_evidence_invariants(evidence)
    replayed = verify_runtime_lock_analysis_artifact(analysis, evidence)
    require_usable_runtime_lock_analysis(replayed)
    if verification is not None and verification != replayed:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "runtime_lock_verification",
            "Runtime Lock verification does not match its Analysis and Evidence",
        )
    return replayed
