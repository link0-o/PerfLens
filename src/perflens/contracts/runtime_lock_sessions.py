"""Public contracts for bounded runtime-lock discovery and collection sessions.

These artifacts expose only content identities, bounded counters, and reviewed
project-relative scopes.  Authorization tokens, absolute host paths, source
bytes, credentials, and runtime object addresses are deliberately absent.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from perflens.contracts.artifacts import SCHEMA_VERSION, ContractModel
from perflens.contracts.runtime_locks import MeasurementSemantics

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
RuntimeLockCapabilityId = Annotated[str, Field(pattern=r"^runtime-lock-capability-[a-f0-9]{20}$")]
RuntimeLockPreviewId = Annotated[str, Field(pattern=r"^runtime-lock-preview-[a-f0-9]{20}$")]
RuntimeLockSessionId = Annotated[str, Field(pattern=r"^runtime-lock-session-[a-f0-9]{20}$")]
RuntimeLockSessionArtifactId = Annotated[
    str, Field(pattern=r"^runtime-lock-session-state-[a-f0-9]{20}$")
]
RuntimeLockRunId = Annotated[str, Field(pattern=r"^runtime-lock-run-[a-f0-9]{20}$")]
RuntimeLockComparisonId = Annotated[str, Field(pattern=r"^runtime-lock-comparison-[a-f0-9]{20}$")]
RuntimeLockAdapterId = Literal[
    "native_pthread",
    "java_jfr",
    "cpython_threading",
    "go_pprof",
    "generic_ndjson_import",
]
RuntimeLockTargetScope = Literal[
    "host_launched_workload",
    "managed_temporary_container",
    "docker_optimization",
    "controlled_import",
]
RuntimeLockSessionEndReason = Literal[
    "adapter_output_invalid",
    "adapter_unavailable",
    "correctness_failed",
    "explicitly_revoked",
    "hard_expiry_reached",
    "identity_or_policy_changed",
    "internal_collection_error",
    "operation_lease_expired",
    "operation_reservation_exceeded",
    "resource_limit_exceeded",
    "run_artifact_mismatch",
    "session_budget_exhausted",
    "target_exited",
    "target_identity_changed",
    "workload_budget_exhausted",
]
RuntimeLockWorkloadKind = Literal[
    "native_elf",
    "java_archive",
    "python_script",
    "go_elf",
]

_SENSITIVE_ARGUMENT = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:password|passwd|pwd|token|secret|credentials?|"
    r"authorization|api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"bearer[_-]?token|refresh[_-]?token)\s*(?:=|:\s+)",
    re.IGNORECASE,
)
_SENSITIVE_ARGUMENT_FLAG = re.compile(
    r"^(?:--?|/)(?:password|passwd|pwd|token|secret|credentials?|authorization|"
    r"api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"bearer[_-]?token|refresh[_-]?token)$",
    re.IGNORECASE,
)


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def _unique_sorted(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)) or tuple(sorted(values)) != values:
        raise ValueError(f"{label} must be unique and sorted")


def _relative_paths(values: tuple[str, ...], label: str) -> None:
    _unique_sorted(values, label)
    for value in values:
        path = PurePosixPath(value)
        if (
            not value
            or value.startswith("/")
            or "\x00" in value
            or len(value.encode("utf-8")) > 4096
            or str(path) != value
            or value in {".", ".."}
            or ".." in path.parts
        ):
            raise ValueError(f"{label} must contain normalized project-relative paths")


def _relative_path(value: str, label: str, *, allow_dot: bool = False) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
        or str(path) != value
        or (value in {".", ".."} and not (allow_dot and value == "."))
        or ".." in path.parts
    ):
        raise ValueError(f"{label} must be a normalized project-relative path")


def _workload_arguments(values: tuple[str, ...]) -> None:
    if len(values) > 128 or sum(len(value.encode("utf-8")) for value in values) > 32 << 10:
        raise ValueError("Runtime Lock workload arguments exceed their fixed bound")
    for value in values:
        if (
            "\x00" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or len(value.encode("utf-8")) > 4096
            or _SENSITIVE_ARGUMENT.search(value) is not None
            or _SENSITIVE_ARGUMENT_FLAG.fullmatch(value) is not None
        ):
            raise ValueError("Runtime Lock workload argument contains unsafe material")


def _derived_id(prefix: str, domain: str, *values: str) -> str:
    material = "\0".join((domain, *values))
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


def derive_runtime_lock_capability_id(
    project_identity_sha256: str,
    project_policy_sha256: str,
    created_at: str,
) -> str:
    return _derived_id(
        "runtime-lock-capability",
        "perflens-runtime-lock-capability-v1",
        project_identity_sha256,
        project_policy_sha256,
        created_at,
    )


def derive_runtime_lock_preview_id(
    project_identity_sha256: str,
    project_policy_sha256: str,
    capability_content_sha256: str,
    created_at: str,
) -> str:
    return _derived_id(
        "runtime-lock-preview",
        "perflens-runtime-lock-preview-v1",
        project_identity_sha256,
        project_policy_sha256,
        capability_content_sha256,
        created_at,
    )


def derive_runtime_lock_session_artifact_id(
    session_id: str,
    revision: int,
    state: str,
    updated_at: str,
    previous_session_artifact_id: str | None,
    previous_session_artifact_content_sha256: str | None,
    workload_runs_used: int,
    active_seconds_used: int,
    evidence_bytes_used: int,
    exact_events_used: int,
) -> str:
    return _derived_id(
        "runtime-lock-session-state",
        "perflens-runtime-lock-session-state-v1",
        session_id,
        str(revision),
        state,
        updated_at,
        previous_session_artifact_id or "",
        previous_session_artifact_content_sha256 or "",
        str(workload_runs_used),
        str(active_seconds_used),
        str(evidence_bytes_used),
        str(exact_events_used),
    )


def derive_runtime_lock_run_id(
    session_id: str,
    adapter_id: str,
    evidence_content_sha256: str,
    started_at: str,
) -> str:
    return _derived_id(
        "runtime-lock-run",
        "perflens-runtime-lock-run-v1",
        session_id,
        adapter_id,
        evidence_content_sha256,
        started_at,
    )


def derive_runtime_lock_comparison_id(
    session_id: str,
    baseline_run_content_sha256: str,
    candidate_run_content_sha256: str,
    created_at: str,
) -> str:
    return _derived_id(
        "runtime-lock-comparison",
        "perflens-runtime-lock-comparison-v1",
        session_id,
        baseline_run_content_sha256,
        candidate_run_content_sha256,
        created_at,
    )


def derive_runtime_lock_workload_identity(
    adapter_id: str,
    workload_kind: str,
    program: str,
    program_sha256: str,
    program_size: int,
    working_directory: str,
    arguments: tuple[str, ...],
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-workload-v1",
            adapter_id,
            workload_kind,
            program,
            program_sha256,
            str(program_size),
            working_directory,
            *arguments,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class RuntimeLockSessionBudget(ContractModel):
    max_workload_runs: int = Field(default=6, ge=1, le=6)
    max_active_seconds: int = Field(default=1200, ge=1, le=1200)
    hard_expiry_seconds: int = Field(default=3600, ge=1, le=3600)
    max_artifact_bytes: int = Field(default=64 << 20, ge=1, le=64 << 20)
    max_evidence_bytes: int = Field(default=512 << 20, ge=1, le=512 << 20)
    max_collection_duration_seconds: int = Field(default=30, ge=1, le=30)
    max_exact_duration_seconds: int = Field(default=3, ge=1, le=3)
    max_exact_events: int = Field(default=20_000, ge=1, le=20_000)
    max_adapter_concurrency: Literal[1] = 1

    @model_validator(mode="after")
    def validate_budget(self) -> RuntimeLockSessionBudget:
        if self.max_exact_duration_seconds > self.max_collection_duration_seconds:
            raise ValueError("exact runtime-lock duration exceeds collection duration")
        if self.max_artifact_bytes > self.max_evidence_bytes:
            raise ValueError("runtime-lock Artifact limit exceeds Session evidence budget")
        return self


class RuntimeLockWorkloadBinding(ContractModel):
    """Content identity for one explicitly reviewed project workload.

    Paths remain project-relative and the argument vector is shown in the
    authorization Preview. Environment variables, absolute host paths and
    credentials are intentionally absent.
    """

    adapter_id: RuntimeLockAdapterId
    workload_kind: RuntimeLockWorkloadKind
    program: str
    program_sha256: Sha256
    program_size: int = Field(gt=0, le=1 << 30)
    working_directory: str = "."
    arguments: tuple[str, ...] = ()
    workload_identity_sha256: Sha256

    @model_validator(mode="after")
    def validate_workload(self) -> RuntimeLockWorkloadBinding:
        _relative_path(self.program, "Runtime Lock workload program")
        _relative_path(
            self.working_directory,
            "Runtime Lock workload directory",
            allow_dot=True,
        )
        _workload_arguments(self.arguments)
        expected = derive_runtime_lock_workload_identity(
            self.adapter_id,
            self.workload_kind,
            self.program,
            self.program_sha256,
            self.program_size,
            self.working_directory,
            self.arguments,
        )
        if self.workload_identity_sha256 != expected:
            raise ValueError("Runtime Lock workload identity differs from its content")
        return self


class RuntimeLockAdapterCapabilityReference(ContractModel):
    adapter_id: RuntimeLockAdapterId
    capability_id: str = Field(pattern=r"^[a-z][a-z0-9-]*-[a-f0-9]{16,64}$")
    capability_content_sha256: Sha256
    availability: Literal["available", "partial", "unavailable", "disabled"]
    supported_semantics: tuple[MeasurementSemantics, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_reference(self) -> RuntimeLockAdapterCapabilityReference:
        _unique_sorted(self.supported_semantics, "runtime-lock supported semantics")
        if self.availability == "available" and not self.supported_semantics:
            raise ValueError("available runtime-lock Adapter must expose a semantics")
        if self.availability in {"unavailable", "disabled"} and self.supported_semantics:
            raise ValueError("unavailable runtime-lock Adapter cannot expose semantics")
        if self.availability != "available" and not self.limitations:
            raise ValueError("non-available runtime-lock Adapter must explain limitations")
        return self


class RuntimeLockCapabilityArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    capability_id: RuntimeLockCapabilityId
    created_at: str
    project_identity_sha256: Sha256
    project_policy_sha256: Sha256
    status: Literal["available", "partial", "unavailable", "disabled"]
    adapters: tuple[RuntimeLockAdapterCapabilityReference, ...]
    limitations: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_capability(self) -> RuntimeLockCapabilityArtifact:
        _timestamp(self.created_at, "Runtime Lock capability creation time")
        adapter_ids = tuple(item.adapter_id for item in self.adapters)
        _unique_sorted(adapter_ids, "Runtime Lock capability adapters")
        if self.status == "available" and not any(
            item.availability == "available" for item in self.adapters
        ):
            raise ValueError("available Runtime Lock capability needs an available Adapter")
        if self.status != "available" and not self.limitations:
            raise ValueError("non-available Runtime Lock capability must explain limitations")
        expected = derive_runtime_lock_capability_id(
            self.project_identity_sha256,
            self.project_policy_sha256,
            self.created_at,
        )
        if self.capability_id != expected:
            raise ValueError("Runtime Lock capability ID differs from its identity")
        return self


class RuntimeLockSessionPreviewArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    preview_id: RuntimeLockPreviewId
    created_at: str
    expires_at: str
    project_identity_sha256: Sha256
    client_connection_identity_sha256: Sha256
    project_policy_sha256: Sha256
    capability_id: RuntimeLockCapabilityId
    capability_content_sha256: Sha256
    runtime_lock_config_sha256: Sha256
    target_scope: RuntimeLockTargetScope
    allowed_adapters: tuple[RuntimeLockAdapterId, ...]
    allowed_semantics: tuple[MeasurementSemantics, ...]
    import_roots: tuple[str, ...] = ()
    workload: RuntimeLockWorkloadBinding | None = None
    budget: RuntimeLockSessionBudget
    planned_actions: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    authorization_summary_sha256: Sha256
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_preview(self) -> RuntimeLockSessionPreviewArtifact:
        created = _timestamp(self.created_at, "Runtime Lock Preview creation time")
        expires = _timestamp(self.expires_at, "Runtime Lock Preview expiry time")
        if expires <= created:
            raise ValueError("Runtime Lock Preview must expire after creation")
        _unique_sorted(self.allowed_adapters, "Runtime Lock Preview adapters")
        _unique_sorted(self.allowed_semantics, "Runtime Lock Preview semantics")
        _relative_paths(self.import_roots, "Runtime Lock Preview import roots")
        if not self.allowed_adapters or not self.allowed_semantics:
            raise ValueError("Runtime Lock Preview requires Adapter and semantics scopes")
        if not self.planned_actions or len(self.planned_actions) > 32:
            raise ValueError("Runtime Lock Preview requires bounded planned actions")
        if self.target_scope == "controlled_import" and not self.import_roots:
            raise ValueError("controlled import requires a reviewed project-relative root")
        if self.target_scope == "controlled_import" and self.workload is not None:
            raise ValueError("controlled import cannot carry an executable workload")
        if self.target_scope == "host_launched_workload":
            if self.workload is None:
                raise ValueError("host Runtime Lock Preview requires an exact workload")
            if self.workload.adapter_id not in self.allowed_adapters:
                raise ValueError("Runtime Lock workload Adapter is outside Preview scope")
        if self.target_scope in {"managed_temporary_container", "docker_optimization"} and (
            self.workload is not None
        ):
            raise ValueError("Docker Runtime Lock Preview must use Docker Artifact identity")
        expected = derive_runtime_lock_preview_id(
            self.project_identity_sha256,
            self.project_policy_sha256,
            self.capability_content_sha256,
            self.created_at,
        )
        if self.preview_id != expected:
            raise ValueError("Runtime Lock Preview ID differs from its identity")
        return self


class RuntimeLockSessionArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    session_artifact_id: RuntimeLockSessionArtifactId
    session_id: RuntimeLockSessionId
    revision: int = Field(ge=0)
    previous_session_artifact_id: RuntimeLockSessionArtifactId | None = None
    previous_session_artifact_content_sha256: Sha256 | None = None
    created_at: str
    updated_at: str
    expires_at: str
    state: Literal["active", "revoked", "expired", "exhausted", "failed"]
    project_identity_sha256: Sha256
    client_connection_identity_sha256: Sha256
    project_policy_sha256: Sha256
    capability_id: RuntimeLockCapabilityId
    capability_content_sha256: Sha256
    runtime_lock_config_sha256: Sha256
    preview_id: RuntimeLockPreviewId
    preview_content_sha256: Sha256
    authorization_receipt_sha256: Sha256
    target_scope: RuntimeLockTargetScope
    allowed_adapters: tuple[RuntimeLockAdapterId, ...]
    allowed_semantics: tuple[MeasurementSemantics, ...]
    budget: RuntimeLockSessionBudget
    workload_runs_used: int = Field(default=0, ge=0, le=6)
    active_seconds_used: int = Field(default=0, ge=0, le=1200)
    evidence_bytes_used: int = Field(default=0, ge=0, le=512 << 20)
    exact_events_used: int = Field(default=0, ge=0, le=120_000)
    invalidation_reason: RuntimeLockSessionEndReason | None = None
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_session(self) -> RuntimeLockSessionArtifact:
        created = _timestamp(self.created_at, "Runtime Lock Session creation time")
        updated = _timestamp(self.updated_at, "Runtime Lock Session update time")
        expires = _timestamp(self.expires_at, "Runtime Lock Session expiry time")
        if updated < created or expires <= created:
            raise ValueError("Runtime Lock Session timestamps are inconsistent")
        _unique_sorted(self.allowed_adapters, "Runtime Lock Session adapters")
        _unique_sorted(self.allowed_semantics, "Runtime Lock Session semantics")
        if not self.allowed_adapters or not self.allowed_semantics:
            raise ValueError("Runtime Lock Session requires Adapter and semantics scopes")
        previous_values = (
            self.previous_session_artifact_id,
            self.previous_session_artifact_content_sha256,
        )
        if self.revision == 0 and any(value is not None for value in previous_values):
            raise ValueError("initial Runtime Lock Session state cannot reference a predecessor")
        if self.revision > 0 and any(value is None for value in previous_values):
            raise ValueError("updated Runtime Lock Session state must reference its predecessor")
        if self.previous_session_artifact_id == self.session_artifact_id:
            raise ValueError("Runtime Lock Session state cannot reference itself")
        if (
            self.workload_runs_used > self.budget.max_workload_runs
            or self.active_seconds_used > self.budget.max_active_seconds
            or self.evidence_bytes_used > self.budget.max_evidence_bytes
            or self.exact_events_used > self.budget.max_workload_runs * self.budget.max_exact_events
        ):
            raise ValueError("Runtime Lock Session counters exceed their budget")
        if self.state == "active" and self.invalidation_reason is not None:
            raise ValueError("active Runtime Lock Session cannot have an end reason")
        if self.state != "active" and self.invalidation_reason is None:
            raise ValueError("inactive Runtime Lock Session must explain why it ended")
        expected = derive_runtime_lock_session_artifact_id(
            self.session_id,
            self.revision,
            self.state,
            self.updated_at,
            self.previous_session_artifact_id,
            self.previous_session_artifact_content_sha256,
            self.workload_runs_used,
            self.active_seconds_used,
            self.evidence_bytes_used,
            self.exact_events_used,
        )
        if self.session_artifact_id != expected:
            raise ValueError("Runtime Lock Session Artifact ID differs from its state")
        return self


class RuntimeLockRunArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    run_id: RuntimeLockRunId
    created_at: str
    started_at: str
    finished_at: str
    session_id: RuntimeLockSessionId
    session_artifact_id: RuntimeLockSessionArtifactId
    session_artifact_content_sha256: Sha256
    session_revision: int = Field(ge=0)
    target_scope: RuntimeLockTargetScope
    operation_identity_sha256: Sha256
    target_identity_sha256: Sha256
    adapter_id: RuntimeLockAdapterId
    measurement_semantics: MeasurementSemantics
    workload_identity_sha256: Sha256
    runtime_lock_evidence_id: str = Field(pattern=r"^runtime-lock-evidence-[a-f0-9]{16,64}$")
    runtime_lock_evidence_content_sha256: Sha256
    runtime_lock_analysis_id: str = Field(pattern=r"^runtime-lock-analysis-[a-f0-9]{16,64}$")
    runtime_lock_analysis_content_sha256: Sha256
    runtime_lock_verification_id: str = Field(
        pattern=r"^runtime-lock-verification-[a-f0-9]{16,64}$"
    )
    runtime_lock_verification_content_sha256: Sha256
    duration_seconds: int = Field(ge=0, le=30)
    evidence_bytes: int = Field(ge=1, le=64 << 20)
    event_count: int = Field(ge=0)
    correctness_status: Literal["passed", "failed", "unavailable"]
    quality_status: Literal["complete", "partial"]
    warnings: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_run(self) -> RuntimeLockRunArtifact:
        created = _timestamp(self.created_at, "Runtime Lock Run creation time")
        started = _timestamp(self.started_at, "Runtime Lock Run start time")
        finished = _timestamp(self.finished_at, "Runtime Lock Run finish time")
        if finished < started or created < finished:
            raise ValueError("Runtime Lock Run timestamps are inconsistent")
        elapsed_seconds = math.ceil((finished - started).total_seconds())
        if self.duration_seconds != elapsed_seconds:
            raise ValueError("Runtime Lock Run duration differs from its timestamps")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("Runtime Lock Run must preserve conclusion boundaries")
        if self.measurement_semantics == "exact" and (
            self.duration_seconds > 3 or self.event_count > 20_000
        ):
            raise ValueError("exact Runtime Lock Run exceeds its hard evidence bound")
        expected = derive_runtime_lock_run_id(
            self.session_id,
            self.adapter_id,
            self.runtime_lock_evidence_content_sha256,
            self.started_at,
        )
        if self.run_id != expected:
            raise ValueError("Runtime Lock Run ID differs from its evidence")
        return self


class RuntimeLockComparisonArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    comparison_id: RuntimeLockComparisonId
    created_at: str
    session_id: RuntimeLockSessionId
    baseline_run_id: RuntimeLockRunId
    baseline_run_content_sha256: Sha256
    candidate_run_id: RuntimeLockRunId
    candidate_run_content_sha256: Sha256
    adapter_match: bool
    semantics_match: bool
    threshold_or_sampling_match: bool
    workload_match: bool
    resource_environment_match: bool
    baseline_quality_status: Literal["complete", "partial"]
    candidate_quality_status: Literal["complete", "partial"]
    correctness_status: Literal["passed", "failed", "unavailable"]
    deterministic_replay_passed: bool
    resource_transfer_status: Literal[
        "no_observed_regression",
        "regression",
        "incomplete",
    ]
    comparable: bool
    conclusion: Literal[
        "verified_improvement",
        "candidate_improvement",
        "candidate_regression",
        "no_material_change",
        "not_comparable",
    ]
    improved_metrics: tuple[str, ...] = ()
    regressed_metrics: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_comparison(self) -> RuntimeLockComparisonArtifact:
        _timestamp(self.created_at, "Runtime Lock comparison creation time")
        if self.baseline_run_id == self.candidate_run_id:
            raise ValueError("Runtime Lock comparison needs distinct Runs")
        _unique_sorted(self.improved_metrics, "Runtime Lock improved metrics")
        _unique_sorted(self.regressed_metrics, "Runtime Lock regressed metrics")
        fixed_match = all(
            (
                self.adapter_match,
                self.semantics_match,
                self.threshold_or_sampling_match,
                self.workload_match,
                self.resource_environment_match,
            )
        )
        if self.comparable != (
            fixed_match and self.correctness_status == "passed" and self.deterministic_replay_passed
        ):
            raise ValueError("Runtime Lock comparison comparability is inconsistent")
        if (self.conclusion == "not_comparable") == self.comparable:
            raise ValueError("Runtime Lock comparison conclusion disagrees with comparability")
        if self.conclusion == "verified_improvement" and (
            not self.comparable
            or self.baseline_quality_status != "complete"
            or self.candidate_quality_status != "complete"
            or self.resource_transfer_status != "no_observed_regression"
            or not self.improved_metrics
            or self.regressed_metrics
        ):
            raise ValueError("verified Runtime Lock improvement lacks matched evidence")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("Runtime Lock comparison must preserve conclusion boundaries")
        expected = derive_runtime_lock_comparison_id(
            self.session_id,
            self.baseline_run_content_sha256,
            self.candidate_run_content_sha256,
            self.created_at,
        )
        if self.comparison_id != expected:
            raise ValueError("Runtime Lock comparison ID differs from its Runs")
        return self
