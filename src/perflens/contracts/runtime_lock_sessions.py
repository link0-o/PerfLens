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

from pydantic import ConfigDict, Field, model_validator

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
RuntimeLockRunFinalizationId = Annotated[
    str, Field(pattern=r"^runtime-lock-run-finalization-[a-f0-9]{20}$")
]
RuntimeLockComparisonId = Annotated[str, Field(pattern=r"^runtime-lock-comparison-[a-f0-9]{20}$")]
RuntimeLockAdapterId = Literal[
    "native_pthread",
    "java_jfr",
    "cpython_threading",
    "go_pprof",
    "generic_ndjson_import",
]
RuntimeLockTargetScope = Literal[
    "host_bound_process",
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
RuntimeLockSessionSchemaVersion = Literal["1.0", "1.1"]
RuntimeLockLimitation = Annotated[str, Field(min_length=1, max_length=2048)]
RuntimeLockRunQualityStatus = Literal["complete", "partial"]

_UNQUALIFIED_RUNTIME_LOCK_CONCLUSION = "unqualified_runtime_lock_conclusion"
_RUNTIME_LOCK_RUN_PARTIAL_PROMOTION_WARNING_PREFIXES: dict[
    RuntimeLockAdapterId, tuple[str, ...]
] = {
    "native_pthread": (
        "Independent TID polling was partial:",
        "Native launch coverage is partial:",
    ),
    "java_jfr": (
        "Independent TID polling was partial:",
        "Independent Java thread polling was partial:",
        "Java launch coverage is partial:",
    ),
    "cpython_threading": (),
    "go_pprof": (),
    "generic_ndjson_import": (),
}

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


def _identity_text(value: str, label: str) -> None:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} cannot contain control characters")


def derive_runtime_lock_run_boundaries(
    *,
    adapter_id: RuntimeLockAdapterId,
    analysis_quality_status: RuntimeLockRunQualityStatus,
    analysis_allowed_conclusions: tuple[str, ...],
    analysis_forbidden_conclusions: tuple[str, ...],
    warnings: tuple[str, ...],
) -> tuple[
    RuntimeLockRunQualityStatus,
    tuple[str, ...],
    tuple[str, ...],
]:
    """Derive the only valid Run quality and conclusion projection.

    A Run normally preserves its deterministic Analysis boundaries exactly. A
    launcher may conservatively promote an otherwise complete Analysis to a
    partial Run, but only for a reviewed Adapter-specific coverage warning. In
    that case the Run adds exactly the unqualified-conclusion gate; arbitrary
    conclusion additions or removals are never accepted.
    """

    if not analysis_allowed_conclusions or not analysis_forbidden_conclusions:
        raise ValueError("Runtime Lock Analysis conclusion boundaries cannot be empty")
    for conclusions, label in (
        (analysis_allowed_conclusions, "allowed"),
        (analysis_forbidden_conclusions, "forbidden"),
    ):
        if any(not conclusion.strip() for conclusion in conclusions):
            raise ValueError(f"Runtime Lock Analysis {label} conclusions cannot be blank")
        if len(set(conclusions)) != len(conclusions):
            raise ValueError(f"Runtime Lock Analysis {label} conclusions must be unique")
    if set(analysis_allowed_conclusions) & set(analysis_forbidden_conclusions):
        raise ValueError("Runtime Lock Analysis conclusion boundaries must be disjoint")

    if analysis_quality_status == "partial":
        if _UNQUALIFIED_RUNTIME_LOCK_CONCLUSION not in analysis_forbidden_conclusions:
            raise ValueError("Partial Runtime Lock Analysis must forbid unqualified conclusions")
        return (
            "partial",
            analysis_allowed_conclusions,
            analysis_forbidden_conclusions,
        )

    if _UNQUALIFIED_RUNTIME_LOCK_CONCLUSION in analysis_forbidden_conclusions:
        raise ValueError("Complete Runtime Lock Analysis cannot carry the partial-quality gate")
    promotion_prefixes = _RUNTIME_LOCK_RUN_PARTIAL_PROMOTION_WARNING_PREFIXES[adapter_id]
    promoted_partial = any(
        warning.startswith(prefix) for warning in warnings for prefix in promotion_prefixes
    )
    if not promoted_partial:
        return (
            "complete",
            analysis_allowed_conclusions,
            analysis_forbidden_conclusions,
        )
    return (
        "partial",
        analysis_allowed_conclusions,
        (*analysis_forbidden_conclusions, _UNQUALIFIED_RUNTIME_LOCK_CONCLUSION),
    )


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
    settlement_finalization_id: str | None = None,
) -> str:
    values = (
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
    # Omitting the optional suffix preserves byte-for-byte schema 1.0 IDs.
    if settlement_finalization_id is not None:
        values = (*values, settlement_finalization_id)
    return _derived_id(
        "runtime-lock-session-state",
        "perflens-runtime-lock-session-state-v1",
        *values,
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


def derive_runtime_lock_run_finalization_id(
    session_id: str,
    operation_identity_sha256: str,
) -> str:
    """Derive the single immutable settlement marker for one consumed operation."""

    return _derived_id(
        "runtime-lock-run-finalization",
        "perflens-runtime-lock-run-finalization-v1",
        session_id,
        operation_identity_sha256,
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


def derive_runtime_lock_process_target_identity(
    target_pid: int,
    target_uid: int,
    target_start_time_ticks: int,
    loopback_port: int,
    socket_inode: int,
) -> str:
    """Bind a host process to one literal loopback listener without exposing paths."""

    material = "\0".join(
        (
            "perflens-runtime-lock-process-target-v1",
            str(target_pid),
            str(target_uid),
            str(target_start_time_ticks),
            "127.0.0.1",
            str(loopback_port),
            str(socket_inode),
        )
    )
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def derive_runtime_lock_adapter_execution_identity(
    adapter_id: str,
    adapter_version: str,
    backend_id: str,
    runtime_version: str,
    profile: str,
    measurement_semantics: str,
    duration_threshold_ns: int | None,
    toolchain_identity_sha256: str,
    configuration_sha256: str,
    metadata_sha256: str,
    runtime_payload_identity_sha256: str | None = None,
) -> str:
    values = (
        "perflens-runtime-lock-adapter-execution-v1",
        adapter_id,
        adapter_version,
        backend_id,
        runtime_version,
        profile,
        measurement_semantics,
        str(duration_threshold_ns) if duration_threshold_ns is not None else "none",
        toolchain_identity_sha256,
        configuration_sha256,
        metadata_sha256,
    )
    if runtime_payload_identity_sha256 is not None:
        values = (*values, runtime_payload_identity_sha256)
    material = "\0".join(values)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def derive_runtime_lock_toolchain_identity(
    tools: tuple[RuntimeLockAdapterToolBinding, ...],
) -> str:
    material = ["perflens-runtime-lock-toolchain-v1"]
    for tool in tools:
        material.extend((tool.name, tool.version, tool.binary_sha256))
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()


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


class RuntimeLockProcessTargetBinding(ContractModel):
    """Identity of one same-UID host process and its literal loopback pprof listener."""

    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    loopback_address: Literal["127.0.0.1"] = "127.0.0.1"
    loopback_port: int = Field(ge=1, le=65535)
    socket_inode: int = Field(gt=0)
    target_identity_sha256: Sha256

    @model_validator(mode="after")
    def validate_target(self) -> RuntimeLockProcessTargetBinding:
        expected = derive_runtime_lock_process_target_identity(
            self.target_pid,
            self.target_uid,
            self.target_start_time_ticks,
            self.loopback_port,
            self.socket_inode,
        )
        if self.target_identity_sha256 != expected:
            raise ValueError("Runtime Lock process target identity differs from its content")
        return self


class RuntimeLockAdapterToolBinding(ContractModel):
    """Path-free identity of one executable used by an active Adapter."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,64}$")
    version: str = Field(min_length=1, max_length=256)
    binary_sha256: Sha256

    @model_validator(mode="after")
    def validate_tool(self) -> RuntimeLockAdapterToolBinding:
        _identity_text(self.version, "Runtime Lock Adapter tool version")
        return self


class RuntimeLockAdapterExecutionBinding(ContractModel):
    """Public, path-free identity for one active Adapter configuration."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"adapter_id": {"const": "java_jfr"}},
                        "required": ["adapter_id"],
                    },
                    "then": {
                        "required": ["tools", "runtime_payload_identity_sha256"],
                        "properties": {"tools": {"minItems": 2, "maxItems": 2}},
                    },
                },
                {
                    "if": {
                        "properties": {"adapter_id": {"const": "cpython_threading"}},
                        "required": ["adapter_id"],
                    },
                    "then": {
                        "required": ["tools", "runtime_payload_identity_sha256"],
                        "properties": {"tools": {"minItems": 1, "maxItems": 1}},
                    },
                },
                {
                    "if": {
                        "properties": {"adapter_id": {"const": "go_pprof"}},
                        "required": ["adapter_id"],
                    },
                    "then": {
                        "required": ["tools"],
                        "properties": {"tools": {"minItems": 2, "maxItems": 2}},
                    },
                },
            ]
        }
    )

    adapter_id: RuntimeLockAdapterId
    adapter_version: str = Field(min_length=1, max_length=128)
    backend_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    runtime_version: str = Field(min_length=1, max_length=128)
    profile: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    measurement_semantics: MeasurementSemantics
    duration_threshold_ns: int | None = Field(default=None, ge=1, le=10**12)
    tools: tuple[RuntimeLockAdapterToolBinding, ...] = Field(default=(), max_length=16)
    toolchain_identity_sha256: Sha256
    configuration_sha256: Sha256
    metadata_sha256: Sha256
    runtime_payload_identity_sha256: Sha256 | None = None
    execution_identity_sha256: Sha256
    limitations: tuple[RuntimeLockLimitation, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_binding(self) -> RuntimeLockAdapterExecutionBinding:
        _identity_text(self.adapter_version, "Runtime Lock Adapter version")
        _identity_text(self.runtime_version, "Runtime Lock runtime version")
        tool_names = tuple(tool.name for tool in self.tools)
        _unique_sorted(tool_names, "Runtime Lock Adapter tools")
        if self.adapter_id == "java_jfr":
            if (
                self.backend_id != "jfr"
                or self.profile not in {"balanced", "deep"}
                or self.measurement_semantics != "thresholded"
                or tool_names != ("java", "jfr")
                or self.runtime_payload_identity_sha256 is None
            ):
                raise ValueError("Java JFR execution binding has unsupported controls")
            expected_threshold = 10_000_000 if self.profile == "balanced" else 1_000_000
            if self.duration_threshold_ns != expected_threshold:
                raise ValueError("Java JFR profile and execution threshold disagree")
        if self.adapter_id == "cpython_threading":
            expected_threshold = 10_000 if self.measurement_semantics == "thresholded" else None
            if (
                self.backend_id != "threading-bootstrap"
                or self.profile not in {"exact", "thresholded"}
                or self.measurement_semantics not in {"exact", "thresholded"}
                or self.profile != self.measurement_semantics
                or tool_names != ("python",)
                or self.runtime_payload_identity_sha256 is None
                or self.duration_threshold_ns != expected_threshold
            ):
                raise ValueError("CPython threading execution binding has unsupported controls")
        if self.adapter_id == "go_pprof" and (
            self.backend_id != "pprof"
            or self.profile != "mutex_and_block"
            or self.measurement_semantics != "cumulative"
            or self.duration_threshold_ns is not None
            or tool_names != ("go", "pprof")
            or self.runtime_payload_identity_sha256 is not None
        ):
            raise ValueError("Go pprof execution binding has unsupported controls")
        if self.tools and self.toolchain_identity_sha256 != derive_runtime_lock_toolchain_identity(
            self.tools
        ):
            raise ValueError("Runtime Lock toolchain identity differs from its tools")
        expected = derive_runtime_lock_adapter_execution_identity(
            self.adapter_id,
            self.adapter_version,
            self.backend_id,
            self.runtime_version,
            self.profile,
            self.measurement_semantics,
            self.duration_threshold_ns,
            self.toolchain_identity_sha256,
            self.configuration_sha256,
            self.metadata_sha256,
            self.runtime_payload_identity_sha256,
        )
        if self.execution_identity_sha256 != expected:
            raise ValueError("Runtime Lock Adapter execution identity differs from its controls")
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
    schema_version: RuntimeLockSessionSchemaVersion = SCHEMA_VERSION
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
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"schema_version": {"const": "1.0"}},
                        "required": ["schema_version"],
                    },
                    "then": {"properties": {"adapter_execution_bindings": {"maxItems": 0}}},
                },
                {
                    "if": {
                        "anyOf": [
                            {
                                "properties": {
                                    "workload": {
                                        "type": "object",
                                        "properties": {"adapter_id": {"const": "java_jfr"}},
                                        "required": ["adapter_id"],
                                    }
                                },
                                "required": ["workload"],
                            },
                            {
                                "properties": {
                                    "schema_version": {"const": "1.1"},
                                    "workload": {
                                        "type": "object",
                                        "properties": {
                                            "adapter_id": {"const": "cpython_threading"}
                                        },
                                        "required": ["adapter_id"],
                                    },
                                },
                                "required": ["schema_version", "workload"],
                            },
                            {
                                "properties": {
                                    "schema_version": {"const": "1.1"},
                                    "workload": {
                                        "type": "object",
                                        "properties": {"adapter_id": {"const": "go_pprof"}},
                                        "required": ["adapter_id"],
                                    },
                                },
                                "required": ["schema_version", "workload"],
                            },
                        ]
                    },
                    "then": {
                        "required": ["adapter_execution_bindings"],
                        "properties": {
                            "adapter_execution_bindings": {"minItems": 1, "maxItems": 1}
                        },
                    },
                },
            ]
        }
    )

    schema_version: RuntimeLockSessionSchemaVersion = SCHEMA_VERSION
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
    process_target: RuntimeLockProcessTargetBinding | None = None
    adapter_execution_bindings: tuple[RuntimeLockAdapterExecutionBinding, ...] = ()
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
        binding_ids = tuple(item.adapter_id for item in self.adapter_execution_bindings)
        _unique_sorted(binding_ids, "Runtime Lock Preview Adapter execution bindings")
        if any(
            item.adapter_id not in self.allowed_adapters for item in self.adapter_execution_bindings
        ):
            raise ValueError("Runtime Lock Adapter execution binding exceeds Preview scope")
        if any(
            item.measurement_semantics not in self.allowed_semantics
            for item in self.adapter_execution_bindings
        ):
            raise ValueError("Runtime Lock Adapter execution binding exceeds semantics scope")
        if self.schema_version == "1.0" and self.adapter_execution_bindings:
            raise ValueError("Runtime Lock Preview 1.0 cannot carry Adapter execution bindings")
        if self.schema_version == "1.0" and self.process_target is not None:
            raise ValueError("Runtime Lock Preview 1.0 cannot carry a process target")
        if not self.allowed_adapters or not self.allowed_semantics:
            raise ValueError("Runtime Lock Preview requires Adapter and semantics scopes")
        if not self.planned_actions or len(self.planned_actions) > 32:
            raise ValueError("Runtime Lock Preview requires bounded planned actions")
        if self.target_scope == "controlled_import" and not self.import_roots:
            raise ValueError("controlled import requires a reviewed project-relative root")
        if self.target_scope == "controlled_import" and self.workload is not None:
            raise ValueError("controlled import cannot carry an executable workload")
        if self.target_scope == "controlled_import" and self.adapter_execution_bindings:
            raise ValueError("controlled import cannot carry an active execution binding")
        if self.target_scope == "host_launched_workload":
            if self.workload is None:
                raise ValueError("host Runtime Lock Preview requires an exact workload")
            if self.workload.adapter_id not in self.allowed_adapters:
                raise ValueError("Runtime Lock workload Adapter is outside Preview scope")
            if binding_ids and binding_ids != (self.workload.adapter_id,):
                raise ValueError("Runtime Lock workload and execution binding disagree")
            if (
                self.workload.adapter_id == "java_jfr"
                or (
                    self.schema_version == "1.1"
                    and self.workload.adapter_id in {"cpython_threading", "go_pprof"}
                )
            ) and binding_ids != (
                self.workload.adapter_id,
            ):
                raise ValueError("Managed runtime workload requires one exact execution binding")
        if self.target_scope == "host_bound_process":
            if (
                self.schema_version != "1.1"
                or self.process_target is None
                or self.workload is not None
                or self.import_roots
                or self.allowed_adapters != ("go_pprof",)
                or self.allowed_semantics != ("cumulative",)
                or binding_ids != ("go_pprof",)
            ):
                raise ValueError(
                    "host-bound process requires one exact Go pprof cumulative target"
                )
        elif self.process_target is not None:
            raise ValueError("Only a host-bound Runtime Lock Preview may carry a process target")
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
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"schema_version": {"const": "1.0"}},
                        "required": ["schema_version"],
                    },
                    "then": {"properties": {"settlement_finalization_id": {"type": "null"}}},
                }
            ]
        }
    )

    schema_version: RuntimeLockSessionSchemaVersion = SCHEMA_VERSION
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
    settlement_finalization_id: RuntimeLockRunFinalizationId | None = None
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
        if self.schema_version == "1.0" and self.settlement_finalization_id is not None:
            raise ValueError("Runtime Lock Session 1.0 cannot carry a settlement marker")
        if self.revision == 0 and self.settlement_finalization_id is not None:
            raise ValueError("initial Runtime Lock Session state cannot settle an operation")
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
            self.settlement_finalization_id,
        )
        if self.session_artifact_id != expected:
            raise ValueError("Runtime Lock Session Artifact ID differs from its state")
        return self


class RuntimeLockRunArtifact(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"schema_version": {"const": "1.0"}},
                        "required": ["schema_version"],
                    },
                    "then": {"properties": {"adapter_execution_identity_sha256": {"type": "null"}}},
                },
                {
                    "if": {
                        "anyOf": [
                            {
                                "properties": {"adapter_id": {"const": "java_jfr"}},
                                "required": ["adapter_id"],
                            },
                            {
                                "properties": {
                                    "schema_version": {"const": "1.1"},
                                    "adapter_id": {"const": "cpython_threading"},
                                },
                                "required": ["schema_version", "adapter_id"],
                            },
                            {
                                "properties": {
                                    "schema_version": {"const": "1.1"},
                                    "adapter_id": {"const": "go_pprof"},
                                },
                                "required": ["schema_version", "adapter_id"],
                            },
                        ]
                    },
                    "then": {
                        "required": ["adapter_execution_identity_sha256"],
                        "properties": {"adapter_execution_identity_sha256": {"type": "string"}},
                    },
                },
            ]
        }
    )

    schema_version: RuntimeLockSessionSchemaVersion = SCHEMA_VERSION
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
    adapter_execution_identity_sha256: Sha256 | None = None
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
    quality_status: RuntimeLockRunQualityStatus
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
        for conclusions, label in (
            (self.allowed_conclusions, "allowed"),
            (self.forbidden_conclusions, "forbidden"),
        ):
            if any(not conclusion.strip() for conclusion in conclusions):
                raise ValueError(f"Runtime Lock Run {label} conclusions cannot be blank")
            if len(set(conclusions)) != len(conclusions):
                raise ValueError(f"Runtime Lock Run {label} conclusions must be unique")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("Runtime Lock Run conclusion boundaries must be disjoint")
        has_partial_gate = _UNQUALIFIED_RUNTIME_LOCK_CONCLUSION in self.forbidden_conclusions
        if self.quality_status == "partial" and not has_partial_gate:
            raise ValueError("Partial Runtime Lock Run must forbid unqualified conclusions")
        if self.quality_status == "complete" and has_partial_gate:
            raise ValueError("Complete Runtime Lock Run cannot carry the partial-quality gate")
        if self.measurement_semantics == "exact" and (
            self.duration_seconds > 3 or self.event_count > 20_000
        ):
            raise ValueError("exact Runtime Lock Run exceeds its hard evidence bound")
        if self.schema_version == "1.0" and self.adapter_execution_identity_sha256 is not None:
            raise ValueError("Runtime Lock Run 1.0 cannot carry an Adapter execution identity")
        if (
            self.adapter_id == "java_jfr"
            or (
                self.schema_version == "1.1"
                and self.adapter_id in {"cpython_threading", "go_pprof"}
            )
        ) and (
            self.adapter_execution_identity_sha256 is None
        ):
            raise ValueError("Managed runtime Run requires its authorized execution identity")
        expected = derive_runtime_lock_run_id(
            self.session_id,
            self.adapter_id,
            self.runtime_lock_evidence_content_sha256,
            self.started_at,
        )
        if self.run_id != expected:
            raise ValueError("Runtime Lock Run ID differs from its evidence")
        return self


class RuntimeLockRunFinalizationArtifact(ContractModel):
    """Commit marker written after a Run and its reconciled Session revision.

    The marker ID is operation-stable, while its content binds both immutable
    artifacts.  Consequently a Run saved before Session settlement remains
    deliberately unreadable until this marker is written last.
    """

    schema_version: Literal["1.1"] = "1.1"
    perflens_version: str
    finalization_id: RuntimeLockRunFinalizationId
    created_at: str
    session_id: RuntimeLockSessionId
    operation_identity_sha256: Sha256
    outcome: Literal["completed", "failed"]
    adapter_id: RuntimeLockAdapterId
    measurement_semantics: MeasurementSemantics
    reserved_session_artifact_id: RuntimeLockSessionArtifactId
    reserved_session_artifact_content_sha256: Sha256
    reserved_session_revision: int = Field(ge=1)
    final_session_artifact_id: RuntimeLockSessionArtifactId
    final_session_artifact_content_sha256: Sha256
    final_session_revision: int = Field(ge=2)
    reserved_active_seconds: int = Field(ge=1, le=30)
    reserved_evidence_bytes: int = Field(ge=1, le=512 << 20)
    reserved_exact_events: int = Field(ge=0, le=20_000)
    accounted_active_seconds: int = Field(ge=0, le=30)
    accounted_evidence_bytes: int = Field(ge=0, le=512 << 20)
    accounted_exact_events: int = Field(ge=0, le=20_000)
    run_id: RuntimeLockRunId | None = None
    run_content_sha256: Sha256 | None = None
    failure_reason: RuntimeLockSessionEndReason | None = None
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_finalization(self) -> RuntimeLockRunFinalizationArtifact:
        _timestamp(self.created_at, "Runtime Lock Run finalization time")
        if self.final_session_revision != self.reserved_session_revision + 1:
            raise ValueError("Runtime Lock finalization must immediately follow its reservation")
        if (
            self.accounted_active_seconds > self.reserved_active_seconds
            or self.accounted_evidence_bytes > self.reserved_evidence_bytes
            or self.accounted_exact_events > self.reserved_exact_events
        ):
            raise ValueError("Runtime Lock finalization usage exceeds its reservation")
        if self.measurement_semantics == "exact":
            if self.reserved_exact_events == 0:
                raise ValueError("exact Runtime Lock finalization requires an event reservation")
        elif self.reserved_exact_events or self.accounted_exact_events:
            raise ValueError("non-exact Runtime Lock finalization cannot account exact events")
        run_values = (self.run_id, self.run_content_sha256)
        if self.outcome == "completed":
            if any(value is None for value in run_values) or self.failure_reason is not None:
                raise ValueError("completed Runtime Lock finalization must bind one Run")
        elif any(value is not None for value in run_values) or self.failure_reason is None:
            raise ValueError("failed Runtime Lock finalization must bind one terminal reason")
        expected = derive_runtime_lock_run_finalization_id(
            self.session_id,
            self.operation_identity_sha256,
        )
        if self.finalization_id != expected:
            raise ValueError("Runtime Lock finalization ID differs from its operation")
        return self


class RuntimeLockComparisonArtifact(ContractModel):
    schema_version: RuntimeLockSessionSchemaVersion = SCHEMA_VERSION
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
