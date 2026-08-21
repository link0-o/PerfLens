"""Versioned public contracts for the v0.3.1 local-Docker target runtime.

The contracts intentionally contain only bounded, Agent-visible projections.
Docker socket paths, raw inspect responses, environment variables, labels,
secrets, host mount source paths, and process argument vectors discovered from
an existing container are private adapter data and never belong here.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from perflens.contracts.artifacts import SCHEMA_VERSION, ContractModel

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
DockerCapabilityId = Annotated[str, Field(pattern=r"^docker-capability-[a-f0-9]{20}$")]
ContainerTargetId = Annotated[str, Field(pattern=r"^container-target-[a-f0-9]{20}$")]
ContainerInventoryId = Annotated[str, Field(pattern=r"^container-inventory-[a-f0-9]{20}$")]
ContainerResourceId = Annotated[str, Field(pattern=r"^container-resource-[a-f0-9]{20}$")]
ContainerWorkloadId = Annotated[str, Field(pattern=r"^container-workload-[a-f0-9]{20}$")]
ContainerSessionId = Annotated[str, Field(pattern=r"^container-session-[a-f0-9]{20}$")]
ContainerRunId = Annotated[str, Field(pattern=r"^container-run-[a-f0-9]{20}$")]
CollectionId = Annotated[str, Field(pattern=r"^collection-[a-f0-9]{16}$")]

CollectionMode = Literal["stat", "record", "sched", "off_cpu", "lock"]
DockerTargetKind = Literal["existing_container", "managed_temporary_container"]
AuthorizationMode = Literal["per_run", "bounded_session"]


def _validate_unique_sorted(values: tuple[str, ...], label: str) -> None:
    if len(set(values)) != len(values) or tuple(sorted(values)) != values:
        raise ValueError(f"{label} must be unique and sorted")


def _validate_container_absolute_path(value: str, label: str) -> None:
    if not value.startswith("/") or "\x00" in value:
        raise ValueError(f"{label} must be an absolute container path")
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value:
        raise ValueError(f"{label} must be normalized and traversal-free")


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def derive_container_resource_context_id(
    *,
    container_identity_sha256: str,
    cgroup_identity_sha256: str,
    source_collection_id: str,
    source_output_sha256: str,
    before_observed_at: str,
    after_observed_at: str,
    created_at: str,
) -> str:
    material = "\0".join(
        (
            "perflens-docker-resource-context-v1",
            container_identity_sha256,
            cgroup_identity_sha256,
            source_collection_id,
            source_output_sha256,
            before_observed_at,
            after_observed_at,
            created_at,
        )
    )
    return f"container-resource-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


class DockerToolIdentity(ContractModel):
    path: str
    version: str = Field(min_length=1, max_length=256)
    binary_sha256: Sha256

    @model_validator(mode="after")
    def validate_path(self) -> DockerToolIdentity:
        if not self.path.startswith("/") or "\x00" in self.path:
            raise ValueError("Docker CLI path must be absolute")
        return self


class DockerRuntimeCapabilityArtifact(ContractModel):
    """Read-only capability result for one fixed local Docker endpoint."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    capability_id: DockerCapabilityId
    checked_at: str
    status: Literal["available", "partial", "unavailable"]
    endpoint_kind: Literal["local_rootful", "local_rootless", "unsupported", "missing"]
    daemon_mode: Literal["rootful", "rootless", "unknown"]
    docker_cli: DockerToolIdentity | None = None
    api_version: str | None = Field(default=None, max_length=64)
    server_operating_system: Literal["linux", "unknown"] = "unknown"
    cgroup_version: Literal["v2", "v1", "unknown"] = "unknown"
    existing_container_discovery: bool = False
    managed_container_execution: bool = False
    build_or_pull_supported: Literal[False] = False
    remote_endpoint_supported: Literal[False] = False
    limitations: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_capability(self) -> DockerRuntimeCapabilityArtifact:
        if self.status == "available":
            if (
                self.endpoint_kind not in {"local_rootful", "local_rootless"}
                or self.daemon_mode == "unknown"
                or self.docker_cli is None
                or self.server_operating_system != "linux"
                or self.cgroup_version != "v2"
                or not self.existing_container_discovery
                or not self.managed_container_execution
            ):
                raise ValueError(
                    "available Docker capability requires a local Linux cgroup-v2 endpoint"
                )
            if self.limitations:
                raise ValueError("available Docker capability cannot carry capability limitations")
        elif not self.limitations:
            raise ValueError("non-available Docker capability must explain its limitations")
        if self.endpoint_kind in {"unsupported", "missing"} and (
            self.existing_container_discovery or self.managed_container_execution
        ):
            raise ValueError("unsupported Docker endpoints cannot expose active operations")
        return self


class ContainerNamespaceIdentity(ContractModel):
    pid_namespace_inode: int = Field(gt=0)
    user_namespace_inode: int = Field(gt=0)
    mount_namespace_inode: int = Field(gt=0)
    cgroup_namespace_inode: int = Field(gt=0)


class ContainerCgroupIdentity(ContractModel):
    version: Literal["v2"] = "v2"
    inode: int = Field(gt=0)
    identity_sha256: Sha256


class ContainerTargetArtifact(ContractModel):
    """Public proof that one container process maps to one immutable host PID."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    target_id: ContainerTargetId
    created_at: str
    target_kind: DockerTargetKind
    container_identity_sha256: Sha256
    image_identity_sha256: Sha256
    container_pid: int = Field(gt=0)
    host_pid: int = Field(gt=0)
    host_uid: int = Field(ge=0)
    host_start_time_ticks: int = Field(gt=0)
    executable_name: str = Field(pattern=r"^[^/\x00]{1,255}$")
    namespace: ContainerNamespaceIdentity
    cgroup: ContainerCgroupIdentity
    uid_mapping: Literal["rootless_same_uid", "rootful_same_uid", "rootful_cross_uid"]
    rootful_risk_authorized: bool = False
    adapter_recipe_id: Literal["local-docker-read-v1", "local-docker-managed-v1"]
    adapter_sha256: Sha256
    identity_fingerprint: Sha256
    validation_status: Literal["verified"] = "verified"
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_target(self) -> ContainerTargetArtifact:
        expected_recipe = (
            "local-docker-read-v1"
            if self.target_kind == "existing_container"
            else "local-docker-managed-v1"
        )
        if self.adapter_recipe_id != expected_recipe:
            raise ValueError("Docker target kind does not match its fixed adapter recipe")
        if self.uid_mapping == "rootful_cross_uid" and not self.rootful_risk_authorized:
            raise ValueError(
                "cross-UID rootful Docker targets require explicit administrator policy"
            )
        if self.uid_mapping != "rootful_cross_uid" and self.rootful_risk_authorized:
            raise ValueError("same-UID Docker targets cannot claim cross-UID risk authorization")
        return self


class ContainerProcessCandidate(ContractModel):
    container_pid: int = Field(gt=0)
    host_pid: int = Field(gt=0)
    executable_name: str = Field(pattern=r"^[^/\x00]{1,255}$")
    cpu_delta_ticks: int = Field(ge=0)
    recommendation: Literal["dominant", "candidate"]


class ContainerProcessInventoryArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    inventory_id: ContainerInventoryId
    created_at: str
    container_identity_sha256: Sha256
    observation_duration_ms: int = Field(gt=0, le=10_000)
    candidates: tuple[ContainerProcessCandidate, ...]
    candidate_count: int = Field(ge=0)
    candidates_truncated: bool
    automatic_recommendation: Literal["unique", "dominant", "ambiguous", "none"]
    recommended_host_pid: int | None = Field(default=None, gt=0)
    limitations: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> ContainerProcessInventoryArtifact:
        if len(self.candidates) > 256:
            raise ValueError("Docker process inventory exceeds the public candidate limit")
        if self.candidate_count < len(self.candidates):
            raise ValueError("Docker candidate_count cannot be smaller than exported candidates")
        host_pids = tuple(item.host_pid for item in self.candidates)
        if len(set(host_pids)) != len(host_pids):
            raise ValueError("Docker process candidates must have unique host PIDs")
        recommended = tuple(
            item.host_pid for item in self.candidates if item.recommendation == "dominant"
        )
        if self.automatic_recommendation in {"unique", "dominant"}:
            if self.recommended_host_pid is None or self.recommended_host_pid not in host_pids:
                raise ValueError(
                    "automatic Docker recommendation must reference an exported candidate"
                )
            if len(recommended) != 1 or recommended[0] != self.recommended_host_pid:
                raise ValueError(
                    "automatic Docker recommendation must identify one dominant candidate"
                )
        elif self.recommended_host_pid is not None or recommended:
            raise ValueError("ambiguous or empty inventories cannot recommend a process")
        return self


class PressureSnapshot(ContractModel):
    some_total_us: int | None = Field(default=None, ge=0)
    full_total_us: int | None = Field(default=None, ge=0)


class CgroupIoDeviceSnapshot(ContractModel):
    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    read_bytes: int = Field(ge=0)
    write_bytes: int = Field(ge=0)
    read_ios: int = Field(ge=0)
    write_ios: int = Field(ge=0)


class ContainerResourceSnapshot(ContractModel):
    observed_at: str
    cpu_usage_usec: int = Field(ge=0)
    cpu_user_usec: int | None = Field(default=None, ge=0)
    cpu_system_usec: int | None = Field(default=None, ge=0)
    cpu_nr_periods: int | None = Field(default=None, ge=0)
    cpu_nr_throttled: int | None = Field(default=None, ge=0)
    cpu_throttled_usec: int | None = Field(default=None, ge=0)
    cpu_quota_usec: int | None = Field(default=None, gt=0)
    cpu_period_usec: int = Field(gt=0)
    cpuset_cpus_effective: str = Field(min_length=1, max_length=4096)
    memory_current_bytes: int = Field(ge=0)
    memory_max_bytes: int | None = Field(default=None, gt=0)
    memory_events: tuple[tuple[str, int], ...] = ()
    memory_pressure: PressureSnapshot | None = None
    io_devices: tuple[CgroupIoDeviceSnapshot, ...] = ()
    io_pressure: PressureSnapshot | None = None
    pids_current: int = Field(ge=0)
    pids_max: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_snapshot(self) -> ContainerResourceSnapshot:
        if len(self.memory_events) > 64 or len(self.io_devices) > 256:
            raise ValueError("cgroup snapshot exceeds public cardinality limits")
        keys = tuple(key for key, _ in self.memory_events)
        if any(not key or len(key) > 64 or not key.replace("_", "").isalnum() for key in keys):
            raise ValueError("memory event names must be bounded identifiers")
        if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
            raise ValueError("memory event counters must be unique and sorted")
        devices = tuple((item.major, item.minor) for item in self.io_devices)
        if len(set(devices)) != len(devices) or tuple(sorted(devices)) != devices:
            raise ValueError("I/O devices must be unique and sorted")
        return self


class ContainerResourceDelta(ContractModel):
    cpu_usage_usec: int = Field(ge=0)
    cpu_user_usec: int | None = Field(default=None, ge=0)
    cpu_system_usec: int | None = Field(default=None, ge=0)
    cpu_nr_periods: int | None = Field(default=None, ge=0)
    cpu_nr_throttled: int | None = Field(default=None, ge=0)
    cpu_throttled_usec: int | None = Field(default=None, ge=0)
    memory_event_deltas: tuple[tuple[str, int], ...] = ()
    io_read_bytes: int = Field(ge=0)
    io_write_bytes: int = Field(ge=0)
    io_read_ios: int = Field(ge=0)
    io_write_ios: int = Field(ge=0)
    memory_pressure_some_usec: int | None = Field(default=None, ge=0)
    memory_pressure_full_usec: int | None = Field(default=None, ge=0)
    io_pressure_some_usec: int | None = Field(default=None, ge=0)
    io_pressure_full_usec: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_delta(self) -> ContainerResourceDelta:
        if len(self.memory_event_deltas) > 64:
            raise ValueError("memory event deltas exceed the public cardinality limit")
        keys = tuple(key for key, _ in self.memory_event_deltas)
        values = tuple(value for _, value in self.memory_event_deltas)
        if any(value < 0 for value in values):
            raise ValueError("memory event deltas cannot be negative")
        if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
            raise ValueError("memory event deltas must be unique and sorted")
        return self


def _exact_delta(before: int, after: int, label: str) -> int:
    if after < before:
        raise ValueError(f"{label} counter cannot decrease within one cgroup identity")
    return after - before


def _optional_exact_delta(
    before: int | None,
    after: int | None,
    label: str,
) -> int | None:
    if before is None or after is None:
        return None
    return _exact_delta(before, after, label)


def _resource_delta_from_snapshots(
    before: ContainerResourceSnapshot,
    after: ContainerResourceSnapshot,
) -> ContainerResourceDelta:
    memory_before = dict(before.memory_events)
    memory_after = dict(after.memory_events)

    def io_totals(
        snapshot: ContainerResourceSnapshot,
        field: Literal["read_bytes", "write_bytes", "read_ios", "write_ios"],
    ) -> dict[tuple[int, int], int]:
        return {
            (device.major, device.minor): getattr(device, field)
            for device in snapshot.io_devices
        }

    def io_delta(
        field: Literal["read_bytes", "write_bytes", "read_ios", "write_ios"],
    ) -> int:
        first = io_totals(before, field)
        second = io_totals(after, field)
        return sum(
            _exact_delta(
                first.get(device, 0),
                second.get(device, 0),
                f"I/O {field}",
            )
            for device in first.keys() | second.keys()
        )

    def pressure_delta(
        field: Literal["some_total_us", "full_total_us"],
        first: PressureSnapshot | None,
        second: PressureSnapshot | None,
        label: str,
    ) -> int | None:
        if first is None or second is None:
            return None
        return _optional_exact_delta(
            getattr(first, field),
            getattr(second, field),
            label,
        )

    return ContainerResourceDelta(
        cpu_usage_usec=_exact_delta(
            before.cpu_usage_usec,
            after.cpu_usage_usec,
            "CPU usage",
        ),
        cpu_user_usec=_optional_exact_delta(
            before.cpu_user_usec,
            after.cpu_user_usec,
            "CPU user",
        ),
        cpu_system_usec=_optional_exact_delta(
            before.cpu_system_usec,
            after.cpu_system_usec,
            "CPU system",
        ),
        cpu_nr_periods=_optional_exact_delta(
            before.cpu_nr_periods,
            after.cpu_nr_periods,
            "CPU periods",
        ),
        cpu_nr_throttled=_optional_exact_delta(
            before.cpu_nr_throttled,
            after.cpu_nr_throttled,
            "CPU throttled periods",
        ),
        cpu_throttled_usec=_optional_exact_delta(
            before.cpu_throttled_usec,
            after.cpu_throttled_usec,
            "CPU throttled time",
        ),
        memory_event_deltas=tuple(
            (
                name,
                _exact_delta(
                    memory_before.get(name, 0),
                    memory_after.get(name, 0),
                    f"memory event {name}",
                ),
            )
            for name in sorted(memory_before.keys() | memory_after.keys())
        ),
        io_read_bytes=io_delta("read_bytes"),
        io_write_bytes=io_delta("write_bytes"),
        io_read_ios=io_delta("read_ios"),
        io_write_ios=io_delta("write_ios"),
        memory_pressure_some_usec=pressure_delta(
            "some_total_us",
            before.memory_pressure,
            after.memory_pressure,
            "memory pressure some",
        ),
        memory_pressure_full_usec=pressure_delta(
            "full_total_us",
            before.memory_pressure,
            after.memory_pressure,
            "memory pressure full",
        ),
        io_pressure_some_usec=pressure_delta(
            "some_total_us",
            before.io_pressure,
            after.io_pressure,
            "I/O pressure some",
        ),
        io_pressure_full_usec=pressure_delta(
            "full_total_us",
            before.io_pressure,
            after.io_pressure,
            "I/O pressure full",
        ),
    )


class ContainerResourceContextArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    resource_context_id: ContainerResourceId
    created_at: str
    container_identity_sha256: Sha256
    cgroup_identity_sha256: Sha256
    source_collection_id: CollectionId
    source_output_sha256: Sha256
    scope: Literal["entire_container_cgroup_v2"] = "entire_container_cgroup_v2"
    before: ContainerResourceSnapshot
    after: ContainerResourceSnapshot
    delta: ContainerResourceDelta
    quality_status: Literal["verified", "partial"]
    limitations: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_context(self) -> ContainerResourceContextArtifact:
        if self.resource_context_id != derive_container_resource_context_id(
            container_identity_sha256=self.container_identity_sha256,
            cgroup_identity_sha256=self.cgroup_identity_sha256,
            source_collection_id=self.source_collection_id,
            source_output_sha256=self.source_output_sha256,
            before_observed_at=self.before.observed_at,
            after_observed_at=self.after.observed_at,
            created_at=self.created_at,
        ):
            raise ValueError("container resource identity does not match its bound evidence")
        if _timestamp(self.before.observed_at, "before.observed_at") >= _timestamp(
            self.after.observed_at,
            "after.observed_at",
        ):
            raise ValueError("container resource snapshots must be time ordered")
        if _timestamp(self.created_at, "created_at") < _timestamp(
            self.after.observed_at,
            "after.observed_at",
        ):
            raise ValueError("container resource creation cannot precede its final snapshot")
        if self.delta != _resource_delta_from_snapshots(self.before, self.after):
            raise ValueError("container resource delta does not match its snapshots")
        environment_changed = (
            self.before.cpu_quota_usec != self.after.cpu_quota_usec
            or self.before.cpu_period_usec != self.after.cpu_period_usec
            or self.before.cpuset_cpus_effective != self.after.cpuset_cpus_effective
            or self.before.memory_max_bytes != self.after.memory_max_bytes
            or self.before.pids_max != self.after.pids_max
        )
        if environment_changed and self.quality_status != "partial":
            raise ValueError("container resource limit drift must be reported as partial")
        if self.quality_status == "partial" and not self.limitations:
            raise ValueError("partial container resource context must explain its limitations")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container resource context must preserve its conclusion boundary")
        return self


class ContainerResourceLimits(ContractModel):
    cpus: float = Field(gt=0, le=1024)
    memory_bytes: int = Field(ge=6 << 20, le=1 << 50)
    pids: int = Field(gt=0, le=1_000_000)


class ContainerWorkloadSpecArtifact(ContractModel):
    """Fixed managed-container recipe; no arbitrary Docker argument surface exists."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    workload_spec_id: ContainerWorkloadId
    created_at: str
    project_identity_sha256: Sha256
    image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    container_gate_sha256: Sha256
    entrypoint: str
    arguments: tuple[str, ...] = ()
    working_directory: str
    workspace_container_path: Literal["/workspace"] = "/workspace"
    workspace_read_only: Literal[True] = True
    scratch_container_path: Literal["/perflens-scratch"] = "/perflens-scratch"
    network_mode: Literal["none"] = "none"
    container_user: str = Field(pattern=r"^[0-9]{1,10}(?::[0-9]{1,10})?$")
    resources: ContainerResourceLimits
    allowed_modes: tuple[CollectionMode, ...]
    authorization_mode: AuthorizationMode
    max_workload_runs: int = Field(default=6, gt=0, le=6)
    max_active_seconds: int = Field(default=1200, gt=0, le=1200)
    hard_expiry_seconds: int = Field(default=7200, gt=0, le=7200)
    trace_max_duration_seconds: int = Field(default=10, gt=0, le=10)
    cleanup_policy: Literal["verified_session_containers_only"] = (
        "verified_session_containers_only"
    )
    correctness_command_sha256: Sha256 | None = None
    benchmark_output_contract_sha256: Sha256 | None = None
    workload_fingerprint: Sha256
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_workload(self) -> ContainerWorkloadSpecArtifact:
        _validate_container_absolute_path(self.entrypoint, "entrypoint")
        _validate_container_absolute_path(self.working_directory, "working_directory")
        if len(self.arguments) > 256 or sum(len(value) for value in self.arguments) > 65_536:
            raise ValueError("container workload arguments exceed bounded limits")
        if any("\x00" in value or len(value) > 4096 for value in self.arguments):
            raise ValueError("container workload arguments must be bounded NUL-free strings")
        user_ids = tuple(int(value) for value in self.container_user.split(":"))
        if any(value > 4_294_967_295 for value in user_ids):
            raise ValueError("container workload UID/GID exceeds the Linux identifier range")
        if not self.allowed_modes:
            raise ValueError("container workload must allow at least one collection mode")
        if len(set(self.allowed_modes)) != len(self.allowed_modes):
            raise ValueError("container workload modes must be unique")
        canonical_modes = ("stat", "record", "sched", "off_cpu", "lock")
        if tuple(sorted(self.allowed_modes, key=canonical_modes.index)) != self.allowed_modes:
            raise ValueError("container workload modes must use canonical order")
        if self.hard_expiry_seconds < self.max_active_seconds:
            raise ValueError("container workload hard expiry cannot be shorter than active budget")
        return self


class ContainerOptimizationSessionArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    session_id: ContainerSessionId
    created_at: str
    expires_at: str
    target_kind: DockerTargetKind
    authorization_mode: AuthorizationMode
    project_identity_sha256: Sha256
    client_connection_identity_sha256: Sha256
    authorization_receipt_sha256: Sha256
    workload_spec_sha256: Sha256 | None = None
    existing_target_identity_sha256: Sha256 | None = None
    allowed_modes: tuple[CollectionMode, ...]
    state: Literal["active", "revoked", "expired", "exhausted"]
    max_workload_runs: int = Field(gt=0, le=6)
    workload_runs_used: int = Field(ge=0, le=6)
    max_active_seconds: int = Field(gt=0, le=1200)
    active_seconds_used: int = Field(ge=0, le=1200)
    max_evidence_bytes: int = Field(gt=0, le=1 << 40)
    evidence_bytes_used: int = Field(ge=0, le=1 << 40)
    instance_count: int = Field(ge=0, le=6)
    invalidation_reason: str | None = Field(default=None, min_length=1, max_length=512)
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_session(self) -> ContainerOptimizationSessionArtifact:
        if self.target_kind == "managed_temporary_container":
            if (
                self.workload_spec_sha256 is None
                or self.existing_target_identity_sha256 is not None
            ):
                raise ValueError("managed Docker session must bind exactly one workload spec")
        elif self.existing_target_identity_sha256 is None or self.workload_spec_sha256 is not None:
            raise ValueError("existing Docker session must bind exactly one target identity")
        if self.authorization_mode == "per_run" and self.max_workload_runs != 1:
            raise ValueError("per_run Docker authorization permits exactly one workload run")
        if _timestamp(self.created_at, "created_at") >= _timestamp(self.expires_at, "expires_at"):
            raise ValueError("Docker session expiry must be after creation")
        if self.workload_runs_used > self.max_workload_runs:
            raise ValueError("Docker session workload budget is overdrawn")
        if self.active_seconds_used > self.max_active_seconds:
            raise ValueError("Docker session active-time budget is overdrawn")
        if self.evidence_bytes_used > self.max_evidence_bytes:
            raise ValueError("Docker session evidence budget is overdrawn")
        if self.state == "active" and self.invalidation_reason is not None:
            raise ValueError("active Docker session cannot carry an invalidation reason")
        if self.state != "active" and self.invalidation_reason is None:
            raise ValueError("inactive Docker session must explain why it ended")
        return self


class ContainerRunArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    run_id: ContainerRunId
    created_at: str
    session_id: ContainerSessionId
    workload_spec_sha256: Sha256
    container_identity_sha256: Sha256
    image_identity_sha256: Sha256
    target_identity_sha256: Sha256
    container_pid: int = Field(gt=0)
    host_pid: int = Field(gt=0)
    host_start_time_ticks: int = Field(gt=0)
    started_at: str
    finished_at: str
    status: Literal["exited", "terminated_after_collection", "failed_before_exec"]
    exit_code: int | None = None
    collection_ids: tuple[CollectionId, ...] = ()
    build_artifact_sha256: tuple[Sha256, ...] = ()
    resource_context_id: str | None = Field(
        default=None,
        pattern=r"^container-resource-[a-f0-9]{20}$",
    )
    cleanup_status: Literal["removed", "preserved_for_manual_cleanup", "not_started"]
    warnings: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_run(self) -> ContainerRunArtifact:
        if _timestamp(self.started_at, "started_at") >= _timestamp(
            self.finished_at,
            "finished_at",
        ):
            raise ValueError("container run timestamps must be ordered")
        _validate_unique_sorted(self.collection_ids, "container collection IDs")
        _validate_unique_sorted(self.build_artifact_sha256, "container build artifact hashes")
        if self.status == "failed_before_exec" and self.exit_code is not None:
            raise ValueError("pre-exec Docker failure cannot claim a workload exit code")
        if self.status != "failed_before_exec" and self.exit_code is None:
            raise ValueError("completed Docker workload must report its exit code")
        return self
