"""Versioned public contracts for the v0.3.1 local-Docker target runtime.

The contracts intentionally contain only bounded, Agent-visible projections.
Docker socket paths, raw inspect responses, environment variables, labels,
secrets, host mount source paths, and process argument vectors discovered from
an existing container are private adapter data and never belong here.
"""

from __future__ import annotations

import hashlib
import json
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
ContainerModuleSnapshotId = Annotated[
    str,
    Field(pattern=r"^container-modules-[a-f0-9]{20}$"),
]
ContainerSymbolContextId = Annotated[
    str,
    Field(pattern=r"^container-symbols-[a-f0-9]{20}$"),
]
ContainerWorkloadId = Annotated[str, Field(pattern=r"^container-workload-[a-f0-9]{20}$")]
ContainerSessionId = Annotated[str, Field(pattern=r"^container-session-[a-f0-9]{20}$")]
ContainerRunId = Annotated[str, Field(pattern=r"^container-run-[a-f0-9]{20}$")]
ContainerMeasurementId = Annotated[
    str,
    Field(pattern=r"^container-measurement-[a-f0-9]{20}$"),
]
ContainerComparisonId = Annotated[
    str,
    Field(pattern=r"^container-comparison-[a-f0-9]{20}$"),
]
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


def derive_container_module_snapshot_id(source_collection_id: str) -> str:
    material = f"perflens-docker-module-snapshot-v1\0{source_collection_id}"
    return f"container-modules-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def derive_container_symbol_context_id(source_analysis_id: str) -> str:
    material = f"perflens-docker-symbol-context-v1\0{source_analysis_id}"
    return f"container-symbols-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def derive_container_measurement_id(source_collection_id: str) -> str:
    material = f"perflens-docker-measurement-v1\0{source_collection_id}"
    return f"container-measurement-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def container_environment_fingerprint(environment: ContainerEnvironmentFingerprint) -> str:
    payload = environment.model_dump(
        mode="json",
        exclude={"environment_fingerprint_sha256"},
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


class CgroupIoDeviceLimit(ContractModel):
    """One normalized cgroup-v2 ``io.max`` device limit.

    A missing value means that dimension is unlimited. Entries where every
    dimension is unlimited are omitted by the parser, so exported entries
    always carry at least one effective limit.
    """

    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    read_bps: int | None = Field(default=None, gt=0)
    write_bps: int | None = Field(default=None, gt=0)
    read_iops: int | None = Field(default=None, gt=0)
    write_iops: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_effective_limit(self) -> CgroupIoDeviceLimit:
        if all(
            value is None
            for value in (self.read_bps, self.write_bps, self.read_iops, self.write_iops)
        ):
            raise ValueError("I/O limit entry must contain at least one effective limit")
        return self


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
    io_limits: tuple[CgroupIoDeviceLimit, ...] = ()
    io_pressure: PressureSnapshot | None = None
    pids_current: int = Field(ge=0)
    pids_max: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_snapshot(self) -> ContainerResourceSnapshot:
        if len(self.memory_events) > 64 or len(self.io_devices) > 256 or len(self.io_limits) > 256:
            raise ValueError("cgroup snapshot exceeds public cardinality limits")
        keys = tuple(key for key, _ in self.memory_events)
        if any(not key or len(key) > 64 or not key.replace("_", "").isalnum() for key in keys):
            raise ValueError("memory event names must be bounded identifiers")
        if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
            raise ValueError("memory event counters must be unique and sorted")
        devices = tuple((item.major, item.minor) for item in self.io_devices)
        if len(set(devices)) != len(devices) or tuple(sorted(devices)) != devices:
            raise ValueError("I/O devices must be unique and sorted")
        limited_devices = tuple((item.major, item.minor) for item in self.io_limits)
        if (
            len(set(limited_devices)) != len(limited_devices)
            or tuple(sorted(limited_devices)) != limited_devices
        ):
            raise ValueError("I/O limit devices must be unique and sorted")
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
            (device.major, device.minor): getattr(device, field) for device in snapshot.io_devices
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
            or self.before.io_limits != self.after.io_limits
            or self.before.pids_max != self.after.pids_max
        )
        if environment_changed and self.quality_status != "partial":
            raise ValueError("container resource limit drift must be reported as partial")
        if self.quality_status == "partial" and not self.limitations:
            raise ValueError("partial container resource context must explain its limitations")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container resource context must preserve its conclusion boundary")
        return self


class ContainerModuleEvidence(ContractModel):
    """One perf-referenced module without exposing its container path."""

    container_path_sha256: Sha256
    recorded_build_id: str = Field(pattern=r"^[a-f0-9]{8,128}$")
    observed_build_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{8,128}$")
    content_sha256: Sha256 | None = None
    file_bytes: int | None = Field(default=None, gt=0)
    status: Literal["verified", "unavailable", "identity_mismatch", "limit_exceeded"]

    @model_validator(mode="after")
    def validate_module(self) -> ContainerModuleEvidence:
        has_file_evidence = any(
            item is not None
            for item in (self.observed_build_id, self.content_sha256, self.file_bytes)
        )
        complete = (
            self.observed_build_id is not None
            and self.content_sha256 is not None
            and self.file_bytes is not None
        )
        if self.status == "verified":
            if not complete or self.observed_build_id != self.recorded_build_id:
                raise ValueError("verified container module must match its recorded Build ID")
        elif self.status == "identity_mismatch":
            if not complete or self.observed_build_id == self.recorded_build_id:
                raise ValueError("module identity mismatch must preserve both differing identities")
        elif has_file_evidence:
            raise ValueError("unavailable container modules cannot claim file evidence")
        return self


class ContainerModuleSnapshotLimits(ContractModel):
    max_modules: int = Field(gt=0, le=1024)
    max_module_bytes: int = Field(gt=0, le=1 << 30)
    max_total_module_bytes: int = Field(gt=0, le=4 << 30)
    max_build_id_output_bytes: int = Field(gt=0, le=16 << 20)


class ContainerModuleSnapshotArtifact(ContractModel):
    """Capture-time, target-bound module identities for one Docker record Collection."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    module_snapshot_id: ContainerModuleSnapshotId
    created_at: str
    source_collection_id: CollectionId
    source_output_sha256: Sha256
    container_target_id: ContainerTargetId
    container_target_content_sha256: Sha256
    container_identity_sha256: Sha256
    mount_namespace_inode: int = Field(gt=0)
    process_root_identity_sha256: Sha256 | None = None
    adapter_recipe_id: Literal["perf-buildid-list-with-hits-v1"]
    adapter_sha256: Sha256
    status: Literal["verified", "partial"]
    referenced_module_count: int = Field(ge=0)
    modules: tuple[ContainerModuleEvidence, ...] = ()
    modules_truncated: bool = False
    limits: ContainerModuleSnapshotLimits
    limitations: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self) -> ContainerModuleSnapshotArtifact:
        if self.module_snapshot_id != derive_container_module_snapshot_id(
            self.source_collection_id
        ):
            raise ValueError("container module snapshot ID does not match its Collection")
        module_keys = tuple(item.container_path_sha256 for item in self.modules)
        _validate_unique_sorted(module_keys, "container module path digests")
        if self.referenced_module_count < len(self.modules):
            raise ValueError("exported container modules exceed the observed module count")
        if self.referenced_module_count > len(self.modules) and not self.modules_truncated:
            raise ValueError("omitted container modules must be reported as truncated")
        degraded = (
            self.modules_truncated
            or not self.modules
            or any(item.status != "verified" for item in self.modules)
            or bool(self.limitations)
            or self.process_root_identity_sha256 is None
        )
        if (self.status == "partial") != degraded:
            raise ValueError("container module quality does not match its evidence")
        if self.status == "partial" and not self.limitations:
            raise ValueError("partial container module evidence requires a limitation")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container module snapshot must preserve conclusion boundaries")
        return self


class ContainerSourceMappingEvidence(ContractModel):
    container_source_path_sha256: Sha256
    line: int | None = Field(default=None, gt=0)
    workspace_relative_path: str | None = Field(default=None, max_length=4096)
    status: Literal["mapped", "unmapped", "rejected", "unavailable"]

    @model_validator(mode="after")
    def validate_mapping(self) -> ContainerSourceMappingEvidence:
        if self.status == "mapped":
            if self.workspace_relative_path is None:
                raise ValueError("mapped container source requires a workspace-relative path")
            relative = PurePosixPath(self.workspace_relative_path)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or str(relative) != self.workspace_relative_path
            ):
                raise ValueError("workspace source mapping must be normalized and relative")
        elif self.workspace_relative_path is not None:
            raise ValueError("unmapped container source cannot expose a workspace path")
        return self


class ContainerSymbolContextArtifact(ContractModel):
    """Analysis-bound projection of verified modules and authorized source mappings."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    symbol_context_id: ContainerSymbolContextId
    created_at: str
    source_analysis_id: str = Field(pattern=r"^analysis-[a-f0-9]{16}$")
    source_analysis_content_sha256: Sha256
    source_collection_id: CollectionId
    module_snapshot_id: ContainerModuleSnapshotId
    module_snapshot_content_sha256: Sha256
    container_target_id: ContainerTargetId
    container_identity_sha256: Sha256
    quality_status: Literal["verified", "partial"]
    module_count: int = Field(ge=0)
    source_location_count: int = Field(ge=0)
    source_mappings: tuple[ContainerSourceMappingEvidence, ...] = ()
    source_mappings_truncated: bool = False
    limitations: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_symbol_context(self) -> ContainerSymbolContextArtifact:
        if self.symbol_context_id != derive_container_symbol_context_id(self.source_analysis_id):
            raise ValueError("container symbol context ID does not match its Analysis")
        mapping_keys = tuple(
            (item.container_source_path_sha256, item.line) for item in self.source_mappings
        )
        ordered_mapping_keys = tuple(sorted(mapping_keys, key=lambda item: (item[0], item[1] or 0)))
        if len(set(mapping_keys)) != len(mapping_keys) or ordered_mapping_keys != mapping_keys:
            raise ValueError("container source mappings must be unique and sorted")
        if self.source_location_count < len(self.source_mappings):
            raise ValueError("exported source mappings exceed observed source locations")
        if self.source_location_count > len(self.source_mappings) and not (
            self.source_mappings_truncated
        ):
            raise ValueError("omitted container source mappings must be reported as truncated")
        degraded = (
            bool(self.limitations)
            or self.module_count == 0
            or self.source_mappings_truncated
            or any(item.status != "mapped" for item in self.source_mappings)
        )
        if (self.quality_status == "partial") != degraded:
            raise ValueError("container symbol quality does not match its evidence")
        if self.quality_status == "partial" and not self.limitations:
            raise ValueError("partial container symbol evidence requires a limitation")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container symbol context must preserve conclusion boundaries")
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
    cleanup_policy: Literal["verified_session_containers_only"] = "verified_session_containers_only"
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


class ContainerEnvironmentFingerprint(ContractModel):
    """Stable A/B invariants; ephemeral container and PID identities are excluded."""

    target_kind: DockerTargetKind
    image_identity_sha256: Sha256
    uid_mapping: Literal[
        "rootless_same_uid",
        "rootful_same_uid",
        "rootful_cross_uid",
    ]
    adapter_recipe_id: Literal["local-docker-read-v1", "local-docker-managed-v1"]
    adapter_sha256: Sha256
    workload_fingerprint: Sha256 | None = None
    container_gate_sha256: Sha256 | None = None
    mount_layout_recipe: Literal[
        "existing-container-unverified-v1",
        "managed-workspace-readonly-v1",
    ]
    network_mode: Literal["unknown", "none"]
    host_kernel_release: str = Field(min_length=1, max_length=256)
    perf_executable_sha256: Sha256
    collector_config_sha256: Sha256
    collector_privilege_mode: Literal["cap_perfmon", "paranoid3_helper"]
    collector_feature_profile: Literal["cpu_only", "full_diagnostics"]
    collection_mode: CollectionMode
    collection_frequency_hz: int | None = Field(default=None, gt=0, le=10_000)
    collection_call_graph: Literal["fp", "dwarf", "lbr"] | None = None
    collection_record_event: Literal["cycles", "cpu-clock"] | None = None
    collection_events: tuple[str, ...] = ()
    requested_event_source: Literal["auto", "hardware_required", "software_only"]
    actual_event_source: Literal["hardware", "software"]
    fallback_used: bool
    fallback_reason: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_limitations: tuple[str, ...] = ()
    cpu_quota_usec: int | None = Field(default=None, gt=0)
    cpu_period_usec: int = Field(gt=0)
    cpuset_cpus_effective: str = Field(min_length=1, max_length=4096)
    memory_max_bytes: int | None = Field(default=None, gt=0)
    io_limits: tuple[CgroupIoDeviceLimit, ...] = ()
    pids_max: int | None = Field(default=None, gt=0)
    environment_fingerprint_sha256: Sha256

    @model_validator(mode="after")
    def validate_fingerprint(self) -> ContainerEnvironmentFingerprint:
        managed = self.target_kind == "managed_temporary_container"
        if managed != (self.workload_fingerprint is not None):
            raise ValueError("managed environment must bind one workload fingerprint")
        if managed != (self.container_gate_sha256 is not None):
            raise ValueError("managed environment must bind one Container Gate")
        if managed != (self.mount_layout_recipe == "managed-workspace-readonly-v1"):
            raise ValueError("Docker target kind and mount-layout recipe differ")
        if managed != (self.network_mode == "none"):
            raise ValueError("managed Docker A/B requires the fixed no-network recipe")
        if self.collection_mode == "record":
            if (
                self.collection_frequency_hz is None
                or self.collection_call_graph is None
                or self.collection_record_event is None
                or self.collection_events
            ):
                raise ValueError("record environment has inconsistent sampling settings")
        elif self.collection_mode == "stat" and (
            self.collection_frequency_hz is not None
            or self.collection_call_graph is not None
            or self.collection_record_event is not None
            or not self.collection_events
        ):
            raise ValueError("stat environment has inconsistent counting settings")
        if self.fallback_used != (self.fallback_reason is not None):
            raise ValueError("Docker environment fallback reason is inconsistent")
        if self.environment_fingerprint_sha256 != container_environment_fingerprint(self):
            raise ValueError("Docker environment fingerprint does not match its invariants")
        return self


class ContainerMeasurementArtifact(ContractModel):
    """One container Collection plus its whole-cgroup and stable-environment evidence."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    measurement_id: ContainerMeasurementId
    created_at: str
    source_collection_id: CollectionId
    source_collection_artifact_sha256: Sha256
    source_output_sha256: Sha256
    resource_context_id: ContainerResourceId
    resource_context_content_sha256: Sha256
    source_run_id: ContainerRunId | None = None
    source_run_content_sha256: Sha256 | None = None
    workload_spec_id: ContainerWorkloadId | None = None
    workload_spec_sha256: Sha256 | None = None
    environment: ContainerEnvironmentFingerprint
    treatment_sha256: tuple[Sha256, ...] = ()
    resource_observation: ContainerResourceDelta
    quality_status: Literal["verified", "partial"]
    limitations: tuple[str, ...] = ()
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_measurement(self) -> ContainerMeasurementArtifact:
        if self.measurement_id != derive_container_measurement_id(self.source_collection_id):
            raise ValueError("container measurement ID does not match its Collection")
        run_bindings = (
            self.source_run_id,
            self.source_run_content_sha256,
            self.workload_spec_id,
            self.workload_spec_sha256,
        )
        managed = self.environment.target_kind == "managed_temporary_container"
        if managed and any(value is None for value in run_bindings):
            raise ValueError("managed container measurement requires run and workload bindings")
        if not managed and any(value is not None for value in run_bindings):
            raise ValueError("existing container measurement cannot claim a managed run")
        _validate_unique_sorted(self.treatment_sha256, "container treatment hashes")
        if self.quality_status == "partial" and not self.limitations:
            raise ValueError("partial container measurement requires a limitation")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container measurement must preserve conclusion boundaries")
        return self


class ContainerMatchedComparisonArtifact(ContractModel):
    """Evidence-constrained matched A/B decision for two container measurements."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str
    comparison_id: ContainerComparisonId
    created_at: str
    baseline_measurement_id: ContainerMeasurementId
    baseline_measurement_content_sha256: Sha256
    candidate_measurement_id: ContainerMeasurementId
    candidate_measurement_content_sha256: Sha256
    baseline_analysis_id: str
    baseline_analysis_content_sha256: Sha256
    candidate_analysis_id: str
    candidate_analysis_content_sha256: Sha256
    profile_comparison_id: str = Field(pattern=r"^profile-comparison-[a-f0-9]{16}$")
    profile_comparison_content_sha256: Sha256
    baseline_benchmark_id: str
    baseline_benchmark_content_sha256: Sha256
    candidate_benchmark_id: str
    candidate_benchmark_content_sha256: Sha256
    benchmark_comparison_id: str = Field(pattern=r"^benchmark-comparison-[a-f0-9]{16}$")
    benchmark_comparison_content_sha256: Sha256
    environment_match: bool
    environment_differences: dict[str, tuple[str, str]] = Field(default_factory=dict)
    treatment_changed: bool
    baseline_treatment_sha256: tuple[Sha256, ...] = ()
    candidate_treatment_sha256: tuple[Sha256, ...] = ()
    correctness_status: Literal["passed", "failed", "unavailable"]
    resource_transfer_status: Literal["no_observed_regression", "regression", "incomplete"]
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
    allowed_conclusions: tuple[str, ...] = ()
    forbidden_conclusions: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_comparison(self) -> ContainerMatchedComparisonArtifact:
        _validate_unique_sorted(self.baseline_treatment_sha256, "baseline treatment hashes")
        _validate_unique_sorted(self.candidate_treatment_sha256, "candidate treatment hashes")
        _validate_unique_sorted(self.improved_metrics, "improved metric names")
        _validate_unique_sorted(self.regressed_metrics, "regressed metric names")
        if self.environment_match == bool(self.environment_differences):
            raise ValueError("environment match status and differences disagree")
        if self.treatment_changed != (
            self.baseline_treatment_sha256 != self.candidate_treatment_sha256
        ):
            raise ValueError("container treatment-change status is inconsistent")
        if self.conclusion == "verified_improvement" and (
            not self.comparable
            or not self.environment_match
            or not self.treatment_changed
            or self.correctness_status != "passed"
            or self.resource_transfer_status != "no_observed_regression"
            or not self.improved_metrics
            or self.regressed_metrics
        ):
            raise ValueError("verified container improvement lacks required matched evidence")
        if self.conclusion == "not_comparable" and self.comparable:
            raise ValueError("comparable container evidence cannot claim not_comparable")
        if self.conclusion != "not_comparable" and not self.comparable:
            raise ValueError("non-comparable container evidence cannot claim a performance result")
        if not self.allowed_conclusions or not self.forbidden_conclusions:
            raise ValueError("container comparison must preserve conclusion boundaries")
        return self
