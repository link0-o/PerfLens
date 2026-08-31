"""Public contract groundwork for the planned v0.4.0 runtime-lock adapters.

The runtime adapters intentionally share one evidence model even though their
source semantics differ.  Exact event streams, thresholded events, sampled
profiles, and cumulative profiles remain distinguishable all the way to the
Agent-visible analysis artifact.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping
from typing import Annotated, Any, Literal, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from perflens.contracts.artifacts import ContractModel

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ArtifactId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*-[a-f0-9]{16,64}$")]
EventId = Annotated[str, Field(pattern=r"^runtime-event-[a-f0-9]{16,64}$")]
LockId = Annotated[str, Field(pattern=r"^runtime-lock-[a-f0-9]{20}$")]
StackId = Annotated[str, Field(pattern=r"^runtime-stack-[a-f0-9]{16,64}$")]
ExecutionContextId = Annotated[
    str,
    Field(pattern=r"^runtime-context-[a-f0-9]{16,64}$"),
]
ContainerTargetId = Annotated[str, Field(pattern=r"^container-target-[a-f0-9]{20}$")]
ContainerRunId = Annotated[str, Field(pattern=r"^container-run-[a-f0-9]{20}$")]

RUNTIME_LOCK_SCHEMA_VERSION = "1.1"
LEGACY_RUNTIME_LOCK_SCHEMA_VERSION = "1.0"
RuntimeLockSchemaVersion = Literal["1.0", "1.1"]


def _legacy_schema_condition() -> dict[str, object]:
    """Match explicit 1.0 and versionless payloads from the v0.3.2 contract."""

    return {
        "anyOf": [
            {"not": {"required": ["schema_version"]}},
            {
                "properties": {"schema_version": {"const": "1.0"}},
                "required": ["schema_version"],
            },
        ]
    }


def _schema_1_1_condition() -> dict[str, object]:
    return {
        "properties": {"schema_version": {"const": RUNTIME_LOCK_SCHEMA_VERSION}},
        "required": ["schema_version"],
    }


def _forbid_present_json_schema(*fields: str) -> dict[str, object]:
    return {"not": {"anyOf": [{"required": [field]} for field in fields]}}


def _json_schema_extra(value: dict[str, Any]) -> dict[str, Any]:
    """Give complex conditional Schema fragments an explicit Pydantic type."""

    return value


_SCHEMA_1_1_QUALITY_FIELDS = (
    "out_of_order_record_count",
    "stack_input_record_count",
    "emitted_stack_count",
    "malformed_stack_record_count",
    "duplicate_stack_record_count",
    "truncated_stack_record_count",
)
_SCHEMA_1_1_EVENT_FIELDS = (
    "execution_context_id",
    "owner_execution_context_id",
    "parked_execution_context_id",
    "wait_end_event_id",
)
_SCHEMA_1_0_EVENT_FIELDS = (
    "target_tid",
    "owner_target_tid",
    "parked_target_tid",
)
_SCHEMA_1_1_ANALYSIS_FIELDS = (
    "execution_context_aggregates",
    "call_path_aggregates",
    "wait_outcome_aggregates",
    "lock_kind_aggregates",
    "total_exact_wait_ns",
    "total_thresholded_wait_ns",
    "total_observed_or_estimated_wait_ns",
    "total_exact_hold_ns",
    "total_owner_observed_count",
    "lock_coverage",
    "execution_context_coverage",
    "call_path_coverage",
    "wait_outcome_coverage",
    "lock_kind_coverage",
)
_SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS = frozenset(
    {
        "performance_root_cause",
        "verified_improvement",
        "cross_artifact_lock_identity",
        "system_wide_or_cross_target_behavior",
    }
)
_RUNTIME_PUBLIC_RAW_ADDRESS = re.compile(r"^(?:0x)?[0-9a-f]{8,32}$", re.IGNORECASE)
_RUNTIME_PUBLIC_CREDENTIAL = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:password|passwd|pwd|token|secret|client[_-]?secret|"
    r"credentials?|authorization)\s*[:=]",
    re.IGNORECASE,
)
_RUNTIME_PUBLIC_URI_USERINFO = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/@\s]+@")
_RUNTIME_PUBLIC_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_RUNTIME_PUBLIC_LABEL_JSON_PATTERN = r"^(?!/|\\\\|//|[A-Za-z]:[\\/]).+$"
_RUNTIME_TOOL_BASENAME_JSON_PATTERN = r"^[A-Za-z0-9_.+-]{1,128}$"

RuntimeFamily = Literal["c_cpp", "java", "python", "go", "custom"]
MeasurementSemantics = Literal["exact", "thresholded", "sampled", "cumulative"]
Availability = Literal["available", "partial", "unavailable", "disabled"]
EvidenceStatus = Literal["complete", "partial"]
LockKind = Literal[
    "mutex",
    "recursive_mutex",
    "rwlock_read",
    "rwlock_write",
    "condition",
    "semaphore",
    "park",
    "gil",
    "runtime_internal",
    "channel",
    "wait_group",
    "custom",
    "unknown",
]
WaitOutcome = Literal[
    "acquired",
    "notified",
    "unparked",
    "timed_out",
    "interrupted",
    "failed",
    "unknown",
]
Diagnostic = Annotated[str, Field(min_length=1, max_length=1024)]


def is_safe_runtime_public_label(value: str) -> bool:
    """Reject raw addresses, credentials and absolute host paths from public labels."""

    normalized = value.strip()
    if not normalized or any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if (
        normalized.startswith(("/", "\\\\", "//"))
        or re.match(r"^[A-Za-z]:[\\/]", normalized) is not None
    ):
        return False
    return not (
        _RUNTIME_PUBLIC_RAW_ADDRESS.fullmatch(normalized)
        or _RUNTIME_PUBLIC_CREDENTIAL.search(normalized)
        or _RUNTIME_PUBLIC_URI_USERINFO.search(normalized)
        or _RUNTIME_PUBLIC_PRIVATE_KEY.search(normalized)
    )


def _is_safe_runtime_tool_basename(value: str) -> bool:
    return re.fullmatch(_RUNTIME_TOOL_BASENAME_JSON_PATTERN, value) is not None


def derive_runtime_lock_id(
    runtime_lock_evidence_id: str,
    first_seen_ordinal: int,
) -> str:
    """Return an Artifact-local opaque lock identity.

    The first-seen ordinal deliberately prevents a raw runtime address from
    becoming Agent-visible.  Binding the digest to the Evidence Artifact also
    prevents callers from correlating lock identities across runs.
    """

    if isinstance(first_seen_ordinal, bool) or first_seen_ordinal < 0:
        raise ValueError("runtime lock first-seen ordinal must be non-negative")
    material = f"perflens-runtime-lock-id-v1.1\0{runtime_lock_evidence_id}\0{first_seen_ordinal}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"runtime-lock-{digest}"


def derive_runtime_execution_context_id(
    runtime_lock_evidence_id: str,
    first_seen_ordinal: int,
) -> str:
    """Return an Artifact-local public execution-context identity."""

    if isinstance(first_seen_ordinal, bool) or first_seen_ordinal < 0:
        raise ValueError("runtime context first-seen ordinal must be non-negative")
    material = f"perflens-runtime-context-id-v1.1\0{runtime_lock_evidence_id}\0{first_seen_ordinal}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"runtime-context-{digest}"


def derive_runtime_native_context_id(
    runtime_lock_evidence_id: str,
    first_seen_ordinal: int,
) -> str:
    """Return an Artifact-local replacement for a Java/Go runtime ID."""

    if isinstance(first_seen_ordinal, bool) or first_seen_ordinal < 0:
        raise ValueError("runtime-native context ordinal must be non-negative")
    material = (
        f"perflens-runtime-native-context-v1.1\0{runtime_lock_evidence_id}\0{first_seen_ordinal}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"runtime-native-{digest}"


def _validate_measurement_controls(
    semantics: MeasurementSemantics,
    *,
    duration_threshold_ns: int | None,
    sampling_period: int | None,
    sampling_fraction: int | None,
    block_profile_rate_ns: int | None,
) -> None:
    controls = (
        duration_threshold_ns,
        sampling_period,
        sampling_fraction,
        block_profile_rate_ns,
    )
    if semantics == "exact":
        if any(value is not None for value in controls):
            raise ValueError("exact runtime evidence cannot carry sampling or threshold knobs")
        return
    if semantics == "thresholded":
        if duration_threshold_ns is None or any(value is not None for value in controls[1:]):
            raise ValueError("thresholded runtime evidence requires only duration_threshold_ns")
        return
    if semantics == "sampled":
        if duration_threshold_ns is not None or block_profile_rate_ns is not None:
            raise ValueError("sampled runtime evidence cannot carry threshold/cumulative knobs")
        if (sampling_period is None) == (sampling_fraction is None):
            raise ValueError("sampled runtime evidence requires exactly one sampling control")
        return
    if duration_threshold_ns is not None:
        raise ValueError("cumulative runtime evidence cannot carry a duration threshold")
    if sum(value is not None for value in controls[1:]) != 1:
        raise ValueError("cumulative runtime evidence requires exactly one profile-rate control")


class RuntimeContainerTargetReference(ContractModel):
    """Content-bound references to existing Docker identity Artifacts.

    ``target_identity_sha256`` is the ContainerTarget identity fingerprint. It
    binds the namespace inode tuple and cgroup-v2 identity without copying that
    private identity surface into Runtime Lock Evidence.
    """

    container_target_id: ContainerTargetId
    container_target_content_sha256: Sha256
    container_run_id: ContainerRunId
    container_run_content_sha256: Sha256
    container_identity_sha256: Sha256
    target_identity_sha256: Sha256
    cgroup_identity_sha256: Sha256


class RuntimeTargetIdentity(ContractModel):
    """PID identity bound at collection/import time."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"target_kind": {"const": "docker"}},
                        "required": ["target_kind"],
                    },
                    "then": {
                        "required": ["container_reference"],
                        "properties": {"container_reference": {"not": {"type": "null"}}},
                    },
                    "else": {"properties": {"container_reference": {"type": "null"}}},
                }
            ],
        },
    )

    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    observed_target_tids: tuple[int, ...] = ()
    target_kind: Literal["host", "docker"] = "host"
    container_reference: RuntimeContainerTargetReference | None = None

    @model_validator(mode="after")
    def validate_tids(self) -> RuntimeTargetIdentity:
        tids = self.observed_target_tids
        if any(isinstance(tid, bool) or tid <= 0 for tid in tids):
            raise ValueError("runtime target TIDs must contain positive integers")
        if len(set(tids)) != len(tids) or tuple(sorted(tids)) != tids:
            raise ValueError("runtime target TIDs must be unique and sorted")
        if (self.target_kind == "docker") != (self.container_reference is not None):
            raise ValueError(
                "Docker runtime targets require one complete container Artifact reference"
            )
        return self


class RuntimeExecutionContext(ContractModel):
    """One runtime scheduling context without inventing an OS thread identity.

    Runtime-native identities are Artifact-local opaque strings because Java
    and Go identifiers are not interchangeable with Linux TIDs and must not be
    correlated across Artifacts.  Only contexts whose source really exposes a
    native thread may carry ``target_tid``.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"kind": {"const": "os_thread"}},
                        "required": ["kind"],
                    },
                    "then": {
                        "required": ["target_tid"],
                        "properties": {
                            "target_tid": {"type": "integer", "exclusiveMinimum": 0},
                            "runtime_context_id": {"type": "null"},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"kind": {"const": "process_aggregate"}},
                        "required": ["kind"],
                    },
                    "then": {
                        "properties": {
                            "target_tid": {"type": "null"},
                            "runtime_context_id": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "kind": {
                                "enum": [
                                    "java_platform_thread",
                                    "java_virtual_thread",
                                    "go_goroutine",
                                ]
                            }
                        },
                        "required": ["kind"],
                    },
                    "then": {
                        "required": ["runtime_context_id"],
                        "properties": {
                            "runtime_context_id": {
                                "type": "string",
                                "pattern": "^runtime-native-[a-f0-9]{16,64}$",
                            }
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"kind": {"enum": ["java_virtual_thread", "go_goroutine"]}},
                        "required": ["kind"],
                    },
                    "then": {"properties": {"target_tid": {"type": "null"}}},
                },
            ]
        },
    )

    context_id: ExecutionContextId
    kind: Literal[
        "os_thread",
        "java_platform_thread",
        "java_virtual_thread",
        "go_goroutine",
        "process_aggregate",
    ]
    target_pid: int = Field(gt=0)
    target_tid: int | None = Field(default=None, gt=0)
    runtime_context_id: str | None = Field(
        default=None,
        pattern=r"^runtime-native-[a-f0-9]{16,64}$",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=r"^[^\x00\r\n]+$",
        json_schema_extra={"pattern": _RUNTIME_PUBLIC_LABEL_JSON_PATTERN},
    )

    @field_validator("name")
    @classmethod
    def validate_public_name(cls, value: str | None) -> str | None:
        if value is not None and not is_safe_runtime_public_label(value):
            raise ValueError("runtime context name contains sensitive or absolute-path material")
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> RuntimeExecutionContext:
        if self.kind == "os_thread":
            if self.target_tid is None or self.runtime_context_id is not None:
                raise ValueError(
                    "OS-thread context requires target_tid and no runtime-native identity"
                )
        elif self.kind == "process_aggregate":
            if self.target_tid is not None or self.runtime_context_id is not None:
                raise ValueError(
                    "process aggregate cannot claim a thread or runtime-native identity"
                )
        elif self.runtime_context_id is None:
            raise ValueError("runtime-native context requires runtime_context_id")
        if self.kind in {"java_virtual_thread", "go_goroutine"} and self.target_tid is not None:
            raise ValueError("virtual-thread and goroutine contexts cannot claim an OS TID")
        return self


class RuntimeToolIdentity(ContractModel):
    """Public tool identity with legacy absolute-path read compatibility."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,64}$")
    path: str | None = None
    version: str | None = Field(default=None, max_length=256)
    binary_sha256: Sha256 | None = None
    status: Literal["available", "missing", "unsupported", "not_checked"]
    reason: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_identity(self) -> RuntimeToolIdentity:
        if self.version is not None and any(
            ord(character) < 32 or ord(character) == 127 for character in self.version
        ):
            raise ValueError("runtime tool version cannot contain control characters")
        if self.path is not None and not (
            self.path.startswith("/") or _is_safe_runtime_tool_basename(self.path)
        ):
            raise ValueError("runtime tool path must be a legacy absolute path or safe basename")
        if self.status == "available":
            if self.path is None or self.version is None or self.binary_sha256 is None:
                raise ValueError("available runtime tools require path, version, and digest")
            if self.reason is not None:
                raise ValueError("available runtime tools cannot carry an unavailable reason")
        elif self.path is None and (self.version is not None or self.binary_sha256 is not None):
            raise ValueError("runtime tool metadata requires a resolved path")
        return self


class RuntimeAdapterCapabilityArtifact(ContractModel):
    """Read-only capability result for one runtime adapter/backend pair."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _schema_1_1_condition(),
                        "then": {
                            "properties": {
                                "tools": {
                                    "items": {
                                        "properties": {
                                            "path": {
                                                "anyOf": [
                                                    {"type": "null"},
                                                    {
                                                        "type": "string",
                                                        "pattern": (
                                                            _RUNTIME_TOOL_BASENAME_JSON_PATTERN
                                                        ),
                                                    },
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    capability_id: ArtifactId
    created_at: str
    runtime: RuntimeFamily
    runtime_name: str = Field(min_length=1, max_length=128)
    runtime_version: str | None = Field(default=None, max_length=256)
    runtime_build: str | None = Field(default=None, max_length=512)
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    adapter_version: str = Field(min_length=1, max_length=128)
    backend_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    availability: Availability
    supported_lock_kinds: tuple[LockKind, ...] = ()
    supported_event_kinds: tuple[
        Literal[
            "wait_begin",
            "wait_end",
            "acquire",
            "release",
            "park",
            "unpark",
            "sampled_contention",
        ],
        ...,
    ] = ()
    measurement_semantics: tuple[MeasurementSemantics, ...] = ()
    fast_path_visibility: Literal["complete", "partial", "none", "unknown"]
    owner_visibility: Literal["available", "partial", "unavailable", "unknown"]
    hold_time_visibility: Literal["available", "partial", "unavailable", "unknown"]
    launch_instrumentation_required: bool
    attach_required: bool
    privileged_backend_required: bool
    tools: tuple[RuntimeToolIdentity, ...] = ()
    limitations: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_capability(self) -> RuntimeAdapterCapabilityArtifact:
        for values, label in (
            (self.supported_lock_kinds, "lock kinds"),
            (self.supported_event_kinds, "event kinds"),
            (self.measurement_semantics, "measurement semantics"),
        ):
            if len(set(values)) != len(values) or tuple(sorted(values)) != values:
                raise ValueError(f"runtime capability {label} must be unique and sorted")
        names = tuple(tool.name for tool in self.tools)
        if len(set(names)) != len(names) or tuple(sorted(names)) != names:
            raise ValueError("runtime capability tools must be unique and sorted")
        if self.schema_version == "1.1" and any(
            tool.path is not None and not _is_safe_runtime_tool_basename(tool.path)
            for tool in self.tools
        ):
            raise ValueError("schema 1.1 runtime capability cannot expose absolute tool paths")
        if self.availability == "available":
            if not self.supported_event_kinds or not self.measurement_semantics:
                raise ValueError("available runtime adapter must declare observable semantics")
        elif not self.limitations:
            raise ValueError("non-available runtime adapter must explain its limitations")
        if self.availability in {"disabled", "unavailable"} and (
            self.supported_event_kinds or self.measurement_semantics
        ):
            raise ValueError("disabled or unavailable adapter cannot claim active observations")
        return self


class RuntimeClock(ContractModel):
    clock: Literal["monotonic", "jfr_ticks", "profile_relative"]
    unit: Literal["nanoseconds"] = "nanoseconds"
    epoch_correlation_available: bool = False


class RuntimeLockResourceLimits(ContractModel):
    max_source_bytes: int = Field(default=67_108_864, gt=0, le=67_108_864)
    max_input_records: int = Field(default=100_000, gt=0, le=100_000)
    max_line_bytes: int = Field(default=65_536, gt=0, le=65_536)
    max_stack_depth: int = Field(default=127, gt=0, le=127)
    max_unique_target_tids: int = Field(default=65_536, gt=0, le=65_536)
    max_unique_locks: int = Field(default=100_000, gt=0, le=100_000)
    max_unique_stacks: int = Field(default=100_000, gt=0, le=100_000)
    max_diagnostics: int = Field(default=1_000, gt=0, le=10_000)
    max_exported_locks: int = Field(default=10_000, gt=0, le=100_000)
    max_output_bytes: int = Field(default=67_108_864, gt=0, le=67_108_864)


class RuntimeSourceManifest(ContractModel):
    """Versioned identity and semantics of one normalized input source."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _legacy_schema_condition(),
                        "then": _forbid_present_json_schema(
                            "converter_version",
                            "adapter_execution_identity_sha256",
                            "configuration_sha256",
                            "metadata_sha256",
                        ),
                        "else": {"required": ["converter_version"]},
                    },
                    {
                        "if": _schema_1_1_condition(),
                        "then": {
                            "properties": {
                                "tool": {
                                    "anyOf": [
                                        {"type": "null"},
                                        {
                                            "type": "object",
                                            "properties": {
                                                "path": {
                                                    "anyOf": [
                                                        {"type": "null"},
                                                        {
                                                            "type": "string",
                                                            "pattern": (
                                                                _RUNTIME_TOOL_BASENAME_JSON_PATTERN
                                                            ),
                                                        },
                                                    ]
                                                }
                                            },
                                        },
                                    ]
                                }
                            }
                        },
                    },
                    {
                        "if": {
                            "properties": {"source_format": {"const": "jfr_json_v1"}},
                            "required": ["source_format"],
                        },
                        "then": {
                            "required": [
                                "adapter_execution_identity_sha256",
                                "configuration_sha256",
                                "metadata_sha256",
                                "tool",
                            ],
                            "properties": {
                                "schema_version": {"const": "1.1"},
                                "runtime": {"const": "java"},
                                "adapter_id": {"const": "java_jfr"},
                                "backend_id": {"const": "jfr"},
                                "target_scope": {"const": "bound_pid"},
                            },
                        },
                    },
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    runtime: RuntimeFamily
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    adapter_version: str = Field(min_length=1, max_length=128)
    backend_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    backend_version: str = Field(min_length=1, max_length=256)
    measurement_semantics: MeasurementSemantics
    source_format: Literal[
        "perflens_runtime_lock_ndjson_v1",
        "jfr_json_v1",
        "pprof_text_v1",
        "native_interposer_ndjson_v1",
    ]
    # The importer/converter version is PerfLens-controlled.  Adapter/backend
    # versions may originate in an imported header and therefore cannot by
    # themselves bind the deterministic transformation implementation.
    converter_version: str | None = Field(default=None, min_length=1, max_length=128)
    source_sha256: Sha256
    source_bytes: int = Field(gt=0)
    conversion_fingerprint: Sha256
    clock: RuntimeClock
    duration_threshold_ns: int | None = Field(default=None, ge=0)
    sampling_period: int | None = Field(default=None, gt=0)
    sampling_fraction: int | None = Field(default=None, gt=0)
    block_profile_rate_ns: int | None = Field(default=None, gt=0)
    fast_path_visibility: Literal["complete", "partial", "none", "unknown"]
    owner_is_source_observed: bool
    hold_time_is_source_observed: bool
    target_scope: Literal["bound_pid", "verified_import"]
    tool: RuntimeToolIdentity | None = None
    adapter_execution_identity_sha256: Sha256 | None = None
    configuration_sha256: Sha256 | None = None
    metadata_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_semantics(self) -> RuntimeSourceManifest:
        if self.schema_version == "1.1" and self.converter_version is None:
            raise ValueError("schema 1.1 runtime source requires a converter version")
        if self.schema_version == "1.0" and "converter_version" in self.model_fields_set:
            raise ValueError("schema 1.0 runtime source cannot carry converter_version")
        execution_fields = (
            self.adapter_execution_identity_sha256,
            self.configuration_sha256,
            self.metadata_sha256,
        )
        if self.schema_version == "1.0" and any(value is not None for value in execution_fields):
            raise ValueError("schema 1.0 runtime source cannot carry Adapter execution identity")
        if (
            self.schema_version == "1.1"
            and self.tool is not None
            and self.tool.path is not None
            and not _is_safe_runtime_tool_basename(self.tool.path)
        ):
            raise ValueError("schema 1.1 runtime source cannot expose an absolute tool path")
        _validate_measurement_controls(
            self.measurement_semantics,
            duration_threshold_ns=self.duration_threshold_ns,
            sampling_period=self.sampling_period,
            sampling_fraction=self.sampling_fraction,
            block_profile_rate_ns=self.block_profile_rate_ns,
        )
        if self.source_format == "jfr_json_v1" and (
            self.schema_version != "1.1"
            or self.runtime != "java"
            or self.adapter_id != "java_jfr"
            or self.backend_id != "jfr"
            or self.target_scope != "bound_pid"
            or any(value is None for value in execution_fields)
            or self.tool is None
            or self.tool.name != "jfr"
            or self.tool.path != "jfr"
            or self.tool.status != "available"
        ):
            raise ValueError("JFR source lacks its bound Adapter execution identity")
        return self


class RuntimeLockImportHeader(ContractModel):
    """First record of the strict custom/runtime NDJSON import contract.

    The header intentionally contains no path, command, environment, or raw lock
    address.  The adapter computes ``RuntimeSourceManifest`` hashes after it has
    consumed the complete immutable stream.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _legacy_schema_condition(),
                        "then": {
                            "properties": {
                                "target": _forbid_present_json_schema(
                                    "target_kind", "container_reference"
                                )
                            }
                        },
                        "else": {"properties": {"target": {"required": ["target_kind"]}}},
                    }
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    record_type: Literal["runtime_lock_header"] = "runtime_lock_header"
    runtime: RuntimeFamily
    runtime_version: str = Field(min_length=1, max_length=256)
    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    adapter_version: str = Field(min_length=1, max_length=128)
    backend_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    backend_version: str = Field(min_length=1, max_length=256)
    target: RuntimeTargetIdentity
    clock: RuntimeClock
    measurement_semantics: MeasurementSemantics
    visible_lock_kinds: tuple[LockKind, ...]
    fast_path_visibility: Literal["complete", "partial", "none", "unknown"]
    owner_is_source_observed: bool
    hold_time_is_source_observed: bool
    duration_threshold_ns: int | None = Field(default=None, ge=0)
    sampling_period: int | None = Field(default=None, gt=0)
    sampling_fraction: int | None = Field(default=None, gt=0)
    block_profile_rate_ns: int | None = Field(default=None, gt=0)
    declared_event_count: int = Field(ge=0)
    declared_lost_event_count: int = Field(ge=0)
    declared_truncated: bool

    @model_validator(mode="after")
    def validate_header(self) -> RuntimeLockImportHeader:
        target_fields = self.target.model_fields_set
        if self.schema_version == "1.0" and target_fields & {
            "target_kind",
            "container_reference",
        }:
            raise ValueError("schema 1.0 runtime target cannot carry Docker identity references")
        if self.schema_version == "1.1" and "target_kind" not in target_fields:
            raise ValueError("schema 1.1 runtime target requires an explicit target kind")
        if not self.visible_lock_kinds:
            raise ValueError("runtime lock import must declare visible lock kinds")
        if (
            len(set(self.visible_lock_kinds)) != len(self.visible_lock_kinds)
            or tuple(sorted(self.visible_lock_kinds)) != self.visible_lock_kinds
        ):
            raise ValueError("runtime import lock kinds must be unique and sorted")
        _validate_measurement_controls(
            self.measurement_semantics,
            duration_threshold_ns=self.duration_threshold_ns,
            sampling_period=self.sampling_period,
            sampling_fraction=self.sampling_fraction,
            block_profile_rate_ns=self.block_profile_rate_ns,
        )
        if self.declared_truncated and self.declared_event_count == 0:
            raise ValueError("truncated runtime import must retain at least one event")
        return self


class RuntimeStackFrame(ContractModel):
    symbol: str = Field(
        min_length=1,
        max_length=4096,
        json_schema_extra={"pattern": _RUNTIME_PUBLIC_LABEL_JSON_PATTERN},
    )
    module: str = Field(
        min_length=1,
        max_length=4096,
        json_schema_extra={"pattern": _RUNTIME_PUBLIC_LABEL_JSON_PATTERN},
    )
    source_file: str | None = Field(
        default=None,
        max_length=4096,
        json_schema_extra={"pattern": _RUNTIME_PUBLIC_LABEL_JSON_PATTERN},
    )
    source_line: int | None = Field(default=None, gt=0)
    is_runtime: bool = False
    is_unknown: bool = False

    @field_validator("symbol", "module", "source_file")
    @classmethod
    def validate_public_frame_label(cls, value: str | None) -> str | None:
        if value is not None and not is_safe_runtime_public_label(value):
            raise ValueError("runtime stack frame contains sensitive or absolute-path material")
        return value


class RuntimeStack(ContractModel):
    stack_id: StackId
    frames: tuple[RuntimeStackFrame, ...] = Field(min_length=1)


class RuntimeLockEventBase(ContractModel):
    event_id: EventId
    event_index: int = Field(ge=0)
    timestamp_ns: int = Field(ge=0)
    execution_context_id: ExecutionContextId | None = None
    # Read compatibility for schema 1.0 Evidence only.  Schema 1.1 events use
    # execution_context_id so aggregate/JVM/goroutine events never fake a TID.
    target_tid: int | None = Field(default=None, gt=0)
    lock_id: LockId | None = None
    lock_kind: LockKind
    stack_id: StackId | None = None
    measurement_semantics: MeasurementSemantics


class RuntimeWaitBeginEvent(RuntimeLockEventBase):
    event_kind: Literal["wait_begin"] = "wait_begin"
    owner_execution_context_id: ExecutionContextId | None = None
    owner_target_tid: int | None = Field(default=None, gt=0)


class RuntimeWaitEndEvent(RuntimeLockEventBase):
    event_kind: Literal["wait_end"] = "wait_end"
    wait_begin_event_id: EventId | None = None
    duration_ns: int = Field(ge=0)
    outcome: WaitOutcome
    owner_execution_context_id: ExecutionContextId | None = None
    owner_target_tid: int | None = Field(default=None, gt=0)


class RuntimeAcquireEvent(RuntimeLockEventBase):
    event_kind: Literal["acquire"] = "acquire"
    wait_end_event_id: EventId | None = None


class RuntimeReleaseEvent(RuntimeLockEventBase):
    event_kind: Literal["release"] = "release"
    acquire_event_id: EventId | None = None
    hold_duration_ns: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_hold_pair(self) -> RuntimeReleaseEvent:
        if (self.acquire_event_id is None) != (self.hold_duration_ns is None):
            raise ValueError("runtime release must provide acquire identity and duration together")
        return self


class RuntimeParkEvent(RuntimeLockEventBase):
    event_kind: Literal["park"] = "park"

    @model_validator(mode="after")
    def validate_park_kind(self) -> RuntimeParkEvent:
        if self.lock_kind not in {"park", "condition", "runtime_internal"}:
            raise ValueError("park events require a park/condition/runtime lock kind")
        return self


class RuntimeUnparkEvent(RuntimeLockEventBase):
    event_kind: Literal["unpark"] = "unpark"
    parked_execution_context_id: ExecutionContextId | None = None
    parked_target_tid: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_unpark_kind(self) -> RuntimeUnparkEvent:
        if self.lock_kind not in {"park", "condition", "runtime_internal"}:
            raise ValueError("unpark events require a park/condition/runtime lock kind")
        return self


class RuntimeSampledContentionEvent(RuntimeLockEventBase):
    event_kind: Literal["sampled_contention"] = "sampled_contention"
    observed_count: int = Field(gt=0)
    estimated_count: float | None = Field(default=None, gt=0)
    cumulative_wait_ns: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_profile_semantics(self) -> RuntimeSampledContentionEvent:
        if self.measurement_semantics not in {"sampled", "cumulative"}:
            raise ValueError("sampled contention requires sampled or cumulative semantics")
        return self


RuntimeLockEvent = Annotated[
    RuntimeWaitBeginEvent
    | RuntimeWaitEndEvent
    | RuntimeAcquireEvent
    | RuntimeReleaseEvent
    | RuntimeParkEvent
    | RuntimeUnparkEvent
    | RuntimeSampledContentionEvent,
    Field(discriminator="event_kind"),
]


class RuntimeEvidenceQuality(ContractModel):
    status: EvidenceStatus
    # Event records only; the header and stack records have independent
    # accounting so malformed stacks cannot disappear inside event totals.
    input_record_count: int = Field(ge=0)
    emitted_event_count: int = Field(ge=0)
    filtered_outside_target_count: int = Field(ge=0)
    malformed_record_count: int = Field(ge=0)
    duplicate_record_count: int = Field(ge=0)
    out_of_order_record_count: int = Field(default=0, ge=0)
    unsupported_record_count: int = Field(ge=0)
    lost_event_count: int = Field(ge=0)
    truncated_event_count: int = Field(ge=0)
    stack_input_record_count: int = Field(default=0, ge=0)
    emitted_stack_count: int = Field(default=0, ge=0)
    malformed_stack_record_count: int = Field(default=0, ge=0)
    duplicate_stack_record_count: int = Field(default=0, ge=0)
    truncated_stack_record_count: int = Field(default=0, ge=0)
    exact_event_count: int = Field(ge=0)
    thresholded_event_count: int = Field(ge=0)
    sampled_event_count: int = Field(ge=0)
    cumulative_event_count: int = Field(ge=0)
    owner_observed_event_count: int = Field(ge=0)
    diagnostic_count: int = Field(ge=0)
    diagnostics_truncated: bool
    diagnostics: tuple[Diagnostic, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_quality(self) -> RuntimeEvidenceQuality:
        terminal = (
            self.emitted_event_count
            + self.filtered_outside_target_count
            + self.malformed_record_count
            + self.duplicate_record_count
            + self.out_of_order_record_count
            + self.unsupported_record_count
            + self.truncated_event_count
        )
        if terminal != self.input_record_count:
            raise ValueError("runtime evidence input records are not conserved")
        stack_terminal = (
            self.emitted_stack_count
            + self.malformed_stack_record_count
            + self.duplicate_stack_record_count
            + self.truncated_stack_record_count
        )
        if stack_terminal != self.stack_input_record_count:
            raise ValueError("runtime evidence stack records are not conserved")
        semantics = (
            self.exact_event_count
            + self.thresholded_event_count
            + self.sampled_event_count
            + self.cumulative_event_count
        )
        if semantics != self.emitted_event_count:
            raise ValueError("runtime evidence semantic counts are not conserved")
        if self.owner_observed_event_count > self.emitted_event_count:
            raise ValueError("runtime owner observations exceed emitted events")
        if self.diagnostic_count < len(self.diagnostics):
            raise ValueError("runtime diagnostic sample exceeds diagnostic_count")
        if self.diagnostics_truncated != (len(self.diagnostics) < self.diagnostic_count):
            raise ValueError("runtime diagnostic truncation flag contradicts its sample")
        degraded = any(
            value > 0
            for value in (
                self.malformed_record_count,
                self.unsupported_record_count,
                self.lost_event_count,
                self.truncated_event_count,
                self.duplicate_record_count,
                self.out_of_order_record_count,
                self.malformed_stack_record_count,
                self.duplicate_stack_record_count,
                self.truncated_stack_record_count,
                self.diagnostic_count,
            )
        )
        if self.status == "complete" and (degraded or self.limitations):
            raise ValueError("complete runtime evidence cannot contain loss or limitations")
        if self.status == "partial" and not (degraded or self.limitations):
            raise ValueError("partial runtime evidence requires a limitation")
        return self


class RuntimeLockEvidenceArtifact(ContractModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _legacy_schema_condition(),
                        "then": {
                            "allOf": [
                                _forbid_present_json_schema("execution_contexts"),
                                {
                                    "properties": {
                                        "target": _forbid_present_json_schema(
                                            "target_kind", "container_reference"
                                        ),
                                        "source": _legacy_schema_condition(),
                                        "quality": _forbid_present_json_schema(
                                            *_SCHEMA_1_1_QUALITY_FIELDS
                                        ),
                                        "events": {
                                            "items": {
                                                "allOf": [
                                                    _forbid_present_json_schema(
                                                        *_SCHEMA_1_1_EVENT_FIELDS
                                                    ),
                                                    {
                                                        "required": ["target_tid"],
                                                        "properties": {
                                                            "target_tid": {
                                                                "type": "integer",
                                                                "exclusiveMinimum": 0,
                                                            }
                                                        },
                                                    },
                                                    {
                                                        "if": {
                                                            "properties": {
                                                                "event_kind": {"const": "unpark"}
                                                            },
                                                            "required": ["event_kind"],
                                                        },
                                                        "then": {
                                                            "required": ["parked_target_tid"],
                                                            "properties": {
                                                                "parked_target_tid": {
                                                                    "type": "integer",
                                                                    "exclusiveMinimum": 0,
                                                                }
                                                            },
                                                        },
                                                    },
                                                ]
                                            }
                                        },
                                    }
                                },
                            ]
                        },
                        "else": {
                            "required": ["execution_contexts"],
                            "properties": {
                                "target": {"required": ["target_kind"]},
                                "source": {
                                    "required": ["schema_version"],
                                    "properties": {"schema_version": {"const": "1.1"}},
                                },
                                "quality": {"required": list(_SCHEMA_1_1_QUALITY_FIELDS)},
                                "events": {
                                    "items": {
                                        "allOf": [
                                            _forbid_present_json_schema(*_SCHEMA_1_0_EVENT_FIELDS),
                                            {
                                                "required": ["execution_context_id"],
                                                "properties": {
                                                    "execution_context_id": {
                                                        "type": "string",
                                                        "pattern": (
                                                            "^runtime-context-[a-f0-9]{16,64}$"
                                                        ),
                                                    }
                                                },
                                            },
                                            {
                                                "if": {
                                                    "properties": {
                                                        "event_kind": {"const": "unpark"}
                                                    },
                                                    "required": ["event_kind"],
                                                },
                                                "then": {
                                                    "required": ["parked_execution_context_id"],
                                                    "properties": {
                                                        "parked_execution_context_id": {
                                                            "type": "string",
                                                            "pattern": (
                                                                "^runtime-context-[a-f0-9]{16,64}$"
                                                            ),
                                                        }
                                                    },
                                                },
                                            },
                                        ]
                                    }
                                },
                            },
                        },
                    }
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    runtime_lock_evidence_id: ArtifactId
    created_at: str
    target: RuntimeTargetIdentity
    source: RuntimeSourceManifest
    limits: RuntimeLockResourceLimits
    quality: RuntimeEvidenceQuality
    execution_contexts: tuple[RuntimeExecutionContext, ...] = ()
    stacks: tuple[RuntimeStack, ...] = ()
    events: tuple[RuntimeLockEvent, ...]
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    evidence_fingerprint: Sha256
    content_sha256: Sha256
    content_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_evidence(self) -> RuntimeLockEvidenceArtifact:
        quality_fields = self.quality.model_fields_set
        target_fields = self.target.model_fields_set
        if self.schema_version == "1.0":
            if "execution_contexts" in self.model_fields_set:
                raise ValueError("schema 1.0 runtime Evidence cannot carry execution contexts")
            if quality_fields & set(_SCHEMA_1_1_QUALITY_FIELDS):
                raise ValueError("schema 1.0 runtime quality cannot carry 1.1 accounting fields")
            if any(event.model_fields_set & set(_SCHEMA_1_1_EVENT_FIELDS) for event in self.events):
                raise ValueError("schema 1.0 runtime event cannot carry 1.1 fields")
            if target_fields & {"target_kind", "container_reference"}:
                raise ValueError(
                    "schema 1.0 runtime target cannot carry Docker identity references"
                )
        else:
            if "execution_contexts" not in self.model_fields_set:
                raise ValueError("schema 1.1 runtime Evidence requires execution_contexts")
            if not set(_SCHEMA_1_1_QUALITY_FIELDS).issubset(quality_fields):
                raise ValueError("schema 1.1 runtime quality requires 1.1 accounting fields")
            if any(event.model_fields_set & set(_SCHEMA_1_0_EVENT_FIELDS) for event in self.events):
                raise ValueError("schema 1.1 runtime event cannot carry legacy TID fields")
            if "target_kind" not in target_fields:
                raise ValueError("schema 1.1 runtime target requires an explicit target kind")
        if self.source.schema_version != self.schema_version:
            raise ValueError("runtime Evidence and source schema versions must match")
        if self.source.source_bytes > self.limits.max_source_bytes:
            raise ValueError("runtime source exceeds max_source_bytes")
        if self.quality.input_record_count > self.limits.max_input_records:
            raise ValueError("runtime evidence exceeds max_input_records")
        if len(self.events) > self.limits.max_input_records:
            raise ValueError("runtime event tuple exceeds max_input_records")
        if len(self.target.observed_target_tids) > self.limits.max_unique_target_tids:
            raise ValueError("runtime evidence exceeds max_unique_target_tids")
        if len(self.stacks) > self.limits.max_unique_stacks:
            raise ValueError("runtime evidence exceeds max_unique_stacks")
        if any(len(stack.frames) > self.limits.max_stack_depth for stack in self.stacks):
            raise ValueError("runtime stack exceeds max_stack_depth")
        if self.quality.diagnostic_count > self.limits.max_diagnostics:
            raise ValueError("runtime evidence exceeds max_diagnostics")
        if self.content_bytes > self.limits.max_output_bytes:
            raise ValueError("runtime evidence exceeds max_output_bytes")
        if len(self.events) != self.quality.emitted_event_count:
            raise ValueError("runtime event tuple does not match emitted_event_count")
        if self.schema_version == "1.1" and len(self.stacks) != self.quality.emitted_stack_count:
            raise ValueError("runtime stack tuple does not match emitted_stack_count")
        event_ids = tuple(event.event_id for event in self.events)
        if len(set(event_ids)) != len(event_ids):
            raise ValueError("runtime event IDs must be unique")
        if tuple(event.event_index for event in self.events) != tuple(range(len(self.events))):
            raise ValueError("runtime event indexes must be contiguous")
        ordering = tuple((event.timestamp_ns, event.event_index) for event in self.events)
        if ordering != tuple(sorted(ordering)):
            raise ValueError("runtime events must use canonical timestamp/index order")
        semantics_count = {
            semantics: sum(event.measurement_semantics == semantics for event in self.events)
            for semantics in ("exact", "thresholded", "sampled", "cumulative")
        }
        if semantics_count != {
            "exact": self.quality.exact_event_count,
            "thresholded": self.quality.thresholded_event_count,
            "sampled": self.quality.sampled_event_count,
            "cumulative": self.quality.cumulative_event_count,
        }:
            raise ValueError("runtime event semantic counts contradict the event tuple")
        if any(
            event.measurement_semantics != self.source.measurement_semantics
            for event in self.events
        ):
            raise ValueError("runtime events must preserve the source measurement semantics")
        if (
            self.schema_version == "1.1"
            and self.source.measurement_semantics in {"sampled", "cumulative"}
            and any(not isinstance(event, RuntimeSampledContentionEvent) for event in self.events)
        ):
            raise ValueError(
                "sampled/cumulative runtime evidence requires profile contention events"
            )

        allowed_tids = set(self.target.observed_target_tids)
        context_ids = tuple(context.context_id for context in self.execution_contexts)
        if len(set(context_ids)) != len(context_ids):
            raise ValueError("runtime execution-context IDs must be unique")
        contexts_by_id = {context.context_id: context for context in self.execution_contexts}
        referenced_context_ids: set[str] = set()
        for ordinal, context in enumerate(self.execution_contexts):
            if context.target_pid != self.target.target_pid:
                raise ValueError("runtime execution context escaped the bound target PID")
            if context.target_tid is not None and context.target_tid not in allowed_tids:
                raise ValueError("runtime execution context escaped the observed target TID set")
            if self.schema_version == "1.1" and context.context_id != (
                derive_runtime_execution_context_id(self.runtime_lock_evidence_id, ordinal)
            ):
                raise ValueError(
                    "runtime execution-context ID is not bound to its Artifact and ordinal"
                )
            if (
                self.schema_version == "1.1"
                and context.runtime_context_id is not None
                and context.runtime_context_id
                != derive_runtime_native_context_id(self.runtime_lock_evidence_id, ordinal)
            ):
                raise ValueError(
                    "runtime-native context ID is not bound to its Artifact and ordinal"
                )

        observed_owner_count = 0
        for event in self.events:
            if self.schema_version == "1.0":
                if event.target_tid is None or event.target_tid not in allowed_tids:
                    raise ValueError("runtime event escaped the observed target TID set")
                if event.execution_context_id is not None:
                    raise ValueError("schema 1.0 runtime event cannot carry execution context")
            else:
                if event.target_tid is not None:
                    raise ValueError("schema 1.1 runtime event cannot carry legacy target_tid")
                context_id = event.execution_context_id
                if context_id is None or context_id not in contexts_by_id:
                    raise ValueError("runtime event references an unknown execution context")
                referenced_context_ids.add(context_id)
            for referenced_tid in (
                getattr(event, "owner_target_tid", None),
                getattr(event, "parked_target_tid", None),
            ):
                if referenced_tid is not None and referenced_tid not in allowed_tids:
                    raise ValueError("runtime event disclosed a non-target thread")
            context_references = (
                getattr(event, "owner_execution_context_id", None),
                getattr(event, "parked_execution_context_id", None),
            )
            if self.schema_version == "1.0" and any(
                item is not None for item in context_references
            ):
                raise ValueError("schema 1.0 runtime event cannot carry context references")
            if self.schema_version == "1.1":
                if any(
                    referenced_tid is not None
                    for referenced_tid in (
                        getattr(event, "owner_target_tid", None),
                        getattr(event, "parked_target_tid", None),
                    )
                ):
                    raise ValueError("schema 1.1 runtime event cannot carry legacy TID references")
                for context_id in context_references:
                    if context_id is not None:
                        if context_id not in contexts_by_id:
                            raise ValueError(
                                "runtime event references an unknown execution context"
                            )
                        referenced_context_ids.add(context_id)
                if (
                    isinstance(event, RuntimeUnparkEvent)
                    and event.parked_execution_context_id is None
                ):
                    raise ValueError("schema 1.1 runtime unpark requires a parked context")
            elif isinstance(event, RuntimeUnparkEvent) and event.parked_target_tid is None:
                raise ValueError("schema 1.0 runtime unpark requires parked_target_tid")
            owner_reference = (
                getattr(event, "owner_target_tid", None)
                if self.schema_version == "1.0"
                else getattr(event, "owner_execution_context_id", None)
            )
            if owner_reference is not None:
                observed_owner_count += 1
                if not self.source.owner_is_source_observed:
                    raise ValueError("runtime event fabricated owner visibility")
            if (
                isinstance(event, RuntimeReleaseEvent)
                and event.hold_duration_ns is not None
                and not self.source.hold_time_is_source_observed
            ):
                raise ValueError("runtime event fabricated hold-time visibility")
        if self.schema_version == "1.0" and self.execution_contexts:
            raise ValueError("schema 1.0 runtime Evidence cannot carry execution contexts")
        if self.schema_version == "1.1" and referenced_context_ids != set(context_ids):
            raise ValueError("runtime execution contexts must be referenced exactly")
        if observed_owner_count != self.quality.owner_observed_event_count:
            raise ValueError("runtime owner observations contradict the event tuple")

        events_by_id = {event.event_id: event for event in self.events}
        paired_wait_ids: set[str] = set()
        paired_wait_end_ids: set[str] = set()
        paired_acquire_ids: set[str] = set()
        for event in self.events:
            if self.schema_version == "1.0":
                continue
            if isinstance(event, RuntimeWaitEndEvent):
                if (
                    self.schema_version == "1.1"
                    and self.source.measurement_semantics == "exact"
                    and event.wait_begin_event_id is None
                ):
                    raise ValueError("exact schema 1.1 wait_end requires a wait_begin pair")
                if event.wait_begin_event_id is not None:
                    if event.wait_begin_event_id in paired_wait_ids:
                        raise ValueError("runtime wait_begin event cannot be paired twice")
                    begin = events_by_id.get(event.wait_begin_event_id)
                    if not isinstance(begin, RuntimeWaitBeginEvent):
                        raise ValueError("runtime wait_end references a non-wait_begin event")
                    self._validate_pair(begin, event, "wait")
                    if event.duration_ns != event.timestamp_ns - begin.timestamp_ns:
                        raise ValueError("runtime wait duration contradicts paired timestamps")
                    paired_wait_ids.add(event.wait_begin_event_id)
            elif isinstance(event, RuntimeAcquireEvent) and event.wait_end_event_id is not None:
                if event.wait_end_event_id in paired_wait_end_ids:
                    raise ValueError("runtime wait_end event cannot be acquired twice")
                wait_end = events_by_id.get(event.wait_end_event_id)
                if not isinstance(wait_end, RuntimeWaitEndEvent):
                    raise ValueError("runtime acquire references a non-wait_end event")
                if wait_end.outcome != "acquired":
                    raise ValueError("runtime acquire can only pair with an acquired wait")
                self._validate_pair(wait_end, event, "wait/acquire")
                paired_wait_end_ids.add(event.wait_end_event_id)
            elif isinstance(event, RuntimeReleaseEvent) and event.acquire_event_id is not None:
                if event.acquire_event_id in paired_acquire_ids:
                    raise ValueError("runtime acquire event cannot be released twice")
                acquire = events_by_id.get(event.acquire_event_id)
                if not isinstance(acquire, RuntimeAcquireEvent):
                    raise ValueError("runtime release references a non-acquire event")
                self._validate_pair(acquire, event, "acquire/release")
                hold_duration_ns = event.hold_duration_ns
                if (
                    hold_duration_ns is None
                    or hold_duration_ns != event.timestamp_ns - acquire.timestamp_ns
                ):
                    raise ValueError("runtime hold duration contradicts paired timestamps")
                paired_acquire_ids.add(event.acquire_event_id)

        if (
            self.schema_version == "1.1"
            and self.source.measurement_semantics == "exact"
            and self.quality.status == "complete"
        ):
            wait_begin_ids = {
                event.event_id for event in self.events if isinstance(event, RuntimeWaitBeginEvent)
            }
            if wait_begin_ids != paired_wait_ids:
                raise ValueError("complete exact runtime evidence has an incomplete wait pair")
            acquired_wait_end_ids = {
                event.event_id
                for event in self.events
                if isinstance(event, RuntimeWaitEndEvent) and event.outcome == "acquired"
            }
            has_acquire_surface = any(
                isinstance(event, RuntimeAcquireEvent) for event in self.events
            )
            if (has_acquire_surface or self.source.hold_time_is_source_observed) and (
                acquired_wait_end_ids != paired_wait_end_ids
            ):
                raise ValueError(
                    "complete exact runtime evidence has an incomplete wait/acquire pair"
                )
            if self.source.hold_time_is_source_observed:
                acquire_ids = {
                    event.event_id
                    for event in self.events
                    if isinstance(event, RuntimeAcquireEvent)
                }
                if acquire_ids != paired_acquire_ids:
                    raise ValueError(
                        "complete exact runtime evidence has an incomplete acquire/release pair"
                    )
            parks = Counter(
                (
                    event.execution_context_id or event.target_tid,
                    event.lock_id,
                    event.lock_kind,
                )
                for event in self.events
                if isinstance(event, RuntimeParkEvent)
            )
            unparks = Counter(
                (
                    event.parked_execution_context_id or event.parked_target_tid,
                    event.lock_id,
                    event.lock_kind,
                )
                for event in self.events
                if isinstance(event, RuntimeUnparkEvent)
            )
            if parks != unparks:
                raise ValueError("complete exact runtime evidence has an incomplete park pair")

        stack_ids = tuple(stack.stack_id for stack in self.stacks)
        if len(set(stack_ids)) != len(stack_ids):
            raise ValueError("runtime stack IDs must be unique")
        if any(
            event.stack_id is not None and event.stack_id not in stack_ids for event in self.events
        ):
            raise ValueError("runtime event references an unknown stack")
        first_seen_lock_ids = tuple(
            dict.fromkeys(event.lock_id for event in self.events if event.lock_id is not None)
        )
        if len(first_seen_lock_ids) > self.limits.max_unique_locks:
            raise ValueError("runtime evidence exceeds max_unique_locks")
        lock_kinds_by_id: dict[str, LockKind] = {}
        for event in self.events:
            if event.lock_id is None:
                continue
            prior_kind = lock_kinds_by_id.setdefault(event.lock_id, event.lock_kind)
            if self.schema_version == "1.1" and prior_kind != event.lock_kind:
                raise ValueError("runtime lock ID changed lock kind")
        if self.schema_version == "1.1" and any(
            lock_id != derive_runtime_lock_id(self.runtime_lock_evidence_id, ordinal)
            for ordinal, lock_id in enumerate(first_seen_lock_ids)
        ):
            raise ValueError("runtime lock ID is not bound to its Artifact and first occurrence")
        for conclusions, label in (
            (self.allowed_conclusions, "allowed"),
            (self.forbidden_conclusions, "forbidden"),
        ):
            if self.schema_version == "1.1" and any(
                not conclusion.strip() for conclusion in conclusions
            ):
                raise ValueError(f"runtime {label} conclusions cannot be blank")
            if self.schema_version == "1.1" and len(set(conclusions)) != len(conclusions):
                raise ValueError(f"runtime {label} conclusions must be unique")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("runtime allowed and forbidden conclusions must be disjoint")
        if self.quality.status == "partial" and "unqualified_runtime_lock_conclusion" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("partial runtime evidence must forbid unqualified conclusions")
        if self.source.measurement_semantics != "exact" and "exact_contention_count" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("non-exact runtime evidence must forbid exact contention counts")
        if not self.source.owner_is_source_observed and "exact_owner_relationship" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("runtime evidence without owner data must forbid owner conclusions")
        if self.source.adapter_id == "java_jfr" and "exact_owner_relationship" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("Java JFR evidence must forbid exact owner conclusions")
        if not self.source.hold_time_is_source_observed and "exact_hold_time" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("runtime evidence without hold data must forbid hold conclusions")
        if (
            self.schema_version == "1.1"
            and "exact_owner_relationship" in (self.allowed_conclusions)
            and (
                self.source.measurement_semantics != "exact"
                or self.quality.status != "complete"
                or not self.source.owner_is_source_observed
            )
        ):
            raise ValueError("exact owner conclusions require complete exact source observations")
        if (
            self.schema_version == "1.1"
            and "exact_hold_time" in (self.allowed_conclusions)
            and (
                self.source.measurement_semantics != "exact"
                or self.quality.status != "complete"
                or not self.source.hold_time_is_source_observed
            )
        ):
            raise ValueError("exact hold conclusions require complete exact source observations")
        if self.schema_version == "1.1":
            allowed = set(self.allowed_conclusions)
            forbidden = set(self.forbidden_conclusions)
            if allowed & _SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS:
                raise ValueError("runtime Evidence allowed a categorically forbidden conclusion")
            if not _SCHEMA_1_1_ALWAYS_FORBIDDEN_CONCLUSIONS.issubset(forbidden):
                raise ValueError(
                    "schema 1.1 runtime Evidence omitted a mandatory forbidden conclusion"
                )
        return self

    @staticmethod
    def _validate_pair(
        earlier: RuntimeLockEventBase,
        later: RuntimeLockEventBase,
        label: str,
    ) -> None:
        if earlier.event_index >= later.event_index or earlier.timestamp_ns > later.timestamp_ns:
            raise ValueError(f"runtime {label} pair is not time ordered")
        if earlier.lock_id != later.lock_id or earlier.lock_kind != later.lock_kind:
            raise ValueError(f"runtime {label} pair changed lock identity or kind")
        earlier_context = earlier.execution_context_id or earlier.target_tid
        later_context = later.execution_context_id or later.target_tid
        if earlier_context != later_context:
            raise ValueError(f"runtime {label} pair changed execution context")


class RuntimeNanosecondDistribution(ContractModel):
    sample_count: int = Field(ge=0)
    total_ns: int = Field(ge=0)
    minimum_ns: int = Field(ge=0)
    mean_ns: int = Field(ge=0)
    p50_ns: int = Field(ge=0)
    p95_ns: int = Field(ge=0)
    p99_ns: int = Field(ge=0)
    maximum_ns: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_distribution(self) -> RuntimeNanosecondDistribution:
        values = (
            self.minimum_ns,
            self.p50_ns,
            self.p95_ns,
            self.p99_ns,
            self.maximum_ns,
        )
        if self.sample_count == 0:
            if self.total_ns or self.mean_ns or any(values):
                raise ValueError("empty runtime distribution must contain only zero values")
        elif self.mean_ns != self.total_ns // self.sample_count:
            raise ValueError("runtime distribution mean must use integer floor")
        elif values != tuple(sorted(values)):
            raise ValueError("runtime distribution quantiles must be monotonic")
        return self


class RuntimeProjectionMetrics(ContractModel):
    """Metrics shared by every independent Runtime Lock projection."""

    exact_waits: RuntimeNanosecondDistribution
    thresholded_waits: RuntimeNanosecondDistribution
    sampled_observation_count: int = Field(ge=0)
    cumulative_observation_count: int = Field(ge=0)
    observed_or_estimated_wait_ns: int = Field(ge=0)
    exact_holds: RuntimeNanosecondDistribution
    owner_observed_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_metrics(self) -> RuntimeProjectionMetrics:
        if self.owner_observed_count > (
            self.exact_waits.sample_count + self.thresholded_waits.sample_count
        ):
            raise ValueError("runtime projection owner observations exceed event waits")
        return self


class RuntimeLockAggregate(RuntimeProjectionMetrics):
    lock_id: LockId | None = None
    lock_kind: LockKind
    # waiter_thread_count is retained solely for strict schema 1.0 loading.
    waiter_thread_count: int | None = Field(default=None, ge=0)
    waiter_execution_context_count: int | None = Field(default=None, ge=0)
    top_stack_ids: tuple[StackId, ...] = ()

    @model_validator(mode="after")
    def validate_aggregate(self) -> RuntimeLockAggregate:
        if (self.waiter_thread_count is None) == (self.waiter_execution_context_count is None):
            raise ValueError("runtime lock aggregate requires exactly one waiter cardinality")
        if len(set(self.top_stack_ids)) != len(self.top_stack_ids):
            raise ValueError("runtime aggregate stack IDs must be unique")
        return self


class RuntimeExecutionContextAggregate(RuntimeProjectionMetrics):
    execution_context_id: ExecutionContextId
    # Profiles such as Go mutex/block do not expose lock object identity.  In
    # that case cardinality is unknown, not one synthetic process-wide lock.
    lock_count: int | None = Field(default=None, ge=0)


class RuntimeCallPathAggregate(RuntimeProjectionMetrics):
    stack_id: StackId | None = None
    lock_count: int | None = Field(default=None, ge=0)
    execution_context_count: int = Field(ge=0)


class RuntimeWaitOutcomeAggregate(RuntimeProjectionMetrics):
    wait_outcome: WaitOutcome
    lock_count: int | None = Field(default=None, ge=0)
    execution_context_count: int = Field(ge=0)


class RuntimeLockKindAggregate(RuntimeProjectionMetrics):
    lock_kind: LockKind
    lock_count: int | None = Field(default=None, ge=0)
    execution_context_count: int = Field(ge=0)


class RuntimeProjectionCoverage(ContractModel):
    """Export/omission accounting for one bounded projection."""

    total_row_count: int = Field(ge=0)
    exported_row_count: int = Field(ge=0)
    omitted_row_count: int = Field(ge=0)
    omitted_exact_wait_count: int = Field(ge=0)
    omitted_exact_wait_ns: int = Field(ge=0)
    omitted_thresholded_wait_count: int = Field(ge=0)
    omitted_thresholded_wait_ns: int = Field(ge=0)
    omitted_sampled_observation_count: int = Field(ge=0)
    omitted_cumulative_observation_count: int = Field(ge=0)
    omitted_observed_or_estimated_wait_ns: int = Field(ge=0)
    omitted_exact_hold_count: int = Field(ge=0)
    omitted_exact_hold_ns: int = Field(ge=0)
    omitted_owner_observed_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_coverage(self) -> RuntimeProjectionCoverage:
        if self.total_row_count != self.exported_row_count + self.omitted_row_count:
            raise ValueError("runtime projection row counts are not conserved")
        omitted_metrics = (
            self.omitted_exact_wait_count,
            self.omitted_exact_wait_ns,
            self.omitted_thresholded_wait_count,
            self.omitted_thresholded_wait_ns,
            self.omitted_sampled_observation_count,
            self.omitted_cumulative_observation_count,
            self.omitted_observed_or_estimated_wait_ns,
            self.omitted_exact_hold_count,
            self.omitted_exact_hold_ns,
            self.omitted_owner_observed_count,
        )
        if self.omitted_row_count == 0 and any(omitted_metrics):
            raise ValueError("runtime projection without omitted rows cannot omit metrics")
        if self.omitted_exact_wait_count == 0 and self.omitted_exact_wait_ns:
            raise ValueError("runtime omitted exact wait duration requires an omitted wait")
        if self.omitted_thresholded_wait_count == 0 and self.omitted_thresholded_wait_ns:
            raise ValueError("runtime omitted thresholded duration requires an omitted wait")
        if self.omitted_exact_hold_count == 0 and self.omitted_exact_hold_ns:
            raise ValueError("runtime omitted exact hold duration requires an omitted hold")
        return self


class RuntimeLockAnalysisArtifact(ContractModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _legacy_schema_condition(),
                        "then": {
                            "allOf": [
                                _forbid_present_json_schema(*_SCHEMA_1_1_ANALYSIS_FIELDS),
                                {
                                    "properties": {
                                        "aggregates": {
                                            "items": _forbid_present_json_schema(
                                                "waiter_execution_context_count"
                                            )
                                        }
                                    }
                                },
                            ]
                        },
                        "else": {
                            "required": list(_SCHEMA_1_1_ANALYSIS_FIELDS),
                            "properties": {
                                "aggregates": {
                                    "items": {
                                        "allOf": [
                                            _forbid_present_json_schema("waiter_thread_count"),
                                            {"required": ["waiter_execution_context_count"]},
                                        ]
                                    }
                                }
                            },
                        },
                    }
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_evidence_id: ArtifactId
    runtime_lock_evidence_content_sha256: Sha256
    runtime_lock_evidence_content_bytes: int = Field(gt=0)
    created_at: str
    runtime: RuntimeFamily
    measurement_semantics: MeasurementSemantics
    quality_status: EvidenceStatus
    limits: RuntimeLockResourceLimits
    aggregates: tuple[RuntimeLockAggregate, ...]
    execution_context_aggregates: tuple[RuntimeExecutionContextAggregate, ...] = ()
    call_path_aggregates: tuple[RuntimeCallPathAggregate, ...] = ()
    wait_outcome_aggregates: tuple[RuntimeWaitOutcomeAggregate, ...] = ()
    lock_kind_aggregates: tuple[RuntimeLockKindAggregate, ...] = ()
    total_exact_wait_count: int = Field(ge=0)
    total_exact_wait_ns: int = Field(default=0, ge=0)
    total_thresholded_wait_count: int = Field(ge=0)
    total_thresholded_wait_ns: int = Field(default=0, ge=0)
    total_sampled_observation_count: int = Field(ge=0)
    total_cumulative_observation_count: int = Field(ge=0)
    total_observed_or_estimated_wait_ns: int = Field(default=0, ge=0)
    total_exact_hold_count: int = Field(ge=0)
    total_exact_hold_ns: int = Field(default=0, ge=0)
    total_owner_observed_count: int = Field(default=0, ge=0)
    lock_coverage: RuntimeProjectionCoverage | None = None
    execution_context_coverage: RuntimeProjectionCoverage | None = None
    call_path_coverage: RuntimeProjectionCoverage | None = None
    wait_outcome_coverage: RuntimeProjectionCoverage | None = None
    lock_kind_coverage: RuntimeProjectionCoverage | None = None
    # Retained for strict schema 1.0 reads and mirrored from lock_coverage in 1.1.
    omitted_lock_count: int = Field(ge=0)
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    analysis_fingerprint: Sha256
    content_sha256: Sha256
    content_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_analysis(self) -> RuntimeLockAnalysisArtifact:
        aggregate_fields = tuple(row.model_fields_set for row in self.aggregates)
        if self.schema_version == "1.0":
            if self.model_fields_set & set(_SCHEMA_1_1_ANALYSIS_FIELDS):
                raise ValueError("schema 1.0 runtime analysis cannot carry 1.1 fields")
            if any("waiter_execution_context_count" in fields for fields in aggregate_fields):
                raise ValueError("schema 1.0 lock aggregate cannot carry 1.1 cardinality")
        else:
            if not set(_SCHEMA_1_1_ANALYSIS_FIELDS).issubset(self.model_fields_set):
                raise ValueError("schema 1.1 runtime analysis requires every 1.1 field")
            if any("waiter_thread_count" in fields for fields in aggregate_fields):
                raise ValueError("schema 1.1 lock aggregate cannot carry legacy cardinality")
            if any("waiter_execution_context_count" not in fields for fields in aggregate_fields):
                raise ValueError("schema 1.1 lock aggregate requires 1.1 cardinality")
        projections: tuple[
            tuple[RuntimeProjectionMetrics, ...],
            ...,
        ] = (
            self.aggregates,
            self.execution_context_aggregates,
            self.call_path_aggregates,
            self.wait_outcome_aggregates,
            self.lock_kind_aggregates,
        )
        if any(len(rows) > self.limits.max_exported_locks for rows in projections):
            raise ValueError("runtime analysis exceeds max_exported_locks")
        if self.runtime_lock_evidence_content_bytes > self.limits.max_output_bytes:
            raise ValueError("runtime analysis input exceeds max_output_bytes")
        if self.content_bytes > self.limits.max_output_bytes:
            raise ValueError("runtime analysis exceeds max_output_bytes")
        lock_ids = tuple(row.lock_id for row in self.aggregates if row.lock_id is not None)
        if len(set(lock_ids)) != len(lock_ids):
            raise ValueError("runtime lock aggregates must have unique lock IDs")
        for values, label in (
            (
                tuple(row.execution_context_id for row in self.execution_context_aggregates),
                "execution-context",
            ),
            (tuple(row.stack_id for row in self.call_path_aggregates), "call-path"),
            (tuple(row.wait_outcome for row in self.wait_outcome_aggregates), "wait-outcome"),
            (tuple(row.lock_kind for row in self.lock_kind_aggregates), "lock-kind"),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"runtime {label} aggregates must have unique keys")

        totals = (
            self.total_exact_wait_count,
            self.total_exact_wait_ns,
            self.total_thresholded_wait_count,
            self.total_thresholded_wait_ns,
            self.total_sampled_observation_count,
            self.total_cumulative_observation_count,
            self.total_observed_or_estimated_wait_ns,
            self.total_exact_hold_count,
            self.total_exact_hold_ns,
            self.total_owner_observed_count,
        )
        if self.schema_version == "1.0":
            if any(
                (
                    self.execution_context_aggregates,
                    self.call_path_aggregates,
                    self.wait_outcome_aggregates,
                    self.lock_kind_aggregates,
                    self.lock_coverage,
                    self.execution_context_coverage,
                    self.call_path_coverage,
                    self.wait_outcome_coverage,
                    self.lock_kind_coverage,
                )
            ):
                raise ValueError("schema 1.0 runtime analysis cannot carry 1.1 projections")
            if any(row.waiter_thread_count is None for row in self.aggregates):
                raise ValueError("schema 1.0 lock aggregate requires waiter_thread_count")
            legacy_expected = (
                sum(row.exact_waits.sample_count for row in self.aggregates),
                sum(row.thresholded_waits.sample_count for row in self.aggregates),
                sum(row.sampled_observation_count for row in self.aggregates),
                sum(row.cumulative_observation_count for row in self.aggregates),
                sum(row.exact_holds.sample_count for row in self.aggregates),
            )
            legacy_actual = (
                self.total_exact_wait_count,
                self.total_thresholded_wait_count,
                self.total_sampled_observation_count,
                self.total_cumulative_observation_count,
                self.total_exact_hold_count,
            )
            if legacy_actual != legacy_expected:
                raise ValueError("runtime lock analysis aggregates are not conserved")
        else:
            coverages = (
                self.lock_coverage,
                self.execution_context_coverage,
                self.call_path_coverage,
                self.wait_outcome_coverage,
                self.lock_kind_coverage,
            )
            if any(coverage is None for coverage in coverages):
                raise ValueError("schema 1.1 runtime analysis requires every projection coverage")
            if any(row.waiter_execution_context_count is None for row in self.aggregates):
                raise ValueError(
                    "schema 1.1 lock aggregate requires waiter_execution_context_count"
                )
            for rows, coverage in zip(projections, coverages, strict=True):
                for row in rows:
                    if self.measurement_semantics == "exact" and (
                        row.observed_or_estimated_wait_ns != row.exact_waits.total_ns
                    ):
                        raise ValueError(
                            "exact runtime projection wait weight contradicts its distribution"
                        )
                    if self.measurement_semantics == "thresholded" and (
                        row.observed_or_estimated_wait_ns != row.thresholded_waits.total_ns
                    ):
                        raise ValueError(
                            "thresholded runtime projection wait weight "
                            "contradicts its distribution"
                        )
                if coverage is None:  # narrowed by the check above
                    raise ValueError("runtime projection coverage is missing")
                if self.measurement_semantics == "exact" and (
                    coverage.omitted_observed_or_estimated_wait_ns != coverage.omitted_exact_wait_ns
                ):
                    raise ValueError(
                        "exact runtime projection omitted wait weight is not conserved"
                    )
                if self.measurement_semantics == "thresholded" and (
                    coverage.omitted_observed_or_estimated_wait_ns
                    != coverage.omitted_thresholded_wait_ns
                ):
                    raise ValueError(
                        "thresholded runtime projection omitted wait weight is not conserved"
                    )
                self._validate_projection(rows, coverage, totals)
            if self.lock_coverage is None:  # narrowed by the check above
                raise ValueError("runtime lock coverage is missing")
            if self.omitted_lock_count != self.lock_coverage.omitted_row_count:
                raise ValueError("runtime omitted_lock_count contradicts lock coverage")
            semantic_counts = {
                "exact": self.total_exact_wait_count,
                "thresholded": self.total_thresholded_wait_count,
                "sampled": self.total_sampled_observation_count,
                "cumulative": self.total_cumulative_observation_count,
            }
            if any(
                count
                for semantics, count in semantic_counts.items()
                if semantics != self.measurement_semantics
            ):
                raise ValueError("runtime analysis mixed measurement semantics")
            expected_wait_ns = {
                "exact": self.total_exact_wait_ns,
                "thresholded": self.total_thresholded_wait_ns,
                "sampled": self.total_observed_or_estimated_wait_ns,
                "cumulative": self.total_observed_or_estimated_wait_ns,
            }[self.measurement_semantics]
            if self.total_observed_or_estimated_wait_ns != expected_wait_ns:
                raise ValueError("runtime analysis wait weights contradict its semantics")
            if self.measurement_semantics != "exact" and (
                self.total_exact_hold_count or self.total_exact_hold_ns
            ):
                raise ValueError("non-exact runtime analysis cannot carry exact hold metrics")
        if self.schema_version == "1.1":
            for conclusions, label in (
                (self.allowed_conclusions, "allowed"),
                (self.forbidden_conclusions, "forbidden"),
            ):
                if any(not conclusion.strip() for conclusion in conclusions):
                    raise ValueError(f"runtime analysis {label} conclusions cannot be blank")
                if len(set(conclusions)) != len(conclusions):
                    raise ValueError(f"runtime analysis {label} conclusions must be unique")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("runtime analysis conclusion sets must be disjoint")
        if self.quality_status == "partial" and "unqualified_runtime_lock_conclusion" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("partial runtime analysis must forbid unqualified conclusions")
        if self.measurement_semantics != "exact" and "exact_contention_count" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("non-exact runtime analysis must forbid exact counts")
        return self

    @staticmethod
    def _validate_projection(
        rows: tuple[RuntimeProjectionMetrics, ...],
        coverage: RuntimeProjectionCoverage,
        totals: tuple[int, ...],
    ) -> None:
        if coverage.exported_row_count != len(rows):
            raise ValueError("runtime projection exported row count contradicts its rows")
        exported = (
            sum(row.exact_waits.sample_count for row in rows),
            sum(row.exact_waits.total_ns for row in rows),
            sum(row.thresholded_waits.sample_count for row in rows),
            sum(row.thresholded_waits.total_ns for row in rows),
            sum(row.sampled_observation_count for row in rows),
            sum(row.cumulative_observation_count for row in rows),
            sum(row.observed_or_estimated_wait_ns for row in rows),
            sum(row.exact_holds.sample_count for row in rows),
            sum(row.exact_holds.total_ns for row in rows),
            sum(row.owner_observed_count for row in rows),
        )
        omitted = (
            coverage.omitted_exact_wait_count,
            coverage.omitted_exact_wait_ns,
            coverage.omitted_thresholded_wait_count,
            coverage.omitted_thresholded_wait_ns,
            coverage.omitted_sampled_observation_count,
            coverage.omitted_cumulative_observation_count,
            coverage.omitted_observed_or_estimated_wait_ns,
            coverage.omitted_exact_hold_count,
            coverage.omitted_exact_hold_ns,
            coverage.omitted_owner_observed_count,
        )
        if tuple(left + right for left, right in zip(exported, omitted, strict=True)) != totals:
            raise ValueError("runtime projection metrics are not conserved")


class RuntimeLockVerificationCheck(ContractModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    status: Literal["passed", "failed", "skipped"]
    detail: str = Field(min_length=1, max_length=1024)


class RuntimeLockSourceReplayReceipt(ContractModel):
    """Path-free attestation that retained raw input reproduced one Evidence."""

    status: Literal["passed"] = "passed"
    source_format: str = Field(min_length=1, max_length=128)
    raw_source_sha256: Sha256
    raw_source_bytes: int = Field(ge=0, le=64 << 20)
    normalized_source_sha256: Sha256
    normalized_source_bytes: int = Field(ge=0, le=64 << 20)
    converter_version: str = Field(min_length=1, max_length=128)
    conversion_fingerprint: Sha256
    adapter_execution_identity_sha256: Sha256 | None = None
    runtime_lock_evidence_id: ArtifactId
    runtime_lock_evidence_content_sha256: Sha256


class RuntimeLockAnalysisVerificationArtifact(ContractModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_extra=_json_schema_extra(
            {
                "allOf": [
                    {
                        "if": _legacy_schema_condition(),
                        "then": {
                            "properties": {
                                "source_replay_receipt": {"type": "null"},
                                "verifier_version": {"const": "runtime-lock-verifier-v1"},
                            }
                        },
                        "else": {
                            "properties": {
                                "verifier_version": {"const": "runtime-lock-verifier-v2"}
                            }
                        },
                    }
                ]
            }
        ),
    )

    schema_version: RuntimeLockSchemaVersion = LEGACY_RUNTIME_LOCK_SCHEMA_VERSION
    runtime_lock_verification_id: ArtifactId
    runtime_lock_evidence_id: ArtifactId
    runtime_lock_evidence_content_sha256: Sha256
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_analysis_content_sha256: Sha256
    created_at: str
    verification_status: Literal["verified", "partial", "failed"]
    checks: tuple[RuntimeLockVerificationCheck, ...] = Field(min_length=1)
    source_replay_receipt: RuntimeLockSourceReplayReceipt | None = None
    verifier_version: Literal[
        "runtime-lock-verifier-v1",
        "runtime-lock-verifier-v2",
    ] = "runtime-lock-verifier-v1"
    content_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def default_verifier_for_schema(cls, data: object) -> object:
        if not isinstance(data, Mapping):
            return data
        mapping = cast(Mapping[str, object], data)
        if "verifier_version" in mapping:
            return mapping
        normalized: dict[str, object] = dict(mapping)
        schema_version = normalized.get("schema_version", LEGACY_RUNTIME_LOCK_SCHEMA_VERSION)
        normalized["verifier_version"] = (
            "runtime-lock-verifier-v1" if schema_version == "1.0" else "runtime-lock-verifier-v2"
        )
        return normalized

    @model_validator(mode="after")
    def validate_verification(self) -> RuntimeLockAnalysisVerificationArtifact:
        expected_verifier = (
            "runtime-lock-verifier-v1"
            if self.schema_version == "1.0"
            else "runtime-lock-verifier-v2"
        )
        if self.verifier_version != expected_verifier:
            raise ValueError("runtime verifier version contradicts its schema version")
        if self.schema_version == "1.0" and self.source_replay_receipt is not None:
            raise ValueError("schema 1.0 verification cannot carry a source replay receipt")
        if self.source_replay_receipt is not None and (
            self.source_replay_receipt.runtime_lock_evidence_id != self.runtime_lock_evidence_id
            or self.source_replay_receipt.runtime_lock_evidence_content_sha256
            != self.runtime_lock_evidence_content_sha256
        ):
            raise ValueError("source replay receipt differs from verified Runtime Lock evidence")
        statuses = {check.status for check in self.checks}
        names = tuple(check.name for check in self.checks)
        if len(set(names)) != len(names):
            raise ValueError("runtime verification check names must be unique")
        expected = (
            "failed"
            if "failed" in statuses
            else ("partial" if "skipped" in statuses else "verified")
        )
        if self.verification_status != expected:
            raise ValueError("runtime verification status contradicts its checks")
        return self


RuntimeLockProjectionName = Literal[
    "lock",
    "execution_context",
    "call_path",
    "wait_outcome",
    "lock_kind",
]
RuntimeLockProjectionItem = (
    RuntimeLockAggregate
    | RuntimeExecutionContextAggregate
    | RuntimeCallPathAggregate
    | RuntimeWaitOutcomeAggregate
    | RuntimeLockKindAggregate
)


class RuntimeLockHotspotPage(ContractModel):
    """One bounded page from exactly one independently conserved projection."""

    schema_version: RuntimeLockSchemaVersion
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_evidence_id: ArtifactId
    projection: RuntimeLockProjectionName
    measurement_semantics: MeasurementSemantics
    quality_status: EvidenceStatus
    items: tuple[RuntimeLockProjectionItem, ...]
    cursor: int = Field(ge=0)
    next_cursor: int | None = Field(default=None, ge=0)
    total_items: int = Field(ge=0)
    coverage: RuntimeProjectionCoverage | None = None
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]

    @model_validator(mode="after")
    def validate_page(self) -> RuntimeLockHotspotPage:
        expected_type: dict[RuntimeLockProjectionName, type[RuntimeProjectionMetrics]] = {
            "lock": RuntimeLockAggregate,
            "execution_context": RuntimeExecutionContextAggregate,
            "call_path": RuntimeCallPathAggregate,
            "wait_outcome": RuntimeWaitOutcomeAggregate,
            "lock_kind": RuntimeLockKindAggregate,
        }
        if any(not isinstance(item, expected_type[self.projection]) for item in self.items):
            raise ValueError("runtime hotspot page contains another projection type")
        if self.cursor + len(self.items) > self.total_items:
            raise ValueError("runtime hotspot page exceeds its total item count")
        expected_next = (
            self.cursor + len(self.items)
            if self.cursor + len(self.items) < self.total_items
            else None
        )
        if self.next_cursor != expected_next:
            raise ValueError("runtime hotspot page next cursor is inconsistent")
        if self.schema_version == "1.1":
            if self.coverage is None:
                raise ValueError("schema 1.1 runtime hotspot page requires coverage")
            if self.coverage.exported_row_count != self.total_items:
                raise ValueError("runtime hotspot page total differs from projection coverage")
        elif self.coverage is not None:
            raise ValueError("schema 1.0 runtime hotspot page cannot carry coverage")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("runtime hotspot page conclusion sets overlap")
        return self


class RuntimeLockCallPathPage(ContractModel):
    """Call-path projections joined to their bounded, redacted public stacks."""

    schema_version: RuntimeLockSchemaVersion
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_evidence_id: ArtifactId
    measurement_semantics: MeasurementSemantics
    quality_status: EvidenceStatus
    items: tuple[RuntimeCallPathAggregate, ...]
    stacks: tuple[RuntimeStack | None, ...]
    cursor: int = Field(ge=0)
    next_cursor: int | None = Field(default=None, ge=0)
    total_items: int = Field(ge=0)
    coverage: RuntimeProjectionCoverage | None = None
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]

    @model_validator(mode="after")
    def validate_page(self) -> RuntimeLockCallPathPage:
        if len(self.items) != len(self.stacks):
            raise ValueError("runtime call-path rows and stacks must have equal length")
        if any(
            (item.stack_id is None) != (stack is None)
            or (stack is not None and item.stack_id != stack.stack_id)
            for item, stack in zip(self.items, self.stacks, strict=True)
        ):
            raise ValueError("runtime call-path rows do not match their public stacks")
        if self.cursor + len(self.items) > self.total_items:
            raise ValueError("runtime call-path page exceeds its total item count")
        expected_next = (
            self.cursor + len(self.items)
            if self.cursor + len(self.items) < self.total_items
            else None
        )
        if self.next_cursor != expected_next:
            raise ValueError("runtime call-path page next cursor is inconsistent")
        if self.schema_version == "1.1":
            if self.coverage is None:
                raise ValueError("schema 1.1 runtime call-path page requires coverage")
            if self.coverage.exported_row_count != self.total_items:
                raise ValueError("runtime call-path total differs from projection coverage")
        elif self.coverage is not None:
            raise ValueError("schema 1.0 runtime call-path page cannot carry coverage")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("runtime call-path page conclusion sets overlap")
        return self


def derive_runtime_lock_diagnosis_id(
    runtime_lock_analysis_id: str,
    runtime_lock_analysis_content_sha256: str,
    runtime_lock_verification_content_sha256: str,
) -> str:
    material = "\0".join(
        (
            "perflens-runtime-lock-diagnosis-v1",
            runtime_lock_analysis_id,
            runtime_lock_analysis_content_sha256,
            runtime_lock_verification_content_sha256,
        )
    )
    return f"runtime-lock-diagnosis-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


class RuntimeLockDiagnosisBundleArtifact(ContractModel):
    """Bounded Agent-facing summary whose facts remain bound to verified evidence."""

    schema_version: RuntimeLockSchemaVersion
    runtime_lock_diagnosis_id: ArtifactId
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_analysis_content_sha256: Sha256
    runtime_lock_evidence_id: ArtifactId
    runtime_lock_evidence_content_sha256: Sha256
    runtime_lock_verification_id: ArtifactId
    runtime_lock_verification_content_sha256: Sha256
    created_at: str
    runtime: RuntimeFamily
    measurement_semantics: MeasurementSemantics
    quality_status: EvidenceStatus
    observations: tuple[str, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)
    top_lock_ids: tuple[LockId, ...] = Field(max_length=32)
    top_execution_context_ids: tuple[ExecutionContextId, ...] = Field(max_length=32)
    top_stack_ids: tuple[StackId, ...] = Field(max_length=32)
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_bundle(self) -> RuntimeLockDiagnosisBundleArtifact:
        expected = derive_runtime_lock_diagnosis_id(
            self.runtime_lock_analysis_id,
            self.runtime_lock_analysis_content_sha256,
            self.runtime_lock_verification_content_sha256,
        )
        if self.runtime_lock_diagnosis_id != expected:
            raise ValueError("runtime diagnosis ID differs from its verified Analysis")
        for values, label in (
            (self.top_lock_ids, "lock"),
            (self.top_execution_context_ids, "execution-context"),
            (self.top_stack_ids, "stack"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"runtime diagnosis {label} IDs must be unique")
        if any(not item.strip() for item in (*self.observations, *self.limitations)):
            raise ValueError("runtime diagnosis text cannot be blank")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("runtime diagnosis conclusion sets overlap")
        return self
