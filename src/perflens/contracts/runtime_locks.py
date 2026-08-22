"""Public contract groundwork for the planned v0.4.0 runtime-lock adapters.

The runtime adapters intentionally share one evidence model even though their
source semantics differ.  Exact event streams, thresholded events, sampled
profiles, and cumulative profiles remain distinguishable all the way to the
Agent-visible analysis artifact.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from perflens.contracts.artifacts import SCHEMA_VERSION, ContractModel

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ArtifactId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*-[a-f0-9]{16,64}$")]
EventId = Annotated[str, Field(pattern=r"^runtime-event-[a-f0-9]{16,64}$")]
LockId = Annotated[str, Field(pattern=r"^runtime-lock-[a-f0-9]{20}$")]
StackId = Annotated[str, Field(pattern=r"^runtime-stack-[a-f0-9]{16,64}$")]

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


class RuntimeTargetIdentity(ContractModel):
    """PID identity bound at collection/import time."""

    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    observed_target_tids: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_tids(self) -> RuntimeTargetIdentity:
        tids = self.observed_target_tids
        if any(isinstance(tid, bool) or tid <= 0 for tid in tids):
            raise ValueError("runtime target TIDs must contain positive integers")
        if len(set(tids)) != len(tids) or tuple(sorted(tids)) != tids:
            raise ValueError("runtime target TIDs must be unique and sorted")
        return self


class RuntimeToolIdentity(ContractModel):
    """Identity of one optional external tool discovered without executing a workload."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,64}$")
    path: str | None = None
    version: str | None = Field(default=None, max_length=256)
    binary_sha256: Sha256 | None = None
    status: Literal["available", "missing", "unsupported", "not_checked"]
    reason: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_identity(self) -> RuntimeToolIdentity:
        if self.path is not None and not self.path.startswith("/"):
            raise ValueError("runtime tool path must be absolute")
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

    schema_version: Literal["1.0"] = SCHEMA_VERSION
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

    schema_version: Literal["1.0"] = SCHEMA_VERSION
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

    @model_validator(mode="after")
    def validate_semantics(self) -> RuntimeSourceManifest:
        _validate_measurement_controls(
            self.measurement_semantics,
            duration_threshold_ns=self.duration_threshold_ns,
            sampling_period=self.sampling_period,
            sampling_fraction=self.sampling_fraction,
            block_profile_rate_ns=self.block_profile_rate_ns,
        )
        return self


class RuntimeLockImportHeader(ContractModel):
    """First record of the strict custom/runtime NDJSON import contract.

    The header intentionally contains no path, command, environment, or raw lock
    address.  The adapter computes ``RuntimeSourceManifest`` hashes after it has
    consumed the complete immutable stream.
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
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
        if not self.visible_lock_kinds:
            raise ValueError("runtime lock import must declare visible lock kinds")
        if len(set(self.visible_lock_kinds)) != len(self.visible_lock_kinds) or tuple(
            sorted(self.visible_lock_kinds)
        ) != self.visible_lock_kinds:
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
    symbol: str = Field(min_length=1, max_length=4096)
    module: str = Field(min_length=1, max_length=4096)
    source_file: str | None = Field(default=None, max_length=4096)
    source_line: int | None = Field(default=None, gt=0)
    is_runtime: bool = False
    is_unknown: bool = False


class RuntimeStack(ContractModel):
    stack_id: StackId
    frames: tuple[RuntimeStackFrame, ...] = Field(min_length=1)


class RuntimeLockEventBase(ContractModel):
    event_id: EventId
    event_index: int = Field(ge=0)
    timestamp_ns: int = Field(ge=0)
    target_tid: int = Field(gt=0)
    lock_id: LockId | None = None
    lock_kind: LockKind
    stack_id: StackId | None = None
    measurement_semantics: MeasurementSemantics


class RuntimeWaitBeginEvent(RuntimeLockEventBase):
    event_kind: Literal["wait_begin"] = "wait_begin"
    owner_target_tid: int | None = Field(default=None, gt=0)


class RuntimeWaitEndEvent(RuntimeLockEventBase):
    event_kind: Literal["wait_end"] = "wait_end"
    wait_begin_event_id: EventId | None = None
    duration_ns: int = Field(ge=0)
    outcome: WaitOutcome
    owner_target_tid: int | None = Field(default=None, gt=0)


class RuntimeAcquireEvent(RuntimeLockEventBase):
    event_kind: Literal["acquire"] = "acquire"


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
    parked_target_tid: int = Field(gt=0)

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
    input_record_count: int = Field(ge=0)
    emitted_event_count: int = Field(ge=0)
    filtered_outside_target_count: int = Field(ge=0)
    malformed_record_count: int = Field(ge=0)
    duplicate_record_count: int = Field(ge=0)
    unsupported_record_count: int = Field(ge=0)
    lost_event_count: int = Field(ge=0)
    truncated_event_count: int = Field(ge=0)
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
            + self.unsupported_record_count
            + self.truncated_event_count
        )
        if terminal != self.input_record_count:
            raise ValueError("runtime evidence input records are not conserved")
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
                self.diagnostic_count,
            )
        )
        if self.status == "complete" and (degraded or self.limitations):
            raise ValueError("complete runtime evidence cannot contain loss or limitations")
        if self.status == "partial" and not (degraded or self.limitations):
            raise ValueError("partial runtime evidence requires a limitation")
        return self


class RuntimeLockEvidenceArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    runtime_lock_evidence_id: ArtifactId
    created_at: str
    target: RuntimeTargetIdentity
    source: RuntimeSourceManifest
    limits: RuntimeLockResourceLimits
    quality: RuntimeEvidenceQuality
    stacks: tuple[RuntimeStack, ...] = ()
    events: tuple[RuntimeLockEvent, ...]
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    evidence_fingerprint: Sha256
    content_sha256: Sha256
    content_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_evidence(self) -> RuntimeLockEvidenceArtifact:
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
        allowed_tids = set(self.target.observed_target_tids)
        observed_owner_count = 0
        for event in self.events:
            if event.target_tid not in allowed_tids:
                raise ValueError("runtime event escaped the observed target TID set")
            for referenced_tid in (
                getattr(event, "owner_target_tid", None),
                getattr(event, "parked_target_tid", None),
            ):
                if referenced_tid is not None and referenced_tid not in allowed_tids:
                    raise ValueError("runtime event disclosed a non-target thread")
            if getattr(event, "owner_target_tid", None) is not None:
                observed_owner_count += 1
                if not self.source.owner_is_source_observed:
                    raise ValueError("runtime event fabricated owner visibility")
            if (
                isinstance(event, RuntimeReleaseEvent)
                and event.hold_duration_ns is not None
                and not self.source.hold_time_is_source_observed
            ):
                raise ValueError("runtime event fabricated hold-time visibility")
        if observed_owner_count != self.quality.owner_observed_event_count:
            raise ValueError("runtime owner observations contradict the event tuple")
        stack_ids = tuple(stack.stack_id for stack in self.stacks)
        if len(set(stack_ids)) != len(stack_ids):
            raise ValueError("runtime stack IDs must be unique")
        if any(
            event.stack_id is not None and event.stack_id not in stack_ids
            for event in self.events
        ):
            raise ValueError("runtime event references an unknown stack")
        lock_ids = {event.lock_id for event in self.events if event.lock_id is not None}
        if len(lock_ids) > self.limits.max_unique_locks:
            raise ValueError("runtime evidence exceeds max_unique_locks")
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
        if not self.source.hold_time_is_source_observed and "exact_hold_time" not in (
            self.forbidden_conclusions
        ):
            raise ValueError("runtime evidence without hold data must forbid hold conclusions")
        return self


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


class RuntimeLockAggregate(ContractModel):
    lock_id: LockId | None
    lock_kind: LockKind
    exact_waits: RuntimeNanosecondDistribution
    thresholded_waits: RuntimeNanosecondDistribution
    sampled_observation_count: int = Field(ge=0)
    cumulative_observation_count: int = Field(ge=0)
    observed_or_estimated_wait_ns: int = Field(ge=0)
    exact_holds: RuntimeNanosecondDistribution
    waiter_thread_count: int = Field(ge=0)
    owner_observed_count: int = Field(ge=0)
    top_stack_ids: tuple[StackId, ...] = ()

    @model_validator(mode="after")
    def validate_aggregate(self) -> RuntimeLockAggregate:
        if self.owner_observed_count > (
            self.exact_waits.sample_count + self.thresholded_waits.sample_count
        ):
            raise ValueError("runtime aggregate owner observations exceed event waits")
        if len(set(self.top_stack_ids)) != len(self.top_stack_ids):
            raise ValueError("runtime aggregate stack IDs must be unique")
        return self


class RuntimeLockAnalysisArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
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
    total_exact_wait_count: int = Field(ge=0)
    total_thresholded_wait_count: int = Field(ge=0)
    total_sampled_observation_count: int = Field(ge=0)
    total_cumulative_observation_count: int = Field(ge=0)
    total_exact_hold_count: int = Field(ge=0)
    omitted_lock_count: int = Field(ge=0)
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    analysis_fingerprint: Sha256
    content_sha256: Sha256
    content_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_analysis(self) -> RuntimeLockAnalysisArtifact:
        if len(self.aggregates) > self.limits.max_exported_locks:
            raise ValueError("runtime analysis exceeds max_exported_locks")
        if self.runtime_lock_evidence_content_bytes > self.limits.max_output_bytes:
            raise ValueError("runtime analysis input exceeds max_output_bytes")
        if self.content_bytes > self.limits.max_output_bytes:
            raise ValueError("runtime analysis exceeds max_output_bytes")
        lock_ids = tuple(row.lock_id for row in self.aggregates if row.lock_id is not None)
        if len(set(lock_ids)) != len(lock_ids):
            raise ValueError("runtime lock aggregates must have unique lock IDs")
        expected = (
            sum(row.exact_waits.sample_count for row in self.aggregates),
            sum(row.thresholded_waits.sample_count for row in self.aggregates),
            sum(row.sampled_observation_count for row in self.aggregates),
            sum(row.cumulative_observation_count for row in self.aggregates),
            sum(row.exact_holds.sample_count for row in self.aggregates),
        )
        actual = (
            self.total_exact_wait_count,
            self.total_thresholded_wait_count,
            self.total_sampled_observation_count,
            self.total_cumulative_observation_count,
            self.total_exact_hold_count,
        )
        if actual != expected:
            raise ValueError("runtime lock analysis aggregates are not conserved")
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


class RuntimeLockVerificationCheck(ContractModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    status: Literal["passed", "failed", "skipped"]
    detail: str = Field(min_length=1, max_length=1024)


class RuntimeLockAnalysisVerificationArtifact(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    runtime_lock_verification_id: ArtifactId
    runtime_lock_evidence_id: ArtifactId
    runtime_lock_evidence_content_sha256: Sha256
    runtime_lock_analysis_id: ArtifactId
    runtime_lock_analysis_content_sha256: Sha256
    created_at: str
    verification_status: Literal["verified", "partial", "failed"]
    checks: tuple[RuntimeLockVerificationCheck, ...] = Field(min_length=1)
    verifier_version: Literal["runtime-lock-verifier-v1"] = "runtime-lock-verifier-v1"
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_verification(self) -> RuntimeLockAnalysisVerificationArtifact:
        statuses = {check.status for check in self.checks}
        names = tuple(check.name for check in self.checks)
        if len(set(names)) != len(names):
            raise ValueError("runtime verification check names must be unique")
        expected = "failed" if "failed" in statuses else (
            "partial" if "skipped" in statuses else "verified"
        )
        if self.verification_status != expected:
            raise ValueError("runtime verification status contradicts its checks")
        return self
