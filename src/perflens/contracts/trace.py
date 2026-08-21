"""Versioned public contracts for deterministic trace evidence and analysis.

These models describe normalized, target-scoped trace evidence.  They never
embed or attempt to decode ``perf.data``; the immutable source artifact is
identified by digest and a fixed external-converter manifest instead.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from perflens.contracts.artifacts import (
    SCHEMA_VERSION,
    ContainerCollectionTargetBinding,
    ContractModel,
)

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ArtifactId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*-[a-f0-9]{16,64}$")]
CollectionId = Annotated[str, Field(pattern=r"^collection-[a-f0-9]{16,64}$")]
EventId = Annotated[str, Field(pattern=r"^event-[a-f0-9]{16,64}$")]
LockId = Annotated[str, Field(pattern=r"^lock-[a-f0-9]{20}$")]


class TraceTargetIdentity(ContractModel):
    """Immutable identity of the process authorized for trace analysis."""

    target_pid: int = Field(gt=0)
    target_uid: int = Field(ge=0)
    target_start_time_ticks: int = Field(gt=0)
    target_runtime: Literal["host", "docker"] = "host"
    container_target: ContainerCollectionTargetBinding | None = None
    # A zero-event, explicitly partial trace may have observed no target thread at all.  Once
    # events exist, the artifact validators below require every event TID to appear here.
    observed_target_tids: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_target_tids(self) -> TraceTargetIdentity:
        if any(isinstance(tid, bool) or tid <= 0 for tid in self.observed_target_tids):
            raise ValueError("observed target TIDs must contain positive integers")
        if len(set(self.observed_target_tids)) != len(self.observed_target_tids):
            raise ValueError("observed target TIDs must be unique")
        if tuple(sorted(self.observed_target_tids)) != self.observed_target_tids:
            raise ValueError("observed target TIDs must be sorted")
        if self.target_runtime == "host":
            if self.container_target is not None:
                raise ValueError("host trace target cannot carry a Docker identity")
        elif self.container_target is None:
            raise ValueError("Docker trace target requires a complete container identity")
        elif (
            self.target_pid != self.container_target.host_pid
            or self.target_uid != self.container_target.host_uid
            or self.target_start_time_ticks != self.container_target.host_start_time_ticks
        ):
            raise ValueError("Docker trace target identity fields differ")
        return self


class TraceEventFormatIdentity(ContractModel):
    """Hash of one kernel event format consumed by the fixed capture backend."""

    event_name: str = Field(pattern=r"^[a-z0-9_]+:[a-z0-9_]+$")
    format_sha256: Sha256


class TraceCaptureManifest(ContractModel):
    """Agent-visible identity and coverage of the private trace producer.

    A successful converter cannot prove that the producer observed every event required for a
    scheduler or off-CPU conclusion.  These fields keep that independent capture boundary in the
    evidence hash and prevent a partial ``perf -p`` capture from being relabeled as complete.
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    mode: Literal["sched", "off_cpu", "lock"]
    backend_id: Literal[
        "target_filtered_kernel_v1",
        "stock_perf_pid_partial_v1",
        "verified_private_import_v1",
    ]
    backend_version: str = Field(min_length=1, max_length=128)
    producer_path: str = Field(min_length=1)
    producer_sha256: Sha256
    kernel_release: str = Field(min_length=1, max_length=256)
    architecture: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,64}$")
    byte_order: Literal["little", "big"]
    pointer_size_bits: Literal[32, 64]
    target_scope: Literal["kernel_tgid_filtered", "per_task_partial", "verified_import"]
    dynamic_thread_coverage: Literal["complete", "partial", "unknown"]
    switch_in_visibility: Literal["complete", "partial", "not_applicable", "unknown"]
    external_wakeup_visibility: Literal[
        "complete", "partial", "not_applicable", "unknown"
    ]
    foreign_metadata_before_userspace: bool
    event_formats: tuple[TraceEventFormatIdentity, ...] = Field(min_length=1)
    capture_fingerprint: Sha256

    @model_validator(mode="after")
    def validate_capture_boundary(self) -> TraceCaptureManifest:
        if not self.producer_path.startswith("/"):
            raise ValueError("trace producer_path must be absolute")
        event_names = tuple(item.event_name for item in self.event_formats)
        if len(set(event_names)) != len(event_names) or tuple(sorted(event_names)) != event_names:
            raise ValueError("trace event formats must be unique and sorted")
        if self.mode == "lock":
            if self.switch_in_visibility != "not_applicable" or (
                self.external_wakeup_visibility != "not_applicable"
            ):
                raise ValueError("lock capture must mark scheduler visibility not_applicable")
        elif (
            self.switch_in_visibility == "not_applicable"
            or self.external_wakeup_visibility == "not_applicable"
        ):
            raise ValueError("scheduler capture requires explicit switch-in and wakeup visibility")

        if self.backend_id == "target_filtered_kernel_v1":
            if (
                self.target_scope != "kernel_tgid_filtered"
                or self.dynamic_thread_coverage != "complete"
                or self.foreign_metadata_before_userspace
            ):
                raise ValueError("target-filtered backend must enforce its complete privacy scope")
            if self.mode in {"sched", "off_cpu"} and (
                self.switch_in_visibility != "complete"
                or self.external_wakeup_visibility != "complete"
            ):
                raise ValueError(
                    "target-filtered scheduler capture requires complete event visibility"
                )
        elif self.backend_id == "stock_perf_pid_partial_v1":
            if self.target_scope != "per_task_partial":
                raise ValueError("stock perf PID capture must remain per-task partial")
            if self.dynamic_thread_coverage == "complete":
                raise ValueError(
                    "stock perf PID capture cannot claim complete dynamic-thread coverage"
                )
            if self.mode in {"sched", "off_cpu"} and (
                self.switch_in_visibility == "complete"
                or self.external_wakeup_visibility == "complete"
            ):
                raise ValueError(
                    "stock perf PID capture cannot claim complete scheduler visibility"
                )
        elif self.target_scope != "verified_import":
            raise ValueError("private imported trace must use verified_import scope")
        return self


class TraceRawArtifactReference(ContractModel):
    """Identity of the immutable Collector artifact used as converter input."""

    collection_id: CollectionId
    mode: Literal["sched", "off_cpu", "lock"]
    collection_artifact_sha256: Sha256
    output_sha256: Sha256
    output_bytes: int = Field(gt=0)
    output_format: Literal["perf_data", "target_filtered_trace_ndjson"] = "perf_data"
    capture: TraceCaptureManifest

    @model_validator(mode="after")
    def validate_capture_mode(self) -> TraceRawArtifactReference:
        if self.capture.mode != self.mode:
            raise ValueError("trace capture manifest mode must match the raw artifact mode")
        return self


class TraceConversionManifest(ContractModel):
    """Reproducible manifest for the fixed external trace conversion."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    adapter: Literal["perf_script_trace", "kernel_trace_ndjson"] = "perf_script_trace"
    recipe_id: Literal["sched-v1", "off-cpu-v1", "lock-v1"]
    converter_path: str = Field(min_length=1)
    converter_sha256: Sha256
    converter_version: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    normalization_version: str = Field(min_length=1)
    argv: tuple[str, ...] = Field(min_length=1)
    locale: Literal["C"] = "C"
    output_format: Literal["perflens_trace_ndjson_v1"] = "perflens_trace_ndjson_v1"
    conversion_fingerprint: Sha256

    @model_validator(mode="after")
    def validate_converter_identity(self) -> TraceConversionManifest:
        if not self.converter_path.startswith("/"):
            raise ValueError("trace converter_path must be absolute")
        if self.argv[0] != self.converter_path:
            raise ValueError("trace converter argv must start with converter_path")
        if any(not argument for argument in self.argv):
            raise ValueError("trace converter argv must not contain empty arguments")
        expected = (
            (
                self.converter_path,
                "script",
                "--force",
                "--ns",
                "--show-lost-events",
                "-F",
                "trace:pid,tid,cpu,time,event,trace",
                "-i",
                "<private-input>",
            )
            if self.adapter == "perf_script_trace"
            else (self.converter_path, "<private-input>")
        )
        private_path_options = {
            "-i": "<private-input>",
            "--input": "<private-input>",
            "-o": "<private-output>",
            "--output": "<private-output>",
        }
        for index, argument in enumerate(self.argv[1:], start=1):
            if "/" in argument or argument.endswith((".data", ".ndjson")):
                raise ValueError(
                    "public trace converter argv must redact input/output paths and filenames"
                )
            if argument in private_path_options and (
                index + 1 >= len(self.argv)
                or self.argv[index + 1] != private_path_options[argument]
            ):
                raise ValueError("trace converter path options require fixed private placeholders")
            for option, placeholder in private_path_options.items():
                if argument.startswith(f"{option}=") and argument != f"{option}={placeholder}":
                    raise ValueError(
                        "trace converter path options require fixed private placeholders"
                    )
        if self.argv != expected:
            raise ValueError("trace converter argv must match the fixed versioned recipe")
        return self


class TraceClock(ContractModel):
    """Clock domain shared by all normalized trace timestamps."""

    clock: Literal["monotonic"] = "monotonic"
    unit: Literal["nanoseconds"] = "nanoseconds"
    source: Literal["linux_perf", "linux_bpf"] = "linux_perf"


class TraceObservationWindow(ContractModel):
    """Boundaries used when deciding whether an interval is complete."""

    start_timestamp_ns: int = Field(ge=0)
    end_timestamp_ns: int = Field(ge=0)
    source: Literal["collector_monotonic_bounds", "observed_event_bounds"]

    @model_validator(mode="after")
    def validate_bounds(self) -> TraceObservationWindow:
        if self.end_timestamp_ns < self.start_timestamp_ns:
            raise ValueError("trace observation window ends before it starts")
        return self


class TraceResourceLimits(ContractModel):
    max_duration_seconds: int = Field(default=10, gt=0, le=10)
    max_input_bytes: int = Field(default=67_108_864, gt=0, le=67_108_864)
    max_input_lines: int = Field(default=100_000, gt=0, le=200_000)
    max_input_events: int = Field(default=100_000, gt=0, le=100_000)
    max_line_bytes: int = Field(default=65_536, gt=0, le=65_536)
    max_stack_depth: int = Field(default=127, gt=0, le=127)
    max_exported_events: int = Field(default=100_000, gt=0, le=100_000)
    max_exported_intervals: int = Field(default=100_000, gt=0, le=100_000)
    max_unique_target_tids: int = Field(default=65_536, gt=0, le=65_536)
    max_unique_locks: int = Field(default=100_000, gt=0, le=100_000)
    max_diagnostics: int = Field(default=1_000, gt=0, le=10_000)
    max_warnings: int = Field(default=1_000, gt=0, le=10_000)
    max_output_bytes: int = Field(default=67_108_864, gt=0, le=67_108_864)


class TraceQuality(ContractModel):
    """Conserved conversion counts and the evidence quality they imply.

    ``input_event_count`` counts records observed by the converter. Every
    observed record is either emitted, merged as non-emitting enrichment, or
    assigned exactly one drop category. A source record may also expand into
    more than one scoped public event; ``expanded_derived_event_count`` is the
    exact number of additional events created by that expansion. Kernel-
    reported lost events were never observed, while unpaired events may remain
    in the emitted evidence, so both are tracked separately from that equality.
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    quality_status: Literal["verified", "partial"]
    input_event_count: int = Field(ge=0)
    emitted_event_count: int = Field(ge=0)
    expanded_derived_event_count: int = Field(default=0, ge=0)
    merged_enrichment_event_count: int = Field(default=0, ge=0)
    lost_event_count: int = Field(ge=0)
    malformed_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    out_of_order_event_count: int = Field(ge=0)
    unpaired_event_count: int = Field(ge=0)
    unsupported_event_count: int = Field(ge=0)
    truncated_event_count: int = Field(ge=0)
    foreign_event_dropped_count: int = Field(ge=0)
    diagnostics_truncated: bool = False
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_conservation_and_status(self) -> TraceQuality:
        dropped = (
            self.malformed_event_count
            + self.duplicate_event_count
            + self.out_of_order_event_count
            + self.unsupported_event_count
            + self.truncated_event_count
            + self.foreign_event_dropped_count
        )
        if self.input_event_count + self.expanded_derived_event_count != (
            self.emitted_event_count + self.merged_enrichment_event_count + dropped
        ):
            raise ValueError("trace event counts are not conserved")
        if self.unpaired_event_count > self.emitted_event_count:
            raise ValueError("unpaired trace events exceed emitted events")
        degraded = (
            self.emitted_event_count == 0
            or self.input_event_count == 0
            or self.lost_event_count > 0
            or self.unpaired_event_count > 0
            or dropped > 0
            or self.diagnostics_truncated
        )
        if self.quality_status == "verified" and degraded:
            raise ValueError(
                "verified trace quality requires emitted evidence without loss, "
                "drops, or truncation"
            )
        return self


class TraceStackFrame(ContractModel):
    ip: str | None = Field(default=None, pattern=r"^(?:0x)?[a-fA-F0-9]+$")
    symbol: str = Field(min_length=1)
    dso: str = Field(min_length=1)
    source_file: str | None = None
    source_line: int | None = Field(default=None, ge=1)
    is_kernel: bool = False


class TraceEventBase(ContractModel):
    event_id: EventId
    event_index: int = Field(ge=0)
    source_sequence: int = Field(ge=0)
    timestamp_ns: int = Field(ge=0)
    cpu: int = Field(ge=0)
    target_pid: int = Field(gt=0)
    target_tid: int = Field(gt=0)


class SchedSwitchEvent(TraceEventBase):
    event_type: Literal["sched_switch"] = "sched_switch"
    direction: Literal["switch_out", "switch_in"]
    previous_state: (
        Literal[
            "running",
            "interruptible_sleep",
            "uninterruptible_sleep",
            "stopped",
            "traced",
            "dead",
            "parked",
            "idle",
            "unknown",
        ]
        | None
    ) = None
    call_stack: tuple[TraceStackFrame, ...] = ()
    semantics: Literal["exact"] = "exact"

    @model_validator(mode="after")
    def validate_previous_state(self) -> SchedSwitchEvent:
        if self.direction == "switch_out" and self.previous_state is None:
            raise ValueError("switch_out requires previous_state")
        if self.direction == "switch_in" and self.previous_state is not None:
            raise ValueError("switch_in must not carry previous_state")
        return self


class SchedWakeupEvent(TraceEventBase):
    event_type: Literal["sched_wakeup"] = "sched_wakeup"
    source_event: Literal["sched_wakeup", "sched_wakeup_new"]
    waker_relation: Literal["same_target", "redacted", "unavailable"]
    waker_target_tid: int | None = Field(default=None, gt=0)
    semantics: Literal["exact"] = "exact"

    @model_validator(mode="after")
    def validate_waker_identity(self) -> SchedWakeupEvent:
        disclosed = self.waker_relation == "same_target"
        if disclosed != (self.waker_target_tid is not None):
            raise ValueError("target waker TID presence must match the disclosed relation")
        return self


class SchedMigrateEvent(TraceEventBase):
    event_type: Literal["sched_migrate"] = "sched_migrate"
    origin_cpu: int = Field(ge=0)
    destination_cpu: int = Field(ge=0)
    semantics: Literal["exact"] = "exact"

    @model_validator(mode="after")
    def validate_migration(self) -> SchedMigrateEvent:
        if self.origin_cpu == self.destination_cpu:
            raise ValueError("scheduler migration must change CPU")
        return self


class LockWaitEvent(TraceEventBase):
    event_type: Literal["lock_wait"] = "lock_wait"
    lock_id: LockId
    lock_kind: Literal["kernel_lock", "unknown"]
    owner_target_tid: int | None = Field(default=None, gt=0)
    call_stack: tuple[TraceStackFrame, ...] = ()
    semantics: Literal["exact"] = "exact"


class LockWaitEndedEvent(TraceEventBase):
    """Observed lock-wait completion; only ``acquired`` may close an exact wait."""

    event_type: Literal["lock_wait_ended"] = "lock_wait_ended"
    lock_id: LockId
    lock_kind: Literal["kernel_lock", "unknown"]
    outcome: Literal["acquired", "timed_out", "interrupted", "failed", "unknown"]
    call_stack: tuple[TraceStackFrame, ...] = ()
    semantics: Literal["exact"] = "exact"


class LockReleasedEvent(TraceEventBase):
    event_type: Literal["lock_released"] = "lock_released"
    lock_id: LockId
    lock_kind: Literal["kernel_lock", "unknown"]
    call_stack: tuple[TraceStackFrame, ...] = ()
    semantics: Literal["exact"] = "exact"


class FutexWaitEvent(TraceEventBase):
    event_type: Literal["futex_wait"] = "futex_wait"
    lock_id: LockId
    operation: Literal["wait", "wait_bitset", "wait_requeue_pi", "unknown"]
    call_stack: tuple[TraceStackFrame, ...] = ()
    semantics: Literal["candidate"] = "candidate"


class FutexWakeEvent(TraceEventBase):
    event_type: Literal["futex_wake"] = "futex_wake"
    lock_id: LockId
    operation: Literal["wake", "wake_bitset", "requeue", "unknown"]
    woken_count: int | None = Field(default=None, ge=0)
    semantics: Literal["candidate"] = "candidate"


TraceEvent = Annotated[
    SchedSwitchEvent
    | SchedWakeupEvent
    | SchedMigrateEvent
    | LockWaitEvent
    | LockWaitEndedEvent
    | LockReleasedEvent
    | FutexWaitEvent
    | FutexWakeEvent,
    Field(discriminator="event_type"),
]


class TraceArtifactBase(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    perflens_version: str = Field(min_length=1)
    mode: Literal["sched", "off_cpu", "lock"]
    status: Literal["complete", "partial"]
    input_sha256: Sha256
    input_bytes: int = Field(gt=0)
    source: TraceRawArtifactReference
    target: TraceTargetIdentity
    conversion: TraceConversionManifest
    clock: TraceClock
    observation_window: TraceObservationWindow
    quality: TraceQuality
    limits: TraceResourceLimits
    allowed_conclusions: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_common_trace_semantics(self) -> TraceArtifactBase:
        if self.source.mode != self.mode:
            raise ValueError("raw trace mode must match artifact mode")
        expected_recipe = {
            "sched": "sched-v1",
            "off_cpu": "off-cpu-v1",
            "lock": "lock-v1",
        }[self.mode]
        if self.conversion.recipe_id != expected_recipe:
            raise ValueError("trace conversion recipe does not match artifact mode")
        if len(self.target.observed_target_tids) > self.limits.max_unique_target_tids:
            raise ValueError("observed target TIDs exceed max_unique_target_tids")
        if (
            self.observation_window.end_timestamp_ns - self.observation_window.start_timestamp_ns
            > self.limits.max_duration_seconds * 1_000_000_000
        ):
            raise ValueError("trace observation window exceeds max_duration_seconds")
        if self.quality.input_event_count > self.limits.max_input_events:
            raise ValueError("trace input event count exceeds max_input_events")
        if self.quality.emitted_event_count > self.limits.max_exported_events:
            raise ValueError("trace emitted event count exceeds max_exported_events")
        if self.status == "complete" and self.quality.quality_status != "verified":
            raise ValueError("complete trace artifacts require verified quality")
        if self.status == "partial" and not self.quality.limitations:
            raise ValueError("partial trace artifacts require an explicit limitation")
        if not self.allowed_conclusions:
            raise ValueError("trace artifacts require at least one allowed conclusion")
        if not self.forbidden_conclusions:
            raise ValueError("trace artifacts require at least one forbidden conclusion")
        if any(not conclusion.strip() for conclusion in self.allowed_conclusions):
            raise ValueError("allowed conclusions must not be empty")
        if any(not conclusion.strip() for conclusion in self.forbidden_conclusions):
            raise ValueError("forbidden conclusions must not be empty")
        if len(set(self.allowed_conclusions)) != len(self.allowed_conclusions):
            raise ValueError("allowed conclusions must be unique")
        if len(set(self.forbidden_conclusions)) != len(self.forbidden_conclusions):
            raise ValueError("forbidden conclusions must be unique")
        if set(self.allowed_conclusions) & set(self.forbidden_conclusions):
            raise ValueError("allowed and forbidden conclusions must be disjoint")
        return self


class TraceEvidenceArtifact(TraceArtifactBase):
    """Canonical normalized trace events bound to an immutable raw source."""

    trace_evidence_id: ArtifactId
    evidence_fingerprint: Sha256
    normalized_ndjson_sha256: Sha256
    normalized_ndjson_bytes: int = Field(ge=0)
    input_line_count: int = Field(ge=0)
    diagnostic_count: int = Field(ge=0)
    events: tuple[TraceEvent, ...]

    @model_validator(mode="after")
    def validate_evidence_identity_and_order(self) -> TraceEvidenceArtifact:
        if self.input_sha256 != self.source.output_sha256:
            raise ValueError("trace evidence input hash must match the raw output hash")
        if self.input_bytes != self.source.output_bytes:
            raise ValueError("trace evidence input size must match the raw output size")
        if self.input_bytes > self.limits.max_input_bytes:
            raise ValueError("raw trace input exceeds max_input_bytes")
        if len(self.events) != self.quality.emitted_event_count:
            raise ValueError("trace event tuple does not match emitted_event_count")
        if self.input_line_count > self.limits.max_input_lines:
            raise ValueError("trace input line count exceeds max_input_lines")
        if self.input_line_count < self.quality.input_event_count:
            raise ValueError("trace input line count is below input_event_count")
        if self.diagnostic_count > self.limits.max_diagnostics:
            raise ValueError("trace diagnostic count exceeds max_diagnostics")
        if not self.events:
            if self.status != "partial" or self.quality.quality_status != "partial":
                raise ValueError("empty trace evidence must remain partial")
            if self.normalized_ndjson_bytes != 0:
                raise ValueError("empty trace evidence must have empty NDJSON output")
        if self.normalized_ndjson_bytes > self.limits.max_output_bytes:
            raise ValueError("normalized trace output exceeds max_output_bytes")
        if self.events and self.normalized_ndjson_bytes == 0:
            raise ValueError("non-empty trace evidence requires non-empty NDJSON output")
        if self.observation_window.source == "observed_event_bounds":
            if not self.events:
                raise ValueError("observed-event bounds require emitted events")
            if (
                self.events[0].timestamp_ns != self.observation_window.start_timestamp_ns
                or self.events[-1].timestamp_ns != self.observation_window.end_timestamp_ns
            ):
                raise ValueError("observed-event bounds must equal first and last event timestamps")
        previous_sort_key: tuple[int, int, int, str] | None = None
        event_ids: set[str] = set()
        for expected_index, event in enumerate(self.events):
            if not (
                self.observation_window.start_timestamp_ns
                <= event.timestamp_ns
                <= self.observation_window.end_timestamp_ns
            ):
                raise ValueError("trace event lies outside the observation window")
            if self.mode in {"sched", "off_cpu"} and not isinstance(
                event, (SchedSwitchEvent, SchedWakeupEvent, SchedMigrateEvent)
            ):
                raise ValueError("scheduler trace mode contains a lock event")
            if self.mode == "lock" and isinstance(
                event, (SchedSwitchEvent, SchedWakeupEvent, SchedMigrateEvent)
            ):
                raise ValueError("lock trace mode contains a scheduler event")
            if event.target_pid != self.target.target_pid:
                raise ValueError("trace event escaped the authorized target PID")
            if event.target_tid not in self.target.observed_target_tids:
                raise ValueError("trace event escaped the observed target TID set")
            if isinstance(event, SchedWakeupEvent) and (
                event.waker_target_tid is not None
                and event.waker_target_tid not in self.target.observed_target_tids
            ):
                raise ValueError("trace waker escaped the observed target TID set")
            if isinstance(event, LockWaitEvent) and (
                event.owner_target_tid is not None
                and event.owner_target_tid not in self.target.observed_target_tids
            ):
                raise ValueError("trace owner escaped the observed target TID set")
            if event.event_id in event_ids:
                raise ValueError("trace event IDs must be unique")
            if event.event_index != expected_index:
                raise ValueError("trace event indexes must be contiguous from zero")
            sort_key = (
                event.timestamp_ns,
                event.cpu,
                event.source_sequence,
                event.event_id,
            )
            if previous_sort_key is not None and sort_key < previous_sort_key:
                raise ValueError("trace events violate canonical source ordering")
            if (
                isinstance(
                    event,
                    (
                        SchedSwitchEvent,
                        LockWaitEvent,
                        LockWaitEndedEvent,
                        LockReleasedEvent,
                        FutexWaitEvent,
                    ),
                )
                and len(event.call_stack) > self.limits.max_stack_depth
            ):
                raise ValueError("trace event stack exceeds max_stack_depth")
            previous_sort_key = sort_key
            event_ids.add(event.event_id)
        unique_locks = {
            event.lock_id
            for event in self.events
            if isinstance(
                event,
                (
                    LockWaitEvent,
                    LockWaitEndedEvent,
                    LockReleasedEvent,
                    FutexWaitEvent,
                    FutexWakeEvent,
                ),
            )
        }
        if len(unique_locks) > self.limits.max_unique_locks:
            raise ValueError("trace lock identities exceed max_unique_locks")
        return self


class NanosecondDistribution(ContractModel):
    sample_count: int = Field(ge=0)
    total_ns: int = Field(ge=0)
    minimum_ns: int = Field(ge=0)
    mean_ns: int = Field(ge=0)
    p50_ns: int = Field(ge=0)
    p95_ns: int = Field(ge=0)
    p99_ns: int = Field(ge=0)
    maximum_ns: int = Field(ge=0)
    percentiles_stable: bool

    @model_validator(mode="after")
    def validate_distribution(self) -> NanosecondDistribution:
        values = (
            self.minimum_ns,
            self.p50_ns,
            self.p95_ns,
            self.p99_ns,
            self.maximum_ns,
        )
        if tuple(sorted(values)) != values:
            raise ValueError("nanosecond distribution quantiles must be ordered")
        if self.sample_count == 0:
            if self.total_ns != 0 or self.mean_ns != 0 or any(values):
                raise ValueError("empty distributions must contain only zero values")
            if self.percentiles_stable:
                raise ValueError("empty distributions cannot have stable percentiles")
        else:
            expected_mean = self.total_ns // self.sample_count
            if self.mean_ns != expected_mean:
                raise ValueError("distribution mean is inconsistent with total and sample count")
            if self.total_ns < self.minimum_ns * self.sample_count:
                raise ValueError("distribution total is below its minimum bound")
            if self.total_ns > self.maximum_ns * self.sample_count:
                raise ValueError("distribution total exceeds its maximum bound")
            if self.sample_count < 20 and self.percentiles_stable:
                raise ValueError("low-sample distributions must mark percentiles unstable")
        return self


def event_id_ledger_sha256(event_ids: tuple[str, ...]) -> str:
    """Hash an ordered complete event-ID ledger using an unambiguous encoding."""

    digest = hashlib.sha256()
    for event_id in event_ids:
        encoded = event_id.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


class TraceEventIdLedger(ContractModel):
    total_count: int = Field(ge=0)
    sample_event_ids: tuple[EventId, ...] = ()
    all_event_ids_sha256: Sha256
    sample_truncated: bool

    @model_validator(mode="after")
    def validate_ledger(self) -> TraceEventIdLedger:
        if len(set(self.sample_event_ids)) != len(self.sample_event_ids):
            raise ValueError("event accounting samples must be unique")
        if len(self.sample_event_ids) > self.total_count:
            raise ValueError("event accounting sample exceeds total count")
        if self.sample_truncated != (len(self.sample_event_ids) < self.total_count):
            raise ValueError("event accounting truncation flag contradicts its sample")
        if not self.sample_truncated and self.all_event_ids_sha256 != (
            event_id_ledger_sha256(self.sample_event_ids)
        ):
            raise ValueError("complete event accounting ledger hash is inconsistent")
        return self


class TraceAnalysisWarning(ContractModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    event_id: EventId | None = None
    target_tid: int | None = Field(default=None, gt=0)


class TraceEventAccounting(ContractModel):
    observed_event_count: int = Field(ge=0)
    consumed: TraceEventIdLedger
    unpaired: TraceEventIdLedger
    ignored: TraceEventIdLedger
    warning_count: int = Field(ge=0)
    warnings: tuple[TraceAnalysisWarning, ...] = ()
    warnings_truncated: bool

    @model_validator(mode="after")
    def validate_accounting(self) -> TraceEventAccounting:
        categorized = (
            self.consumed.total_count + self.unpaired.total_count + self.ignored.total_count
        )
        if categorized != self.observed_event_count:
            raise ValueError("analysis event accounting is not conserved")
        if self.warning_count < len(self.warnings):
            raise ValueError("analysis warning sample exceeds warning count")
        if self.warnings_truncated != (len(self.warnings) < self.warning_count):
            raise ValueError("analysis warning truncation flag contradicts its sample")
        sampled = (
            self.consumed.sample_event_ids
            + self.unpaired.sample_event_ids
            + self.ignored.sample_event_ids
        )
        if len(set(sampled)) != len(sampled):
            raise ValueError("analysis event accounting categories overlap")
        return self


def _validate_analysis_accounting(
    accounting: TraceEventAccounting,
    *,
    quality: TraceQuality,
    limits: TraceResourceLimits,
    target: TraceTargetIdentity,
) -> None:
    if accounting.observed_event_count != quality.emitted_event_count:
        raise ValueError("analysis accounting must partition every emitted event")
    if accounting.warning_count > limits.max_warnings:
        raise ValueError("analysis warning count exceeds max_warnings")
    if len(accounting.warnings) > limits.max_diagnostics:
        raise ValueError("analysis warning sample exceeds max_diagnostics")
    allowed_tids = set(target.observed_target_tids)
    for warning in accounting.warnings:
        if warning.target_tid is not None and warning.target_tid not in allowed_tids:
            raise ValueError("analysis warning escaped the observed target TID set")


class RunnableLatencyInterval(ContractModel):
    target_tid: int = Field(gt=0)
    wakeup_timestamp_ns: int = Field(ge=0)
    switch_in_timestamp_ns: int = Field(ge=0)
    duration_ns: int = Field(ge=0)
    waker_target_tid: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_interval(self) -> RunnableLatencyInterval:
        if self.switch_in_timestamp_ns < self.wakeup_timestamp_ns:
            raise ValueError("runnable interval ends before it starts")
        if self.duration_ns != self.switch_in_timestamp_ns - self.wakeup_timestamp_ns:
            raise ValueError("runnable interval duration is inconsistent")
        return self


class SchedulerThreadAggregate(ContractModel):
    target_tid: int = Field(gt=0)
    runtime_ns: int = Field(ge=0)
    run_interval_count: int = Field(ge=0)
    context_switch_count: int = Field(ge=0)
    migration_count: int = Field(ge=0)
    runnable_latency: NanosecondDistribution
    worst_runnable_intervals: tuple[RunnableLatencyInterval, ...] = ()

    @model_validator(mode="after")
    def validate_thread_intervals(self) -> SchedulerThreadAggregate:
        if len(self.worst_runnable_intervals) > self.runnable_latency.sample_count:
            raise ValueError("exported worst runnable intervals exceed the sample count")
        if any(item.target_tid != self.target_tid for item in self.worst_runnable_intervals):
            raise ValueError("runnable interval belongs to a different thread")
        return self


class SchedulerAnalysisArtifact(TraceArtifactBase):
    scheduler_analysis_id: ArtifactId
    trace_evidence_id: ArtifactId
    trace_evidence_content_sha256: Sha256
    trace_evidence_content_bytes: int = Field(gt=0)
    analysis_fingerprint: Sha256
    analyzer_version: Literal["scheduler-analyzer-v1"] = "scheduler-analyzer-v1"
    event_accounting: TraceEventAccounting
    threads: tuple[SchedulerThreadAggregate, ...]
    total_runtime_ns: int = Field(ge=0)
    total_run_interval_count: int = Field(ge=0)
    total_runnable_wait_ns: int = Field(ge=0)
    total_runnable_interval_count: int = Field(ge=0)
    total_context_switch_count: int = Field(ge=0)
    total_migration_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_scheduler_aggregates(self) -> SchedulerAnalysisArtifact:
        if self.mode != "sched":
            raise ValueError("scheduler analysis requires mode=sched")
        if self.input_sha256 != self.trace_evidence_content_sha256:
            raise ValueError("scheduler input hash must match trace evidence content hash")
        if self.input_bytes != self.trace_evidence_content_bytes:
            raise ValueError("scheduler input size must match trace evidence content size")
        if self.input_bytes > self.limits.max_output_bytes:
            raise ValueError("scheduler input exceeds max_output_bytes")
        _validate_analysis_accounting(
            self.event_accounting,
            quality=self.quality,
            limits=self.limits,
            target=self.target,
        )
        if len({thread.target_tid for thread in self.threads}) != len(self.threads):
            raise ValueError("scheduler threads must be unique")
        if any(
            thread.target_tid not in self.target.observed_target_tids for thread in self.threads
        ):
            raise ValueError("scheduler thread escaped the observed target TID set")
        for thread in self.threads:
            for interval in thread.worst_runnable_intervals:
                if (
                    interval.waker_target_tid is not None
                    and interval.waker_target_tid not in self.target.observed_target_tids
                ):
                    raise ValueError("scheduler waker escaped the observed target TID set")
        expected = (
            sum(thread.runtime_ns for thread in self.threads),
            sum(thread.run_interval_count for thread in self.threads),
            sum(thread.runnable_latency.total_ns for thread in self.threads),
            sum(thread.runnable_latency.sample_count for thread in self.threads),
            sum(thread.context_switch_count for thread in self.threads),
            sum(thread.migration_count for thread in self.threads),
        )
        actual = (
            self.total_runtime_ns,
            self.total_run_interval_count,
            self.total_runnable_wait_ns,
            self.total_runnable_interval_count,
            self.total_context_switch_count,
            self.total_migration_count,
        )
        if actual != expected:
            raise ValueError("scheduler aggregates are not conserved")
        if sum(len(thread.worst_runnable_intervals) for thread in self.threads) > (
            self.limits.max_exported_intervals
        ):
            raise ValueError("scheduler intervals exceed max_exported_intervals")
        return self


WaitCategory = Literal["disk", "network", "lock", "timer", "sleep", "unknown"]


class OffCpuInterval(ContractModel):
    target_tid: int = Field(gt=0)
    switch_out_timestamp_ns: int | None = Field(default=None, ge=0)
    wakeup_timestamp_ns: int | None = Field(default=None, ge=0)
    switch_in_timestamp_ns: int | None = Field(default=None, ge=0)
    off_cpu_duration_ns: int | None = Field(default=None, ge=0)
    blocked_duration_ns: int | None = Field(default=None, ge=0)
    runnable_duration_ns: int | None = Field(default=None, ge=0)
    unknown_duration_ns: int | None = Field(default=None, ge=0)
    observed_blocked_prefix_ns: int | None = Field(default=None, ge=0)
    observed_runnable_suffix_ns: int | None = Field(default=None, ge=0)
    task_state: str | None = Field(default=None, min_length=1)
    candidate_wait_category: WaitCategory
    waker_target_tid: int | None = Field(default=None, gt=0)
    switch_out_call_stack: tuple[TraceStackFrame, ...] = ()
    total_complete: bool
    split_complete: bool
    incomplete_reason: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_interval(self) -> OffCpuInterval:
        if (
            self.switch_out_timestamp_ns is not None
            and self.wakeup_timestamp_ns is not None
            and self.wakeup_timestamp_ns < self.switch_out_timestamp_ns
        ):
            raise ValueError("off-CPU wakeup precedes switch-out")
        if (
            self.wakeup_timestamp_ns is not None
            and self.switch_in_timestamp_ns is not None
            and self.wakeup_timestamp_ns > self.switch_in_timestamp_ns
        ):
            raise ValueError("off-CPU wakeup follows switch-in")
        if self.total_complete:
            if (
                self.switch_out_timestamp_ns is None
                or self.switch_in_timestamp_ns is None
                or self.off_cpu_duration_ns is None
                or self.unknown_duration_ns is None
            ):
                raise ValueError("total-complete off-CPU intervals require both endpoints")
            if self.switch_in_timestamp_ns < self.switch_out_timestamp_ns:
                raise ValueError("off-CPU interval ends before it starts")
            if self.off_cpu_duration_ns != (
                self.switch_in_timestamp_ns - self.switch_out_timestamp_ns
            ):
                raise ValueError("off-CPU interval duration is inconsistent")
            if self.split_complete and self.incomplete_reason is not None:
                raise ValueError("split-complete intervals cannot carry an incomplete reason")
            if not self.split_complete and self.incomplete_reason is None:
                raise ValueError("unsplit complete intervals require an incomplete reason")
        elif any(
            value is not None
            for value in (
                self.off_cpu_duration_ns,
                self.blocked_duration_ns,
                self.runnable_duration_ns,
                self.unknown_duration_ns,
            )
        ):
            raise ValueError("total-incomplete off-CPU intervals cannot contain final durations")
        if (
            not self.total_complete
            and self.switch_out_timestamp_ns is not None
            and self.switch_in_timestamp_ns is not None
        ):
            raise ValueError("off-CPU intervals with both endpoints must be total-complete")
        if not self.total_complete and self.incomplete_reason is None:
            raise ValueError("total-incomplete off-CPU intervals require a reason")

        if self.split_complete:
            if not self.total_complete:
                raise ValueError("split-complete off-CPU intervals must also be total-complete")
            if (
                self.wakeup_timestamp_ns is None
                or self.blocked_duration_ns is None
                or self.runnable_duration_ns is None
                or self.unknown_duration_ns != 0
            ):
                raise ValueError(
                    "split-complete intervals require exact blocked/runnable durations"
                )
            assert self.switch_out_timestamp_ns is not None
            assert self.switch_in_timestamp_ns is not None
            if not (
                self.switch_out_timestamp_ns
                <= self.wakeup_timestamp_ns
                <= self.switch_in_timestamp_ns
            ):
                raise ValueError("off-CPU wakeup is outside the interval")
            blocked = self.wakeup_timestamp_ns - self.switch_out_timestamp_ns
            runnable = self.switch_in_timestamp_ns - self.wakeup_timestamp_ns
            if self.blocked_duration_ns != blocked or self.runnable_duration_ns != runnable:
                raise ValueError("off-CPU blocked/runnable durations are inconsistent")
        else:
            if self.blocked_duration_ns is not None or self.runnable_duration_ns is not None:
                raise ValueError("non-split intervals cannot claim blocked/runnable durations")
            if self.total_complete and self.unknown_duration_ns != self.off_cpu_duration_ns:
                raise ValueError("unsplit complete intervals must classify all time as unknown")

        if self.total_complete:
            assert self.off_cpu_duration_ns is not None
            assert self.unknown_duration_ns is not None
            blocked = self.blocked_duration_ns or 0
            runnable = self.runnable_duration_ns or 0
            if self.off_cpu_duration_ns != blocked + runnable + self.unknown_duration_ns:
                raise ValueError("off-CPU duration components are not conserved")

        if self.observed_blocked_prefix_ns is not None:
            if self.total_complete:
                raise ValueError("complete intervals cannot claim a boundary prefix")
            if self.switch_out_timestamp_ns is None or self.wakeup_timestamp_ns is None:
                raise ValueError("observed blocked prefix requires switch-out and wakeup")
            if self.observed_blocked_prefix_ns != (
                self.wakeup_timestamp_ns - self.switch_out_timestamp_ns
            ):
                raise ValueError("observed blocked prefix is inconsistent")
        if self.observed_runnable_suffix_ns is not None:
            if self.total_complete:
                raise ValueError("complete intervals cannot claim a boundary suffix")
            if self.wakeup_timestamp_ns is None or self.switch_in_timestamp_ns is None:
                raise ValueError("observed runnable suffix requires wakeup and switch-in")
            if self.observed_runnable_suffix_ns != (
                self.switch_in_timestamp_ns - self.wakeup_timestamp_ns
            ):
                raise ValueError("observed runnable suffix is inconsistent")
        return self


class WaitCategoryCount(ContractModel):
    category: WaitCategory
    interval_count: int = Field(ge=0)


class OffCpuThreadAggregate(ContractModel):
    target_tid: int = Field(gt=0)
    off_cpu_duration: NanosecondDistribution
    blocked_duration: NanosecondDistribution
    runnable_duration: NanosecondDistribution
    unknown_duration: NanosecondDistribution
    total_complete_interval_count: int = Field(ge=0)
    split_complete_interval_count: int = Field(ge=0)
    total_incomplete_interval_count: int = Field(ge=0)
    candidate_categories: tuple[WaitCategoryCount, ...]
    worst_intervals: tuple[OffCpuInterval, ...] = ()

    @model_validator(mode="after")
    def validate_thread_aggregate(self) -> OffCpuThreadAggregate:
        if self.total_complete_interval_count != self.off_cpu_duration.sample_count:
            raise ValueError("off-CPU total-complete interval count is inconsistent")
        if self.split_complete_interval_count != self.blocked_duration.sample_count:
            raise ValueError("off-CPU split-complete interval count is inconsistent")
        if self.split_complete_interval_count != self.runnable_duration.sample_count:
            raise ValueError("off-CPU runnable split count is inconsistent")
        if self.unknown_duration.sample_count != (
            self.total_complete_interval_count - self.split_complete_interval_count
        ):
            raise ValueError("off-CPU unknown duration count is inconsistent")
        if self.off_cpu_duration.total_ns != (
            self.blocked_duration.total_ns
            + self.runnable_duration.total_ns
            + self.unknown_duration.total_ns
        ):
            raise ValueError("off-CPU thread duration components are not conserved")
        if len({item.category for item in self.candidate_categories}) != len(
            self.candidate_categories
        ):
            raise ValueError("off-CPU candidate categories must be unique")
        if sum(item.interval_count for item in self.candidate_categories) != (
            self.total_complete_interval_count
        ):
            raise ValueError("off-CPU candidate category counts are not conserved")
        if len(self.worst_intervals) > (
            self.total_complete_interval_count + self.total_incomplete_interval_count
        ):
            raise ValueError("exported off-CPU intervals exceed the interval count")
        if any(item.target_tid != self.target_tid for item in self.worst_intervals):
            raise ValueError("off-CPU interval belongs to a different thread")
        return self


class OffCpuAnalysisArtifact(TraceArtifactBase):
    off_cpu_analysis_id: ArtifactId
    trace_evidence_id: ArtifactId
    trace_evidence_content_sha256: Sha256
    trace_evidence_content_bytes: int = Field(gt=0)
    analysis_fingerprint: Sha256
    analyzer_version: Literal["off-cpu-analyzer-v1"] = "off-cpu-analyzer-v1"
    event_accounting: TraceEventAccounting
    threads: tuple[OffCpuThreadAggregate, ...]
    total_off_cpu_ns: int = Field(ge=0)
    total_blocked_ns: int = Field(ge=0)
    total_runnable_ns: int = Field(ge=0)
    total_unknown_ns: int = Field(ge=0)
    total_complete_interval_count: int = Field(ge=0)
    split_complete_interval_count: int = Field(ge=0)
    total_incomplete_interval_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_off_cpu_aggregates(self) -> OffCpuAnalysisArtifact:
        if self.mode != "off_cpu":
            raise ValueError("off-CPU analysis requires mode=off_cpu")
        if self.input_sha256 != self.trace_evidence_content_sha256:
            raise ValueError("off-CPU input hash must match trace evidence content hash")
        if self.input_bytes != self.trace_evidence_content_bytes:
            raise ValueError("off-CPU input size must match trace evidence content size")
        if self.input_bytes > self.limits.max_output_bytes:
            raise ValueError("off-CPU input exceeds max_output_bytes")
        _validate_analysis_accounting(
            self.event_accounting,
            quality=self.quality,
            limits=self.limits,
            target=self.target,
        )
        if len({thread.target_tid for thread in self.threads}) != len(self.threads):
            raise ValueError("off-CPU threads must be unique")
        if any(
            thread.target_tid not in self.target.observed_target_tids for thread in self.threads
        ):
            raise ValueError("off-CPU thread escaped the observed target TID set")
        for thread in self.threads:
            for interval in thread.worst_intervals:
                if (
                    interval.waker_target_tid is not None
                    and interval.waker_target_tid not in self.target.observed_target_tids
                ):
                    raise ValueError("off-CPU waker escaped the observed target TID set")
        expected = (
            sum(thread.off_cpu_duration.total_ns for thread in self.threads),
            sum(thread.blocked_duration.total_ns for thread in self.threads),
            sum(thread.runnable_duration.total_ns for thread in self.threads),
            sum(thread.unknown_duration.total_ns for thread in self.threads),
            sum(thread.total_complete_interval_count for thread in self.threads),
            sum(thread.split_complete_interval_count for thread in self.threads),
            sum(thread.total_incomplete_interval_count for thread in self.threads),
        )
        actual = (
            self.total_off_cpu_ns,
            self.total_blocked_ns,
            self.total_runnable_ns,
            self.total_unknown_ns,
            self.total_complete_interval_count,
            self.split_complete_interval_count,
            self.total_incomplete_interval_count,
        )
        if actual != expected:
            raise ValueError("off-CPU aggregates are not conserved")
        if self.total_off_cpu_ns != (
            self.total_blocked_ns + self.total_runnable_ns + self.total_unknown_ns
        ):
            raise ValueError("off-CPU artifact duration components are not conserved")
        if sum(len(thread.worst_intervals) for thread in self.threads) > (
            self.limits.max_exported_intervals
        ):
            raise ValueError("off-CPU intervals exceed max_exported_intervals")
        return self


class TraceCallPathAggregate(ContractModel):
    frames: tuple[TraceStackFrame, ...] = Field(min_length=1)
    occurrence_count: int = Field(gt=0)


class LockWaitInterval(ContractModel):
    lock_id: LockId
    lock_kind: Literal["kernel_lock", "futex_candidate", "unknown"]
    waiter_tid: int = Field(gt=0)
    owner_target_tid: int | None = Field(default=None, gt=0)
    wait_begin_timestamp_ns: int = Field(ge=0)
    wait_end_timestamp_ns: int = Field(ge=0)
    wait_duration_ns: int = Field(ge=0)
    outcome: Literal["acquired", "timed_out", "interrupted", "failed", "unknown"]
    call_stack: tuple[TraceStackFrame, ...] = ()

    @model_validator(mode="after")
    def validate_interval(self) -> LockWaitInterval:
        if self.wait_end_timestamp_ns < self.wait_begin_timestamp_ns:
            raise ValueError("lock wait interval ends before it starts")
        if self.wait_duration_ns != self.wait_end_timestamp_ns - self.wait_begin_timestamp_ns:
            raise ValueError("lock wait interval duration is inconsistent")
        return self


class LockWaitOutcomeCount(ContractModel):
    outcome: Literal["acquired", "timed_out", "interrupted", "failed", "unknown"]
    interval_count: int = Field(ge=0)


class LockHoldInterval(ContractModel):
    lock_id: LockId
    holder_tid: int = Field(gt=0)
    acquire_timestamp_ns: int = Field(ge=0)
    release_timestamp_ns: int = Field(ge=0)
    hold_duration_ns: int = Field(ge=0)
    call_stack: tuple[TraceStackFrame, ...] = ()

    @model_validator(mode="after")
    def validate_interval(self) -> LockHoldInterval:
        if self.release_timestamp_ns < self.acquire_timestamp_ns:
            raise ValueError("lock hold interval ends before it starts")
        if self.hold_duration_ns != self.release_timestamp_ns - self.acquire_timestamp_ns:
            raise ValueError("lock hold interval duration is inconsistent")
        return self


class LockProjectionAggregate(ContractModel):
    projection_type: Literal["thread", "call_path"]
    target_tid: int | None = Field(default=None, gt=0)
    call_path: tuple[TraceStackFrame, ...] = ()
    path_resolved: bool
    exact_wait_duration: NanosecondDistribution
    exact_hold_duration: NanosecondDistribution
    candidate_wait_event_count: int = Field(ge=0)
    candidate_wake_event_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_projection(self) -> LockProjectionAggregate:
        if self.projection_type == "thread":
            if self.target_tid is None or self.call_path:
                raise ValueError("thread lock projection requires only target_tid")
        elif self.target_tid is not None:
            raise ValueError("call-path lock projection cannot carry target_tid")
        if self.path_resolved != bool(self.call_path):
            raise ValueError("lock call-path resolution flag is inconsistent")
        return self


class LockAggregate(ContractModel):
    lock_id: LockId
    lock_kind: Literal["kernel_lock", "futex_candidate", "unknown"]
    exact_wait_count: int = Field(ge=0)
    waiter_thread_count: int = Field(ge=0)
    owner_observed_count: int = Field(ge=0)
    exact_wait_duration: NanosecondDistribution
    exact_wait_outcomes: tuple[LockWaitOutcomeCount, ...]
    exact_hold_count: int = Field(ge=0)
    exact_hold_duration: NanosecondDistribution
    candidate_wait_event_count: int = Field(ge=0)
    candidate_wake_event_count: int = Field(ge=0)
    worst_waits: tuple[LockWaitInterval, ...] = ()
    worst_holds: tuple[LockHoldInterval, ...] = ()
    call_paths: tuple[TraceCallPathAggregate, ...] = ()

    @model_validator(mode="after")
    def validate_lock_semantics(self) -> LockAggregate:
        if self.exact_wait_count != self.exact_wait_duration.sample_count:
            raise ValueError("exact lock wait count must match the wait sample count")
        if len({row.outcome for row in self.exact_wait_outcomes}) != len(self.exact_wait_outcomes):
            raise ValueError("lock wait outcomes must be unique")
        if sum(row.interval_count for row in self.exact_wait_outcomes) != (self.exact_wait_count):
            raise ValueError("lock wait outcomes are not conserved")
        if self.exact_hold_count != self.exact_hold_duration.sample_count:
            raise ValueError("exact lock hold count must match the hold sample count")
        if self.owner_observed_count > self.exact_wait_count:
            raise ValueError("lock owner observations exceed contentions")
        if self.waiter_thread_count > self.exact_wait_count:
            raise ValueError("lock waiter count exceeds contentions")
        if len(self.worst_waits) > self.exact_wait_count:
            raise ValueError("exported worst lock waits exceed contentions")
        if len(self.worst_holds) > self.exact_hold_count:
            raise ValueError("exported worst lock holds exceed hold pairs")
        if any(item.lock_id != self.lock_id for item in self.worst_waits):
            raise ValueError("lock wait interval belongs to a different lock")
        if any(item.lock_id != self.lock_id for item in self.worst_holds):
            raise ValueError("lock hold interval belongs to a different lock")
        if self.lock_kind == "futex_candidate" and (self.exact_wait_count or self.exact_hold_count):
            raise ValueError("futex evidence cannot claim exact high-level lock intervals")
        return self


class LockAnalysisArtifact(TraceArtifactBase):
    lock_analysis_id: ArtifactId
    trace_evidence_id: ArtifactId
    trace_evidence_content_sha256: Sha256
    trace_evidence_content_bytes: int = Field(gt=0)
    analysis_fingerprint: Sha256
    analyzer_version: Literal["lock-analyzer-v1"] = "lock-analyzer-v1"
    event_accounting: TraceEventAccounting
    locks: tuple[LockAggregate, ...]
    thread_projections: tuple[LockProjectionAggregate, ...]
    call_path_projections: tuple[LockProjectionAggregate, ...]
    total_exact_wait_count: int = Field(ge=0)
    total_exact_wait_ns: int = Field(ge=0)
    total_exact_hold_count: int = Field(ge=0)
    total_exact_hold_ns: int = Field(ge=0)
    total_candidate_wait_event_count: int = Field(ge=0)
    total_candidate_wake_event_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_lock_aggregates(self) -> LockAnalysisArtifact:
        if self.mode != "lock":
            raise ValueError("lock analysis requires mode=lock")
        if self.input_sha256 != self.trace_evidence_content_sha256:
            raise ValueError("lock input hash must match trace evidence content hash")
        if self.input_bytes != self.trace_evidence_content_bytes:
            raise ValueError("lock input size must match trace evidence content size")
        if self.input_bytes > self.limits.max_output_bytes:
            raise ValueError("lock input exceeds max_output_bytes")
        _validate_analysis_accounting(
            self.event_accounting,
            quality=self.quality,
            limits=self.limits,
            target=self.target,
        )
        if len({lock.lock_id for lock in self.locks}) != len(self.locks):
            raise ValueError("anonymous lock IDs must be unique within an artifact")
        for lock in self.locks:
            for interval in lock.worst_waits:
                if interval.waiter_tid not in self.target.observed_target_tids:
                    raise ValueError("lock waiter escaped the observed target TID set")
                if (
                    interval.owner_target_tid is not None
                    and interval.owner_target_tid not in self.target.observed_target_tids
                ):
                    raise ValueError("lock owner escaped the observed target TID set")
        expected = (
            sum(lock.exact_wait_count for lock in self.locks),
            sum(lock.exact_wait_duration.total_ns for lock in self.locks),
            sum(lock.exact_hold_count for lock in self.locks),
            sum(lock.exact_hold_duration.total_ns for lock in self.locks),
            sum(lock.candidate_wait_event_count for lock in self.locks),
            sum(lock.candidate_wake_event_count for lock in self.locks),
        )
        actual = (
            self.total_exact_wait_count,
            self.total_exact_wait_ns,
            self.total_exact_hold_count,
            self.total_exact_hold_ns,
            self.total_candidate_wait_event_count,
            self.total_candidate_wake_event_count,
        )
        if actual != expected:
            raise ValueError("lock aggregates are not conserved")
        if (
            sum(len(lock.worst_waits) + len(lock.worst_holds) for lock in self.locks)
            > self.limits.max_exported_intervals
        ):
            raise ValueError("lock intervals exceed max_exported_intervals")
        for row in self.thread_projections:
            if row.projection_type != "thread" or row.target_tid not in (
                self.target.observed_target_tids
            ):
                raise ValueError("lock thread projection escaped target scope")
        thread_ids = tuple(row.target_tid for row in self.thread_projections)
        if len(set(thread_ids)) != len(thread_ids):
            raise ValueError("lock thread projections must be unique")
        if any(row.projection_type != "call_path" for row in self.call_path_projections):
            raise ValueError("lock call-path projection has the wrong projection type")
        path_keys = tuple(
            tuple(
                (
                    frame.ip,
                    frame.symbol,
                    frame.dso,
                    frame.source_file,
                    frame.source_line,
                    frame.is_kernel,
                )
                for frame in row.call_path
            )
            for row in self.call_path_projections
        )
        if len(set(path_keys)) != len(path_keys):
            raise ValueError("lock call-path projections must be unique")
        for attr in (
            "exact_wait_duration",
            "exact_hold_duration",
        ):
            lock_total = sum(getattr(lock, attr).total_ns for lock in self.locks)
            thread_total = sum(getattr(row, attr).total_ns for row in self.thread_projections)
            path_total = sum(getattr(row, attr).total_ns for row in self.call_path_projections)
            if thread_total != lock_total or path_total != lock_total:
                raise ValueError("lock projection durations are not conserved")
            lock_count = sum(getattr(lock, attr).sample_count for lock in self.locks)
            thread_count = sum(getattr(row, attr).sample_count for row in self.thread_projections)
            path_count = sum(getattr(row, attr).sample_count for row in self.call_path_projections)
            if thread_count != lock_count or path_count != lock_count:
                raise ValueError("lock projection interval counts are not conserved")
        for attr in ("candidate_wait_event_count", "candidate_wake_event_count"):
            lock_total = sum(getattr(lock, attr) for lock in self.locks)
            thread_total = sum(getattr(row, attr) for row in self.thread_projections)
            path_total = sum(getattr(row, attr) for row in self.call_path_projections)
            if thread_total != lock_total or path_total != lock_total:
                raise ValueError("lock projection candidate counts are not conserved")
        return self


TraceVerificationCheckName = Literal[
    "raw_evidence_identity",
    "conversion_manifest",
    "target_scope",
    "event_count_conservation",
    "time_interval_conservation",
    "analysis_aggregate_conservation",
    "loss_truncation_consistency",
    "agent_visible_content_sha256",
]


class TraceVerificationCheck(ContractModel):
    """Trace-only check status; the existing profile VerificationCheck is unchanged."""

    name: TraceVerificationCheckName
    status: Literal["passed", "failed", "skipped"]
    detail: str = Field(min_length=1)


class TraceAnalysisVerificationArtifact(TraceArtifactBase):
    verification_id: ArtifactId
    verification_fingerprint: Sha256
    verifier_version: Literal["trace-verifier-v1"] = "trace-verifier-v1"
    analysis_artifact_type: Literal[
        "SchedulerAnalysisArtifact",
        "OffCpuAnalysisArtifact",
        "LockAnalysisArtifact",
    ]
    analysis_id: ArtifactId
    analysis_content_sha256: Sha256
    analysis_content_bytes: int = Field(gt=0)
    agent_visible_content_sha256: Sha256
    verification_status: Literal["verified", "partial", "failed"]
    checks: tuple[TraceVerificationCheck, ...]
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_verification_checks(self) -> TraceAnalysisVerificationArtifact:
        required_names = {
            "raw_evidence_identity",
            "conversion_manifest",
            "target_scope",
            "event_count_conservation",
            "time_interval_conservation",
            "analysis_aggregate_conservation",
            "loss_truncation_consistency",
            "agent_visible_content_sha256",
        }
        names = [check.name for check in self.checks]
        if len(names) != len(set(names)) or set(names) != required_names:
            raise ValueError("trace verification requires each fixed check exactly once")
        statuses = {check.status for check in self.checks}
        expected_status: Literal["verified", "partial", "failed"]
        if "failed" in statuses:
            expected_status = "failed"
        elif "skipped" in statuses:
            expected_status = "partial"
        else:
            expected_status = "verified"
        if self.verification_status != expected_status:
            raise ValueError("trace verification status contradicts its check statuses")
        # Verification completeness and evidence completeness are independent dimensions.
        # All integrity checks may pass for an Analysis that truthfully remains partial because
        # its trace had loss, boundary intervals, diagnostics, or conservative semantics.
        if self.verification_status != "verified" and self.status != "partial":
            raise ValueError("partial or failed verification must be a partial artifact")
        if self.input_sha256 != self.analysis_content_sha256:
            raise ValueError("verification input hash must match the analysis content hash")
        if self.input_bytes != self.analysis_content_bytes:
            raise ValueError("verification input size must match the analysis content size")
        if self.input_bytes > self.limits.max_output_bytes:
            raise ValueError("verification input exceeds max_output_bytes")
        expected_mode = {
            "SchedulerAnalysisArtifact": "sched",
            "OffCpuAnalysisArtifact": "off_cpu",
            "LockAnalysisArtifact": "lock",
        }[self.analysis_artifact_type]
        if self.mode != expected_mode:
            raise ValueError("verification mode contradicts the analysis artifact type")
        return self
