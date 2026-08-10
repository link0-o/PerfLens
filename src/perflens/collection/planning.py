"""Deterministic planning for policy-bounded automatic PID collection."""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from perflens.collection.collector import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_RECORD_EVENT,
    HARDWARE_STAT_EVENTS,
    SOFTWARE_RECORD_EVENT,
    SOFTWARE_STAT_EVENTS,
    CallGraphMode,
    CollectionMode,
)
from perflens.contracts.artifacts import CollectionCapabilityArtifact, CollectionPlanArtifact
from perflens.domain.errors import ErrorCode, PerfLensError


@dataclass(frozen=True, slots=True)
class AutomaticCollectionPolicy:
    """Server-side categorical grant; the broker applies an independent policy too."""

    enabled: bool = False
    allowed_modes: tuple[CollectionMode, ...] = ("record", "stat")
    allow_other_uids: bool = False
    max_duration_seconds: float = 30.0
    max_frequency_hz: int = 99
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    plan_ttl_seconds: int = 120
    allow_software_fallback: bool = True


@dataclass(frozen=True, slots=True)
class CollectionPlanRequest:
    mode: CollectionMode
    pid: int
    duration_seconds: float = 10.0
    frequency_hz: int = 99
    call_graph: CallGraphMode = "dwarf"
    events: tuple[str, ...] = HARDWARE_STAT_EVENTS
    event_source: Literal["auto", "hardware_required", "software_only"] = "auto"
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


def create_collection_plan(
    request: CollectionPlanRequest,
    *,
    policy: AutomaticCollectionPolicy,
    capabilities: CollectionCapabilityArtifact,
    now: datetime | None = None,
) -> CollectionPlanArtifact:
    """Bind an automatic request to a specific PID incarnation and policy snapshot."""
    _validate_policy(policy)
    _validate_request(request)
    target_uid, start_time_ticks = inspect_pid_identity(request.pid)
    warnings: list[str] = []
    allowed = policy.enabled
    if request.mode not in policy.allowed_modes:
        allowed = False
        warnings.append(f"Mode {request.mode} is outside the MCP automatic-collection policy.")
    if target_uid != os.geteuid() and not policy.allow_other_uids:
        allowed = False
        warnings.append("The target PID is owned by a different user.")
    if request.duration_seconds > policy.max_duration_seconds:
        allowed = False
        warnings.append("The requested duration exceeds the MCP policy limit.")
    if request.frequency_hz > policy.max_frequency_hz:
        allowed = False
        warnings.append("The requested sampling frequency exceeds the MCP policy limit.")
    if request.max_output_bytes > policy.max_output_bytes:
        allowed = False
        warnings.append("The requested output size exceeds the MCP policy limit.")
    if not policy.enabled:
        warnings.append("Automatic collection is disabled by MCP server policy.")
    if request.event_source == "auto" and not policy.allow_software_fallback:
        warnings.append("Software fallback is disabled by MCP server policy.")

    mode_capability = next(item for item in capabilities.modes if item.mode == request.mode)
    if mode_capability.status == "blocked":
        warnings.append(
            "The MCP process cannot collect this mode locally; the configured broker must provide "
            "the required privilege."
        )
    created = now or datetime.now(tz=UTC)
    expires_at = created + timedelta(seconds=policy.plan_ttl_seconds)
    event_source = (
        request.event_source if request.mode in {"record", "stat"} else "hardware_required"
    )
    fallback_allowed = event_source == "auto" and policy.allow_software_fallback
    if request.mode == "stat":
        events = SOFTWARE_STAT_EVENTS if event_source == "software_only" else request.events
        fallback_events = SOFTWARE_STAT_EVENTS if fallback_allowed else ()
        record_event = None
        fallback_record_event = None
    elif request.mode == "record":
        events = ()
        fallback_events = ()
        record_event = (
            SOFTWARE_RECORD_EVENT
            if event_source == "software_only"
            else DEFAULT_RECORD_EVENT
        )
        fallback_record_event = SOFTWARE_RECORD_EVENT if fallback_allowed else None
    else:
        events = ()
        fallback_events = ()
        record_event = None
        fallback_record_event = None
    frequency = request.frequency_hz if request.mode in {"record", "off_cpu"} else None
    call_graph = request.call_graph if request.mode in {"record", "off_cpu"} else None
    identity = "\0".join(
        (
            request.mode,
            str(request.pid),
            str(target_uid),
            str(start_time_ticks),
            str(request.duration_seconds),
            str(frequency),
            str(call_graph),
            ",".join(events),
            event_source,
            str(fallback_allowed),
            ",".join(fallback_events),
            str(record_event),
            str(fallback_record_event),
            str(request.max_output_bytes),
            created.isoformat(),
        )
    )
    return CollectionPlanArtifact(
        plan_id=f"plan-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
        mode=request.mode,
        target_type="pid",
        target_pid=request.pid,
        target_uid=target_uid,
        target_start_time_ticks=start_time_ticks,
        backend="privileged_broker",
        duration_seconds=request.duration_seconds,
        frequency_hz=frequency,
        call_graph=call_graph,
        events=events,
        requested_event_source=event_source,
        fallback_allowed=fallback_allowed,
        fallback_events=fallback_events,
        record_event=record_event,
        fallback_record_event=fallback_record_event,
        max_output_bytes=request.max_output_bytes,
        expires_at=expires_at.isoformat(),
        policy_status="allowed" if allowed else "denied",
        required_privilege=mode_capability.required_privilege,
        warnings=tuple(warnings),
    )


def inspect_pid_identity(pid: int) -> tuple[int, int]:
    if pid <= 0 or pid == os.getpid():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Target PID must be positive and must not be the planning process",
        )
    proc = Path("/proc") / str(pid)
    try:
        owner_uid = proc.stat().st_uid
        text = (proc / "stat").read_text(encoding="ascii", errors="strict")
        closing = text.rfind(")")
        if closing < 0:
            raise ValueError("missing process name terminator")
        fields_after_name = text[closing + 2 :].split()
        start_time_ticks = int(fields_after_name[19])
    except (OSError, ValueError, IndexError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Target PID does not exist or its identity cannot be verified",
            recoverable=True,
            details={"pid": pid},
        ) from exc
    if start_time_ticks <= 0:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Target PID has an invalid start time",
            details={"pid": pid},
        )
    return owner_uid, start_time_ticks


def assert_plan_current(plan: CollectionPlanArtifact, *, now: datetime | None = None) -> None:
    if plan.policy_status != "allowed":
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Collection plan was denied by MCP server policy",
            recoverable=True,
            details={"plan_id": plan.plan_id},
        )
    current = now or datetime.now(tz=UTC)
    try:
        expires_at = datetime.fromisoformat(plan.expires_at)
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection plan has an invalid expiration timestamp",
            details={"plan_id": plan.plan_id},
        ) from exc
    if expires_at.tzinfo is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection plan expiration timestamp must include a timezone",
            details={"plan_id": plan.plan_id},
        )
    if current >= expires_at:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Collection plan has expired",
            recoverable=True,
            details={"plan_id": plan.plan_id},
        )
    target_uid, start_time_ticks = inspect_pid_identity(plan.target_pid)
    if target_uid != plan.target_uid or start_time_ticks != plan.target_start_time_ticks:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Target PID identity changed after the collection plan was created",
            recoverable=True,
            details={"plan_id": plan.plan_id, "pid": plan.target_pid},
        )


def _validate_policy(policy: AutomaticCollectionPolicy) -> None:
    if (
        policy.max_duration_seconds <= 0
        or policy.max_duration_seconds > 86_400
        or policy.max_frequency_hz < 1
        or policy.max_frequency_hz > 10_000
        or policy.max_output_bytes < 1
        or policy.plan_ttl_seconds < 1
        or policy.plan_ttl_seconds > 3600
        or type(policy.allow_software_fallback) is not bool
    ):
        raise ValueError("Automatic collection policy limits are invalid")


def _validate_request(request: CollectionPlanRequest) -> None:
    if not math.isfinite(request.duration_seconds) or not 0 < request.duration_seconds <= 86_400:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection duration must be finite, positive, and at most one day",
        )
    if request.frequency_hz < 1 or request.frequency_hz > 10_000:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Sampling frequency must be between 1 and 10000",
        )
    if request.max_output_bytes < 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection output limit must be positive",
        )
    if request.event_source not in {"auto", "hardware_required", "software_only"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection event source preference is unsupported",
        )
    if request.mode == "stat":
        if not request.events or len(request.events) > 64:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection_plan",
                "perf stat requires between 1 and 64 events",
            )
        if any(
            not event or len(event) > 128 or any(character in event for character in "\0\n\r,;")
            for event in request.events
        ):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection_plan",
                "perf stat event contains unsupported characters",
            )
        if request.event_source != "software_only" and any(
            event not in HARDWARE_STAT_EVENTS for event in request.events
        ):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection_plan",
                "Automatic hardware stat plans accept only fixed hardware events",
            )
