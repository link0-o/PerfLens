"""Root-owned policy for the optional collector broker."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from perflens.collection.collector import DEFAULT_STAT_EVENTS, CollectionMode
from perflens.domain.errors import ErrorCode, PerfLensError


@dataclass(frozen=True, slots=True)
class CollectorBrokerPolicy:
    spool_root: Path
    perf_path: Path
    allowed_uids: tuple[int, ...]
    allowed_modes: tuple[CollectionMode, ...] = ("record", "stat")
    allow_other_target_uids: bool = False
    max_duration_seconds: float = 30.0
    max_frequency_hz: int = 99
    max_output_bytes: int = 1 << 30
    max_plan_ttl_seconds: int = 300
    allowed_stat_events: tuple[str, ...] = DEFAULT_STAT_EVENTS
    socket_mode: int = 0o660
    artifact_mode: int = 0o640


def load_broker_policy(path: Path) -> CollectorBrokerPolicy:
    """Load a non-writable, explicitly selected broker policy file."""
    safe_path = _trusted_policy_file(path)
    try:
        with safe_path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            "Collector policy is unreadable or invalid TOML",
            details={"path": str(safe_path)},
        ) from exc
    section = payload.get("collector")
    if not isinstance(section, dict):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            "Collector policy requires a [collector] table",
        )
    return _parse_policy(cast(dict[str, Any], section))


def validate_broker_policy(policy: CollectorBrokerPolicy) -> CollectorBrokerPolicy:
    spool_root = _secure_spool_root(policy.spool_root)
    perf_path = _executable(policy.perf_path)
    supported_modes = {"record", "stat", "sched", "lock", "off_cpu"}
    if not policy.allowed_uids or any(uid < 0 for uid in policy.allowed_uids):
        raise ValueError("Collector policy requires at least one non-negative allowed UID")
    if not policy.allowed_modes or any(
        mode not in supported_modes for mode in policy.allowed_modes
    ):
        raise ValueError("Collector policy contains an unsupported or empty mode set")
    if (
        policy.max_duration_seconds <= 0
        or policy.max_duration_seconds > 86_400
        or policy.max_frequency_hz < 1
        or policy.max_frequency_hz > 10_000
        or policy.max_output_bytes < 1
        or policy.max_plan_ttl_seconds < 1
        or policy.max_plan_ttl_seconds > 3600
    ):
        raise ValueError("Collector policy limits are invalid")
    if not policy.allowed_stat_events or len(policy.allowed_stat_events) > 64:
        raise ValueError("Collector policy requires between 1 and 64 stat events")
    if (
        policy.socket_mode < 0
        or policy.socket_mode > 0o660
        or policy.socket_mode & 0o007
        or policy.socket_mode & 0o600 != 0o600
    ):
        raise ValueError("Collector socket mode must not grant access to other users")
    if (
        policy.artifact_mode < 0
        or policy.artifact_mode > 0o640
        or policy.artifact_mode & 0o007
        or policy.artifact_mode & 0o400 != 0o400
    ):
        raise ValueError(
            "Collector artifact mode must be owner-readable and inaccessible to others"
        )
    return CollectorBrokerPolicy(
        spool_root=spool_root,
        perf_path=perf_path,
        allowed_uids=tuple(sorted(set(policy.allowed_uids))),
        allowed_modes=tuple(dict.fromkeys(policy.allowed_modes)),
        allow_other_target_uids=policy.allow_other_target_uids,
        max_duration_seconds=policy.max_duration_seconds,
        max_frequency_hz=policy.max_frequency_hz,
        max_output_bytes=policy.max_output_bytes,
        max_plan_ttl_seconds=policy.max_plan_ttl_seconds,
        allowed_stat_events=tuple(dict.fromkeys(policy.allowed_stat_events)),
        socket_mode=policy.socket_mode,
        artifact_mode=policy.artifact_mode,
    )


def _parse_policy(section: dict[str, Any]) -> CollectorBrokerPolicy:
    allowed_keys = {
        "spool_root",
        "perf_path",
        "allowed_uids",
        "allowed_modes",
        "allow_other_target_uids",
        "max_duration_seconds",
        "max_frequency_hz",
        "max_output_bytes",
        "max_plan_ttl_seconds",
        "allowed_stat_events",
        "socket_mode",
        "artifact_mode",
    }
    extras = sorted(set(section) - allowed_keys)
    if extras:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            "Collector policy contains unknown fields",
            details={"fields": extras},
        )
    try:
        raw_modes = tuple(section.get("allowed_modes", ["record", "stat"]))
        raw_events = tuple(section.get("allowed_stat_events", DEFAULT_STAT_EVENTS))
        socket_mode_raw = section.get("socket_mode", "0660")
        artifact_mode_raw = section.get("artifact_mode", "0640")
        socket_mode = (
            int(socket_mode_raw, 8) if isinstance(socket_mode_raw, str) else int(socket_mode_raw)
        )
        artifact_mode = (
            int(artifact_mode_raw, 8)
            if isinstance(artifact_mode_raw, str)
            else int(artifact_mode_raw)
        )
        allow_other = section.get("allow_other_target_uids", False)
        if not isinstance(allow_other, bool):
            raise TypeError("allow_other_target_uids must be boolean")
        policy = CollectorBrokerPolicy(
            spool_root=Path(str(section["spool_root"])),
            perf_path=Path(str(section["perf_path"])),
            allowed_uids=tuple(int(uid) for uid in section["allowed_uids"]),
            allowed_modes=cast(tuple[CollectionMode, ...], raw_modes),
            allow_other_target_uids=allow_other,
            max_duration_seconds=float(section.get("max_duration_seconds", 30.0)),
            max_frequency_hz=int(section.get("max_frequency_hz", 99)),
            max_output_bytes=int(section.get("max_output_bytes", 1 << 30)),
            max_plan_ttl_seconds=int(section.get("max_plan_ttl_seconds", 300)),
            allowed_stat_events=tuple(str(event) for event in raw_events),
            socket_mode=socket_mode,
            artifact_mode=artifact_mode,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            "Collector policy contains missing or invalid field values",
        ) from exc
    try:
        return validate_broker_policy(policy)
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            str(exc),
        ) from exc


def _trusted_policy_file(path: Path) -> Path:
    if not path.expanduser().is_absolute():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_policy",
            "Collector policy path must be absolute",
        )
    try:
        safe_path = path.expanduser().resolve(strict=True)
        metadata = safe_path.stat()
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_policy",
            "Collector policy cannot be resolved",
            details={"path": str(path)},
        ) from exc
    trusted_owners = {0, os.geteuid()}
    service_owned_and_writable = (
        metadata.st_uid == os.geteuid() and os.geteuid() != 0 and metadata.st_mode & 0o200
    )
    if (
        not safe_path.is_file()
        or metadata.st_uid not in trusted_owners
        or metadata.st_mode & 0o022
        or service_owned_and_writable
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_policy",
            "Collector policy must be root-owned, or immutable to a non-root service owner, and "
            "must not be group/world writable",
            details={"path": str(safe_path)},
        )
    return safe_path


def _secure_spool_root(path: Path) -> Path:
    if not path.expanduser().is_absolute():
        raise ValueError("Collector spool root must be absolute")
    try:
        safe_path = path.expanduser().resolve(strict=True)
        metadata = safe_path.stat()
    except OSError as exc:
        raise ValueError("Collector spool root must already exist") from exc
    if not safe_path.is_dir() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise ValueError(
            "Collector spool root must be owned by the service UID and not group/world writable"
        )
    return safe_path


def _executable(path: Path) -> Path:
    if not path.expanduser().is_absolute():
        raise ValueError("Collector perf path must be absolute")
    try:
        safe_path = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError("Collector perf path cannot be resolved") from exc
    metadata = safe_path.stat()
    trusted_owners = {0, os.geteuid()}
    service_owned_and_writable = (
        metadata.st_uid == os.geteuid() and os.geteuid() != 0 and metadata.st_mode & 0o200
    )
    if (
        not safe_path.is_file()
        or not os.access(safe_path, os.X_OK)
        or metadata.st_uid not in trusted_owners
        or metadata.st_mode & 0o022
        or service_owned_and_writable
    ):
        raise ValueError(
            "Collector perf path must be a trusted executable regular file that the non-root "
            "service cannot modify"
        )
    return safe_path
