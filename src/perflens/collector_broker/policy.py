"""Root-owned policy for the optional collector broker."""

from __future__ import annotations

import math
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from perflens.collection.collector import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_STAT_EVENTS,
    CollectionMode,
)
from perflens.domain.errors import ErrorCode, PerfLensError

COLLECTOR_POLICY_VERSION = 1
DEFAULT_MAX_SPOOL_BYTES = 5 << 30
DEFAULT_MAX_SPOOL_ARTIFACTS = 500
DEFAULT_MIN_FREE_BYTES = 2 << 30
DEFAULT_MAX_PLAN_TTL_SECONDS = 120


@dataclass(frozen=True, slots=True)
class CollectorBrokerPolicy:
    spool_root: Path
    perf_path: Path
    allowed_uids: tuple[int, ...]
    policy_version: int = COLLECTOR_POLICY_VERSION
    allowed_modes: tuple[CollectionMode, ...] = ("record", "stat")
    allow_other_target_uids: bool = False
    max_duration_seconds: float = 30.0
    max_frequency_hz: int = 99
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES
    max_spool_artifacts: int = DEFAULT_MAX_SPOOL_ARTIFACTS
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES
    max_plan_ttl_seconds: int = DEFAULT_MAX_PLAN_TTL_SECONDS
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
    if (
        not _is_integer(policy.policy_version)
        or policy.policy_version != COLLECTOR_POLICY_VERSION
    ):
        raise ValueError(
            f"Unsupported Collector policy version: {policy.policy_version}; "
            f"expected {COLLECTOR_POLICY_VERSION}"
        )
    if len(policy.allowed_uids) != 1 or any(
        not _is_integer(uid) or uid < 0 for uid in policy.allowed_uids
    ):
        raise ValueError("Collector policy requires exactly one non-negative allowed UID")
    if not policy.allowed_modes or any(
        not _is_string(mode) or mode not in supported_modes
        for mode in policy.allowed_modes
    ):
        raise ValueError("Collector policy contains an unsupported or empty mode set")
    if not _is_boolean(policy.allow_other_target_uids):
        raise ValueError("Collector cross-UID policy must be boolean")
    if not _is_number(policy.max_duration_seconds) or not math.isfinite(
        policy.max_duration_seconds
    ):
        raise ValueError("Collector policy duration must be a finite number")
    integer_limits = (
        policy.max_frequency_hz,
        policy.max_output_bytes,
        policy.max_spool_bytes,
        policy.max_spool_artifacts,
        policy.min_free_bytes,
        policy.max_plan_ttl_seconds,
    )
    if any(not _is_integer(value) for value in integer_limits):
        raise ValueError("Collector policy integer limits must be integers, not booleans")
    if (
        policy.max_duration_seconds <= 0
        or policy.max_duration_seconds > 86_400
        or policy.max_frequency_hz < 1
        or policy.max_frequency_hz > 10_000
        or policy.max_output_bytes < 1
        or policy.max_spool_bytes < policy.max_output_bytes
        or policy.max_spool_bytes > 1 << 50
        or policy.max_spool_artifacts < 1
        or policy.max_spool_artifacts > 1_000_000
        or policy.min_free_bytes < 0
        or policy.min_free_bytes > 1 << 50
        or policy.max_plan_ttl_seconds < 1
        or policy.max_plan_ttl_seconds > 3600
    ):
        raise ValueError("Collector policy limits are invalid")
    if (
        not policy.allowed_stat_events
        or len(policy.allowed_stat_events) > 64
        or any(
            not _is_string(event) or not event or "\0" in event
            for event in policy.allowed_stat_events
        )
    ):
        raise ValueError("Collector policy requires between 1 and 64 stat events")
    if (
        not _is_integer(policy.socket_mode)
        or policy.socket_mode < 0
        or policy.socket_mode > 0o660
        or policy.socket_mode & 0o007
        or policy.socket_mode & 0o600 != 0o600
    ):
        raise ValueError("Collector socket mode must not grant access to other users")
    if (
        not _is_integer(policy.artifact_mode)
        or policy.artifact_mode not in {0o440, 0o640}
    ):
        raise ValueError(
            "Collector artifact mode must be 0440 or 0640 so the authorized group is "
            "read-only and other users have no access"
        )
    return CollectorBrokerPolicy(
        spool_root=spool_root,
        perf_path=perf_path,
        allowed_uids=tuple(sorted(set(policy.allowed_uids))),
        policy_version=policy.policy_version,
        allowed_modes=tuple(dict.fromkeys(policy.allowed_modes)),
        allow_other_target_uids=policy.allow_other_target_uids,
        max_duration_seconds=policy.max_duration_seconds,
        max_frequency_hz=policy.max_frequency_hz,
        max_output_bytes=policy.max_output_bytes,
        max_spool_bytes=policy.max_spool_bytes,
        max_spool_artifacts=policy.max_spool_artifacts,
        min_free_bytes=policy.min_free_bytes,
        max_plan_ttl_seconds=policy.max_plan_ttl_seconds,
        allowed_stat_events=tuple(dict.fromkeys(policy.allowed_stat_events)),
        socket_mode=policy.socket_mode,
        artifact_mode=policy.artifact_mode,
    )


def _parse_policy(section: dict[str, Any]) -> CollectorBrokerPolicy:
    allowed_keys = {
        "policy_version",
        "spool_root",
        "perf_path",
        "allowed_uids",
        "allowed_modes",
        "allow_other_target_uids",
        "max_duration_seconds",
        "max_frequency_hz",
        "max_output_bytes",
        "max_spool_bytes",
        "max_spool_artifacts",
        "min_free_bytes",
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
        socket_mode = _mode_value(socket_mode_raw)
        artifact_mode = _mode_value(artifact_mode_raw)
        policy_version = _integer_field(
            section,
            "policy_version",
            COLLECTOR_POLICY_VERSION,
        )
        allow_other = section.get("allow_other_target_uids", False)
        if not isinstance(allow_other, bool):
            raise TypeError("allow_other_target_uids must be boolean")
        policy = CollectorBrokerPolicy(
            spool_root=Path(_string_value(section["spool_root"])),
            perf_path=Path(_string_value(section["perf_path"])),
            allowed_uids=tuple(_integer_value(uid) for uid in section["allowed_uids"]),
            policy_version=policy_version,
            allowed_modes=cast(tuple[CollectionMode, ...], raw_modes),
            allow_other_target_uids=allow_other,
            max_duration_seconds=_number_field(section, "max_duration_seconds", 30.0),
            max_frequency_hz=_integer_field(section, "max_frequency_hz", 99),
            max_output_bytes=_integer_field(
                section, "max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES
            ),
            max_spool_bytes=_integer_field(
                section, "max_spool_bytes", DEFAULT_MAX_SPOOL_BYTES
            ),
            max_spool_artifacts=_integer_field(
                section, "max_spool_artifacts", DEFAULT_MAX_SPOOL_ARTIFACTS
            ),
            min_free_bytes=_integer_field(
                section, "min_free_bytes", DEFAULT_MIN_FREE_BYTES
            ),
            max_plan_ttl_seconds=_integer_field(
                section, "max_plan_ttl_seconds", DEFAULT_MAX_PLAN_TTL_SECONDS
            ),
            allowed_stat_events=tuple(_string_value(event) for event in raw_events),
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


def _integer_field(section: dict[str, Any], name: str, default: int) -> int:
    return _integer_value(section.get(name, default))


def _integer_value(value: object) -> int:
    if not _is_integer(value):
        raise TypeError("Collector policy integer field must be an integer, not a boolean")
    return cast(int, value)


def _number_field(section: dict[str, Any], name: str, default: float) -> float:
    value = section.get(name, default)
    if not _is_number(value):
        raise TypeError("Collector policy number field must be numeric, not a boolean")
    return float(value)


def _mode_value(value: object) -> int:
    if isinstance(value, str):
        return int(value, 8)
    return _integer_value(value)


def _string_value(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Collector policy string list must contain only strings")
    return value


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_string(value: object) -> bool:
    return isinstance(value, str)


def _is_boolean(value: object) -> bool:
    return isinstance(value, bool)


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
