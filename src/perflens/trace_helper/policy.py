"""Strict independent policy for the target-filtered Trace Helper boundary."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from perflens.domain.errors import ErrorCode, PerfLensError

TRACE_POLICY_SCHEMA_VERSION = 1
TRACE_CAPTURE_BACKEND = "target_filtered_kernel_v1"
TRACE_HELPER_SOCKET = Path("/run/perflens-trace-helper/helper.sock")
TRACE_PRIVATE_SPOOL = Path("/var/lib/perflens-trace-helper")
TRACE_MODES = ("sched", "off_cpu", "lock")
TRACE_MAX_DURATION_SECONDS = 10
TRACE_MAX_OUTPUT_BYTES = 64 << 20
TRACE_MAX_CONCURRENT_COLLECTIONS = 1
_MAX_POLICY_BYTES = 64 << 10

TraceMode = Literal["sched", "off_cpu", "lock"]


@dataclass(frozen=True, slots=True)
class TracePolicy:
    """Validated policy shared by the public Broker and private Helper."""

    path: Path
    policy_sha256: str
    allowed_uid: int
    allowed_modes: tuple[TraceMode, ...]
    max_duration_seconds: int
    max_output_bytes: int
    helper_socket: Path = TRACE_HELPER_SOCKET
    private_spool: Path = TRACE_PRIVATE_SPOOL
    capture_backend: str = TRACE_CAPTURE_BACKEND
    target_filter_before_userspace: bool = True
    max_concurrent_collections: int = TRACE_MAX_CONCURRENT_COLLECTIONS


def load_trace_policy(path: Path) -> TracePolicy:
    """Load a bounded, immutable policy and reject every non-contract field."""
    safe_path, raw = _read_trusted_policy(path)
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _invalid_policy("Trace policy is not valid bounded UTF-8 TOML") from exc
    if set(payload) != {"trace"} or not isinstance(payload["trace"], dict):
        raise _invalid_policy("Trace policy requires exactly one [trace] table")
    section = cast(dict[str, Any], payload["trace"])
    expected_fields = {
        "schema_version",
        "allowed_uid",
        "allowed_modes",
        "capture_backend",
        "target_filter_before_userspace",
        "max_duration_seconds",
        "max_output_bytes",
        "max_concurrent_collections",
        "helper_socket",
        "private_spool",
    }
    if set(section) != expected_fields:
        raise _invalid_policy("Trace policy contains unknown or missing fields")
    try:
        schema_version = _integer(section["schema_version"])
        allowed_uid = _integer(section["allowed_uid"])
        modes = tuple(_string(value) for value in _list(section["allowed_modes"]))
        capture_backend = _string(section["capture_backend"])
        filter_before_userspace = _boolean(section["target_filter_before_userspace"])
        duration = _integer(section["max_duration_seconds"])
        output_bytes = _integer(section["max_output_bytes"])
        concurrency = _integer(section["max_concurrent_collections"])
        helper_socket = Path(_string(section["helper_socket"]))
        private_spool = Path(_string(section["private_spool"]))
    except (TypeError, ValueError) as exc:
        raise _invalid_policy("Trace policy contains an invalid typed value") from exc
    if (
        schema_version != TRACE_POLICY_SCHEMA_VERSION
        or allowed_uid <= 0
        or modes != tuple(mode for mode in TRACE_MODES if mode in modes)
        or len(set(modes)) != len(modes)
        or not modes
        or any(mode not in TRACE_MODES for mode in modes)
        or capture_backend != TRACE_CAPTURE_BACKEND
        or not filter_before_userspace
        or duration < 1
        or duration > TRACE_MAX_DURATION_SECONDS
        or output_bytes < 1
        or output_bytes > TRACE_MAX_OUTPUT_BYTES
        or concurrency != TRACE_MAX_CONCURRENT_COLLECTIONS
        or helper_socket != TRACE_HELPER_SOCKET
        or private_spool != TRACE_PRIVATE_SPOOL
    ):
        raise _invalid_policy("Trace policy exceeds or differs from the fixed safety boundary")
    return TracePolicy(
        path=safe_path,
        policy_sha256=hashlib.sha256(raw).hexdigest(),
        allowed_uid=allowed_uid,
        allowed_modes=cast(tuple[TraceMode, ...], modes),
        max_duration_seconds=duration,
        max_output_bytes=output_bytes,
    )


def _read_trusted_policy(path: Path) -> tuple[Path, bytes]:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise _unsafe_policy("Trace policy path must be absolute and must not be a symlink")
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > _MAX_POLICY_BYTES
            or (
                before.st_uid == os.geteuid()
                and os.geteuid() != 0
                and before.st_mode & 0o200
            )
        ):
            raise _unsafe_policy("Trace policy ownership or permissions are unsafe")
        raw = os.read(descriptor, _MAX_POLICY_BYTES + 1)
        after = os.fstat(descriptor)
        current = resolved.stat(follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or len(raw) > _MAX_POLICY_BYTES
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(current)
        ):
            raise _unsafe_policy("Trace policy identity changed while it was read")
    except PerfLensError:
        raise
    except OSError as exc:
        raise _unsafe_policy("Trace policy cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return resolved, raw


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
    )


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("expected integer")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expected string")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError("expected boolean")
    return value


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError("expected list")
    return cast(list[object], value)


def _unsafe_policy(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PATH_SAFETY_VIOLATION, "trace_policy", message)


def _invalid_policy(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.INVALID_INPUT, "trace_policy", message)

