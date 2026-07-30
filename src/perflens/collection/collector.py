"""Safe, bounded wrappers around active Linux perf collection modes."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens.contracts.artifacts import CollectionArtifact, PerfStatMetric
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner
from perflens.metrics.perf_stat import PerfStatMetricAdapter
from perflens.security.paths import validate_new_output_file

ACTIVE_COLLECTION_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING"
PID_ATTACH_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_PID_ATTACH"
DEFAULT_STAT_EVENTS = (
    "cycles",
    "instructions",
    "cache-references",
    "cache-misses",
    "branches",
    "branch-misses",
    "context-switches",
    "cpu-migrations",
    "page-faults",
)
CollectionMode = Literal["record", "stat", "sched", "lock", "off_cpu"]
CallGraphMode = Literal["fp", "dwarf", "lbr"]


@dataclass(frozen=True, slots=True)
class CollectionTarget:
    executable: Path | None = None
    arguments: tuple[str, ...] = ()
    pid: int | None = None
    duration_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    mode: CollectionMode
    target: CollectionTarget
    output_path: Path
    authorization: str
    pid_authorization: str | None = None
    perf_path: Path | None = None
    frequency_hz: int = 99
    call_graph: CallGraphMode = "dwarf"
    events: tuple[str, ...] = DEFAULT_STAT_EVENTS
    timeout_seconds: float = 300.0
    max_output_bytes: int = 1 << 30


def collect_profile(request: CollectionRequest) -> CollectionArtifact:
    """Run one explicitly authorized collection and publish a new immutable output."""
    _validate_request(request)
    perf_path = _resolve_executable(request.perf_path or _find_executable("perf"), "perf")
    target, target_type = _resolve_target(request.target)
    safe_output = validate_new_output_file(request.output_path)
    started = datetime.now(tz=UTC)
    temporary_path = _reserve_temporary_path(safe_output)
    runner = CommandRunner({perf_path})
    try:
        argv = _build_perf_argv(request, perf_path, temporary_path, target, target_type)
        with tempfile.TemporaryFile(mode="w+b") as stdout:
            result = runner.run_to_file(
                argv,
                stdout,
                limits=CommandLimits(
                    timeout_seconds=request.timeout_seconds,
                    max_stdout_bytes=1 << 20,
                    max_stderr_bytes=1 << 20,
                    max_created_file_bytes=request.max_output_bytes,
                ),
                watched_output=temporary_path,
            )
        output_size = _validate_collected_output(temporary_path, request.max_output_bytes)
        metrics, metric_warnings = _read_metrics(request.mode, temporary_path)
        output_sha256 = _sha256_file(temporary_path)
        _publish_without_overwrite(temporary_path, safe_output)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise

    finished = datetime.now(tz=UTC)
    target_hash = _target_hash(target, target_type)
    identity = "\0".join(
        (
            request.mode,
            target_type,
            target_hash,
            output_sha256,
            str(request.frequency_hz),
            request.call_graph,
        )
    )
    collection_id = f"collection-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
    diagnostics = tuple(line[:512] for line in result.stderr.splitlines()[:32] if line.strip())
    warnings = [*metric_warnings]
    if request.mode == "off_cpu":
        warnings.append(
            "off_cpu records sched:sched_switch tracepoint stacks; interpreting blocked time "
            "still requires workload-aware post-processing."
        )
    return CollectionArtifact(
        collection_id=collection_id,
        mode=request.mode,
        target_type=target_type,
        target_executable=str(target[0]) if target_type == "command" else None,
        target_argument_count=len(target) - 1 if target_type == "command" else 0,
        target_argv_sha256=target_hash if target_type == "command" else None,
        target_pid=request.target.pid if target_type == "pid" else None,
        output_path=str(safe_output),
        output_sha256=output_sha256,
        output_bytes=output_size,
        output_format="perf_stat_delimited" if request.mode == "stat" else "perf_data",
        perf_executable=str(perf_path),
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=result.duration_seconds,
        frequency_hz=request.frequency_hz if request.mode in {"record", "off_cpu"} else None,
        call_graph=request.call_graph if request.mode in {"record", "off_cpu"} else None,
        events=request.events if request.mode == "stat" else (),
        metrics=metrics,
        diagnostics=diagnostics,
        diagnostics_truncated=result.stderr_truncated or result.stderr_bytes > (1 << 20),
        warnings=tuple(warnings),
    )


def _validate_request(request: CollectionRequest) -> None:
    if request.authorization != ACTIVE_COLLECTION_AUTHORIZATION:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Active collection requires the exact explicit authorization token",
            recoverable=True,
        )
    if request.target.pid is not None and request.pid_authorization != PID_ATTACH_AUTHORIZATION:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "PID attachment requires its separate explicit authorization token",
            recoverable=True,
        )
    if request.frequency_hz < 1 or request.frequency_hz > 10_000:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "frequency_hz must be between 1 and 10000",
        )
    if request.timeout_seconds <= 0 or request.timeout_seconds > 86_400:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "timeout_seconds must be greater than zero and at most one day",
        )
    if request.max_output_bytes < 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "max_output_bytes must be positive",
        )
    if request.mode == "stat":
        if not request.events or len(request.events) > 64:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "perf stat requires between 1 and 64 events",
            )
        for event in request.events:
            if not event or len(event) > 128 or any(character in event for character in "\0\n\r,;"):
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "collection",
                    "perf stat event contains unsupported characters",
                    details={"event": event[:128]},
                )


def _resolve_target(
    target: CollectionTarget,
) -> tuple[tuple[str, ...], Literal["command", "pid"]]:
    command_selected = target.executable is not None
    pid_selected = target.pid is not None
    if command_selected == pid_selected:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Select exactly one target: executable or pid",
        )
    if command_selected:
        assert target.executable is not None
        executable = _resolve_executable(target.executable, "target")
        for argument in target.arguments:
            if "\0" in argument or "\n" in argument or "\r" in argument:
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "collection",
                    "Target arguments must not contain NUL or newline characters",
                )
        if target.duration_seconds is not None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "duration_seconds is only valid for PID attachment",
            )
        return (str(executable), *target.arguments), "command"

    assert target.pid is not None
    if target.pid <= 0 or target.pid == os.getpid():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Target PID must be positive and must not be the collector process",
        )
    if not (Path("/proc") / str(target.pid)).is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Target PID does not exist",
            recoverable=True,
            details={"pid": target.pid},
        )
    duration = target.duration_seconds
    if duration is None or duration <= 0 or duration > 86_400:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "PID attachment duration must be greater than zero and at most one day",
        )
    return (str(target.pid), str(duration)), "pid"


def _build_perf_argv(
    request: CollectionRequest,
    perf_path: Path,
    output_path: Path,
    target: tuple[str, ...],
    target_type: Literal["command", "pid"],
) -> tuple[str, ...]:
    if request.mode == "record":
        prefix = (
            str(perf_path),
            "record",
            "--freq",
            str(request.frequency_hz),
            "--call-graph",
            request.call_graph,
            "-g",
            "-o",
            str(output_path),
        )
    elif request.mode == "stat":
        prefix = (
            str(perf_path),
            "stat",
            "--no-big-num",
            "-x",
            ";",
            "-o",
            str(output_path),
            "-e",
            ",".join(request.events),
        )
    elif request.mode == "sched":
        prefix = (str(perf_path), "sched", "record", "-o", str(output_path))
    elif request.mode == "lock":
        prefix = (str(perf_path), "lock", "record", "-o", str(output_path))
    else:
        prefix = (
            str(perf_path),
            "record",
            "-e",
            "sched:sched_switch",
            "--freq",
            str(request.frequency_hz),
            "--call-graph",
            request.call_graph,
            "-g",
            "-o",
            str(output_path),
        )
    if target_type == "command":
        return (*prefix, "--", *target)
    sleep_path = _resolve_executable(_find_executable("sleep"), "sleep")
    return (*prefix, "-p", target[0], "--", str(sleep_path), target[1])


def _read_metrics(
    mode: CollectionMode, output_path: Path
) -> tuple[tuple[PerfStatMetric, ...], tuple[str, ...]]:
    if mode != "stat":
        return (), ()
    return PerfStatMetricAdapter().parse(output_path)


def _resolve_executable(path: Path, label: str) -> Path:
    if not path.expanduser().is_absolute():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collection",
            f"{label} executable path must be absolute",
            details={"path": str(path)},
        )
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            f"{label} executable cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            f"{label} path is not an executable regular file",
            details={"path": str(resolved)},
        )
    return resolved


def _find_executable(name: str) -> Path:
    discovered = shutil.which(name)
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "external_tool",
            f"System {name} executable was not found",
            recoverable=True,
        )
    return Path(discovered).resolve(strict=True)


def _reserve_temporary_path(output_path: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".perflens-collect-", dir=output_path.parent)
    os.close(descriptor)
    return Path(name)


def _validate_collected_output(path: Path, maximum: int) -> int:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collection",
            "perf did not create a readable collection output",
            details={"path": str(path)},
        ) from exc
    if not path.is_file() or size <= 0:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collection",
            "perf collection output is empty or not a regular file",
            details={"path": str(path), "actual_bytes": size},
        )
    if size > maximum:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "collection",
            "perf collection output exceeds its size limit",
            details={"actual_bytes": size, "max_output_bytes": maximum},
        )
    return size


def _publish_without_overwrite(temporary_path: Path, output_path: Path) -> None:
    try:
        os.link(temporary_path, output_path)
        temporary_path.unlink()
    except FileExistsError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Collection output appeared during execution and was not overwritten",
            details={"path": str(output_path)},
        ) from exc
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "output",
            "Unable to publish collection output atomically",
            details={"path": str(output_path)},
        ) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _target_hash(target: Sequence[str], target_type: str) -> str:
    material = "\0".join((target_type, *target)).encode()
    return hashlib.sha256(material).hexdigest()
