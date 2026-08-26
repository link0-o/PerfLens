"""Safe, bounded wrappers around active Linux perf collection modes."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens.application.evidence import verify_collection_artifact
from perflens.contracts.artifacts import CollectionArtifact, PerfStatMetric
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner
from perflens.metrics.perf_stat import PerfStatMetricAdapter
from perflens.perf_events import (
    DEFAULT_RECORD_EVENT,
    DEFAULT_STAT_EVENTS,
    HARDWARE_STAT_EVENTS,
    SOFTWARE_RECORD_EVENT,
    SOFTWARE_STAT_EVENTS,
)
from perflens.security.paths import validate_new_output_file

ACTIVE_COLLECTION_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING"
PID_ATTACH_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_PID_ATTACH"
FALLBACK_REASONS = (
    "hardware_probe_skipped_for_short_collection",
    "hardware_probe_failed",
    "hardware_probe_produced_no_usable_counts",
    "hardware_execution_failed_after_probe",
)
DEFAULT_MAX_OUTPUT_BYTES = 256 << 20
_PERF_CONTROL_TIMEOUT_SECONDS = 5.0
_PERF_CONTROL_ACK_MAX_BYTES = 16
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
    record_event: Literal["cycles", "cpu-clock"] = DEFAULT_RECORD_EVENT
    requested_event_source: Literal["auto", "hardware_required", "software_only"] = (
        "hardware_required"
    )
    fallback_used: bool = False
    fallback_reason: str | None = None
    timeout_seconds: float = 300.0
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


def collect_profile(
    request: CollectionRequest,
    *,
    pid_identity_validator: Callable[[], None] | None = None,
    ready_callback: Callable[[], None] | None = None,
    record_build_id_mmap: bool = False,
) -> CollectionArtifact:
    """Run one explicitly authorized collection and publish a new immutable output."""
    _validate_request(request)
    perf_path = _resolve_executable(request.perf_path or _find_executable("perf"), "perf")
    target, target_type = _resolve_target(request.target)
    if pid_identity_validator is not None and target_type != "pid":
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "PID identity validation is only valid for PID collection",
        )
    if ready_callback is not None and pid_identity_validator is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Collection readiness requires a PID identity validator",
        )
    if record_build_id_mmap and (
        request.mode != "record"
        or request.target.pid is None
        or pid_identity_validator is None
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Container Build ID mapping requires an identity-validated PID record collection",
        )
    safe_output = validate_new_output_file(request.output_path)
    started = datetime.now(tz=UTC)
    temporary_path = _reserve_temporary_path(safe_output)
    runner = CommandRunner({perf_path})
    control: _PerfControl | None = None
    try:
        if pid_identity_validator is not None:
            control = _PerfControl(pid_identity_validator, ready_callback)
        argv = _build_perf_argv(
            request,
            perf_path,
            temporary_path,
            target,
            target_type,
            control_argument=control.argument if control is not None else None,
            record_build_id_mmap=record_build_id_mmap,
        )
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
                pass_fds=control.child_fds if control is not None else (),
                after_start=control.after_start if control is not None else None,
            )
        output_size = _validate_collected_output(temporary_path, request.max_output_bytes)
        metrics, metric_warnings = _read_metrics(request.mode, temporary_path)
        output_sha256 = _sha256_file(temporary_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    finally:
        if control is not None:
            control.close()

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
    actual_event_source = _actual_event_source(request)
    evidence_limitations = _evidence_limitations(actual_event_source)
    if request.fallback_used:
        warnings.append(
            "Hardware PMU evidence was unavailable; PerfLens continued with software events."
        )
    if request.mode == "off_cpu":
        warnings.append(
            "off_cpu records sched:sched_switch tracepoint stacks; interpreting blocked time "
            "still requires workload-aware post-processing."
        )
    temporary_artifact = CollectionArtifact(
        collection_id=collection_id,
        mode=request.mode,
        target_type=target_type,
        target_executable=str(target[0]) if target_type == "command" else None,
        target_argument_count=len(target) - 1 if target_type == "command" else 0,
        target_argv_sha256=target_hash if target_type == "command" else None,
        target_pid=request.target.pid if target_type == "pid" else None,
        output_path=str(temporary_path),
        output_sha256=output_sha256,
        output_bytes=output_size,
        output_format="perf_stat_delimited" if request.mode == "stat" else "perf_data",
        perf_executable=str(perf_path),
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=result.duration_seconds,
        frequency_hz=request.frequency_hz if request.mode in {"record", "off_cpu"} else None,
        call_graph=request.call_graph if request.mode in {"record", "off_cpu"} else None,
        record_event=request.record_event if request.mode == "record" else None,
        events=request.events if request.mode == "stat" else (),
        requested_event_source=request.requested_event_source,
        actual_event_source=actual_event_source,
        fallback_used=request.fallback_used,
        fallback_reason=request.fallback_reason,
        evidence_limitations=evidence_limitations,
        metrics=metrics,
        diagnostics=diagnostics,
        diagnostics_truncated=result.stderr_truncated or result.stderr_bytes > (1 << 20),
        warnings=tuple(warnings),
    )
    try:
        # Validate the exact raw file and its typed projection before publication. This keeps an
        # invalid formal hardware attempt from occupying the fixed output name and blocking the
        # policy-bounded software fallback.
        verify_collection_artifact(
            temporary_artifact,
            max_output_bytes=request.max_output_bytes,
        )
        _publish_without_overwrite(temporary_path, safe_output)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    artifact = temporary_artifact.model_copy(update={"output_path": str(safe_output)})
    # Re-open the published hard link so publication identity, size, and digest are also checked.
    verify_collection_artifact(artifact, max_output_bytes=request.max_output_bytes)
    return artifact


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
    if request.requested_event_source not in {"auto", "hardware_required", "software_only"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "requested_event_source is unsupported",
        )
    if request.fallback_used and request.requested_event_source != "auto":
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Only auto collection may report a software fallback",
        )
    if request.fallback_used != (request.fallback_reason is not None) or (
        request.fallback_reason is not None and request.fallback_reason not in FALLBACK_REASONS
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Software fallback requires one fixed fallback reason",
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
        selected_events = set(request.events)
        if request.requested_event_source == "software_only" and not selected_events.issubset(
            SOFTWARE_STAT_EVENTS
        ):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "Software-only stat collection accepts only fixed software events",
            )
        if (
            request.requested_event_source == "hardware_required"
            and not selected_events.intersection(HARDWARE_STAT_EVENTS)
        ):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "Hardware-required stat collection requires a hardware event",
            )
        if request.fallback_used and not selected_events.issubset(SOFTWARE_STAT_EVENTS):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "Software fallback stat collection requires fixed software events",
            )
    if request.record_event not in {DEFAULT_RECORD_EVENT, SOFTWARE_RECORD_EVENT}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "perf record event is unsupported",
        )
    if request.mode == "record" and (
        (
            request.requested_event_source == "software_only"
            and request.record_event != SOFTWARE_RECORD_EVENT
        )
        or (
            request.requested_event_source == "hardware_required"
            and request.record_event != DEFAULT_RECORD_EVENT
        )
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "perf record event does not match the requested event source",
        )
    if (
        request.mode == "record"
        and request.fallback_used
        and (request.record_event != SOFTWARE_RECORD_EVENT)
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection",
            "Software fallback record collection requires cpu-clock",
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
    *,
    control_argument: str | None = None,
    record_build_id_mmap: bool = False,
) -> tuple[str, ...]:
    if request.mode == "record":
        prefix = (
            str(perf_path),
            "record",
            "-e",
            request.record_event,
            "--freq",
            str(request.frequency_hz),
            "--call-graph",
            request.call_graph,
            "--sample-cpu",
            "-g",
            "-o",
            str(output_path),
        )
        if record_build_id_mmap:
            prefix = (*prefix, "--buildid-mmap")
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
            "--sample-cpu",
            "-g",
            "-o",
            str(output_path),
        )
    if target_type == "command":
        if control_argument is not None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collection",
                "perf control is only valid for PID collection",
            )
        return (*prefix, "--", *target)
    if control_argument is not None:
        prefix = (*prefix, "-D", "-1", "--control", control_argument)
    sleep_path = _resolve_executable(_find_executable("sleep"), "sleep")
    return (*prefix, "-p", target[0], "--", str(sleep_path), target[1])


class _PerfControl:
    """Keep PID events disabled until perf has bound and the plan identity is revalidated."""

    def __init__(
        self,
        pid_identity_validator: Callable[[], None],
        ready_callback: Callable[[], None] | None,
    ) -> None:
        self._validator = pid_identity_validator
        self._ready_callback = ready_callback
        control_writer, control_reader = socket.socketpair()
        try:
            ack_writer, ack_reader = socket.socketpair()
        except BaseException:
            control_writer.close()
            control_reader.close()
            raise
        self._control_writer = control_writer
        self._control_reader = control_reader
        self._ack_writer = ack_writer
        self._ack_reader = ack_reader
        try:
            self._control_writer.settimeout(_PERF_CONTROL_TIMEOUT_SECONDS)
            self._ack_reader.settimeout(_PERF_CONTROL_TIMEOUT_SECONDS)
        except BaseException:
            self.close()
            raise
        self._ack_buffer = bytearray()
        self._child_closed = False

    @property
    def argument(self) -> str:
        return f"fd:{self._control_reader.fileno()},{self._ack_writer.fileno()}"

    @property
    def child_fds(self) -> tuple[int, int]:
        return self._control_reader.fileno(), self._ack_writer.fileno()

    def after_start(self) -> None:
        self._close_child_ends()
        # perf's documented control protocol has no generic ping command. Because `-D -1`
        # already opened the events disabled, an acknowledged idempotent `disable` is the
        # non-enabling barrier that proves perf has finished binding the target.
        self._send("disable")
        self._validator()
        self._send("enable")
        if self._ready_callback is not None:
            self._ready_callback()

    def close(self) -> None:
        for endpoint in (
            self._control_writer,
            self._control_reader,
            self._ack_writer,
            self._ack_reader,
        ):
            endpoint.close()

    def _close_child_ends(self) -> None:
        if self._child_closed:
            return
        self._control_reader.close()
        self._ack_writer.close()
        self._child_closed = True

    def _send(self, command: str) -> None:
        try:
            self._control_writer.sendall(command.encode("ascii") + b"\n")
            acknowledgement = self._read_acknowledgement()
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "external_tool",
                "perf control channel failed before collection could be enabled",
                recoverable=True,
            ) from exc
        if acknowledgement.lstrip(b"\0") != b"ack\n":
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "external_tool",
                "perf returned an invalid control acknowledgement",
                recoverable=True,
            )

    def _read_acknowledgement(self) -> bytes:
        while b"\n" not in self._ack_buffer:
            if len(self._ack_buffer) >= _PERF_CONTROL_ACK_MAX_BYTES:
                break
            chunk = self._ack_reader.recv(_PERF_CONTROL_ACK_MAX_BYTES - len(self._ack_buffer))
            if not chunk:
                break
            self._ack_buffer.extend(chunk)
        newline = self._ack_buffer.find(b"\n")
        if newline < 0:
            acknowledgement = bytes(self._ack_buffer)
            self._ack_buffer.clear()
            return acknowledgement
        end = newline + 1
        acknowledgement = bytes(self._ack_buffer[:end])
        del self._ack_buffer[:end]
        return acknowledgement


def _read_metrics(
    mode: CollectionMode, output_path: Path
) -> tuple[tuple[PerfStatMetric, ...], tuple[str, ...]]:
    if mode != "stat":
        return (), ()
    return PerfStatMetricAdapter().parse(output_path)


def _actual_event_source(request: CollectionRequest) -> Literal["hardware", "software", "unknown"]:
    if request.mode == "record":
        return "software" if request.record_event == SOFTWARE_RECORD_EVENT else "hardware"
    if request.mode == "stat":
        selected = set(request.events)
        if selected and selected.issubset(SOFTWARE_STAT_EVENTS):
            return "software"
        if selected.intersection(HARDWARE_STAT_EVENTS):
            return "hardware"
    return "unknown"


def _evidence_limitations(event_source: str) -> tuple[str, ...]:
    if event_source != "software":
        return ()
    return (
        "instructions-per-cycle unavailable",
        "hardware cache-miss evidence unavailable",
        "hardware branch-miss evidence unavailable",
    )


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
