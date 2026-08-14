"""Launch one project executable unprivileged and collect its exact PID."""

from __future__ import annotations

import hashlib
import math
import os
import select
import signal
import stat
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from perflens import __version__
from perflens.collection.collector import (
    DEFAULT_MAX_OUTPUT_BYTES,
    HARDWARE_STAT_EVENTS,
    CallGraphMode,
    CollectionMode,
)
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionCapabilityArtifact,
    ProjectRunArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

PROJECT_EXECUTION_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION"
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_BYTES = 32 << 10
_BOOTSTRAP_READY_TIMEOUT_SECONDS = 3.0
_TERMINATE_GRACE_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class ProjectWorkloadRequest:
    project_root: Path
    executable: Path
    authorization: str
    arguments: tuple[str, ...] = ()
    mode: CollectionMode = "record"
    duration_seconds: float = 10.0
    frequency_hz: int = 99
    call_graph: CallGraphMode = "dwarf"
    events: tuple[str, ...] = HARDWARE_STAT_EVENTS
    event_source: Literal["auto", "hardware_required", "software_only"] = "auto"
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


def collect_project_workload(
    request: ProjectWorkloadRequest,
    *,
    policy: AutomaticCollectionPolicy,
    capabilities: CollectionCapabilityArtifact,
    collector_socket: Path,
) -> tuple[CollectionArtifact, ProjectRunArtifact]:
    """Run an exact executable as the current user and profile only that PID incarnation."""
    project, executable, arguments = _validate_request(request)
    started_at = datetime.now(tz=UTC)
    release_read, release_write = os.pipe()
    ready_read, ready_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    released = False
    try:
        bootstrap = Path(__file__).with_name("_bootstrap.py").resolve(strict=True)
        process = _start_bootstrap(
            bootstrap,
            project,
            executable,
            arguments,
            release_read=release_read,
            ready_write=ready_write,
        )
        os.close(release_read)
        release_read = -1
        os.close(ready_write)
        ready_write = -1
        _wait_until_ready(process, ready_read)
        os.close(ready_read)
        ready_read = -1

        plan = create_collection_plan(
            CollectionPlanRequest(
                mode=request.mode,
                pid=process.pid,
                duration_seconds=request.duration_seconds,
                frequency_hz=request.frequency_hz,
                call_graph=request.call_graph,
                events=request.events,
                event_source=request.event_source,
                max_output_bytes=request.max_output_bytes,
            ),
            policy=policy,
            capabilities=capabilities,
        )
        if plan.policy_status != "allowed":
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "project_workload",
                "Project collection was denied by the automatic collection policy",
                recoverable=True,
                details={"warnings": list(plan.warnings)},
            )

        client = CollectorBrokerClient(
            collector_socket,
            timeout_seconds=min(plan.duration_seconds + 15, 86_500),
        )

        def release_workload() -> None:
            nonlocal release_write, released
            os.write(release_write, b"1")
            os.close(release_write)
            release_write = -1
            released = True

        collection = client.collect(plan, ready_callback=release_workload)
        if not released:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "project_workload",
                "Collector completed without confirming that it attached to the project PID",
            )

        exit_code = process.poll()
        warnings = list(plan.warnings)
        if exit_code is None:
            _terminate_group(process)
            exit_code = process.returncode
            workload_status = "terminated_after_collection"
        else:
            workload_status = "exited"
            if exit_code != 0:
                warnings.append(f"Project workload exited with code {exit_code}.")
        finished_at = datetime.now(tz=UTC)
        identity = "\0".join(
            (
                str(project),
                str(executable),
                "\0".join(arguments),
                str(plan.target_pid),
                str(plan.target_start_time_ticks),
                collection.collection_id,
            )
        )
        project_run = ProjectRunArtifact(
            perflens_version=__version__,
            project_run_id=f"project-run-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
            project_root=str(project),
            executable=str(executable),
            arguments=arguments,
            target_pid=plan.target_pid,
            target_uid=plan.target_uid,
            target_start_time_ticks=plan.target_start_time_ticks,
            mode=plan.mode,
            requested_duration_seconds=plan.duration_seconds,
            collection_id=collection.collection_id,
            workload_status=workload_status,
            workload_exit_code=exit_code,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            warnings=tuple(warnings),
        )
        return collection, project_run
    except BaseException:
        if process is not None and process.poll() is None:
            _terminate_group(process)
        raise
    finally:
        for descriptor in (release_read, release_write, ready_read, ready_write):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
        if process is not None and released and process.poll() is None:
            _terminate_group(process)


def _validate_request(
    request: ProjectWorkloadRequest,
) -> tuple[Path, Path, tuple[str, ...]]:
    if request.authorization != PROJECT_EXECUTION_AUTHORIZATION:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Project execution requires explicit per-call authorization",
            recoverable=True,
            details={"required_authorization": PROJECT_EXECUTION_AUTHORIZATION},
            suggested_actions=(
                "After the user authorizes the exact workload, pass "
                f"authorization={PROJECT_EXECUTION_AUTHORIZATION} to collect_project_workload.",
                "Do not replace a denied project-workload call with a shell launch, direct perf, "
                "or existing-PID attachment.",
            ),
        )
    try:
        project = request.project_root.expanduser().resolve(strict=True)
        candidate = request.executable.expanduser()
        if not candidate.is_absolute():
            candidate = project / candidate
        executable = candidate.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "project_workload",
            "Project root or executable cannot be resolved",
        ) from exc
    if not project.is_dir() or not executable.is_file() or not executable.is_relative_to(project):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "project_workload",
            "Project executable must be a regular file inside the project root",
            details={"project_root": str(project), "executable": str(executable)},
        )
    if not os.access(executable, os.X_OK):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "project_workload",
            "Project executable is not executable",
            details={"executable": str(executable)},
        )
    if executable.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "project_workload",
            "Project executable must not have set-user-ID or set-group-ID bits",
            details={"executable": str(executable)},
        )
    arguments = tuple(request.arguments)
    total_bytes = sum(len(argument.encode("utf-8")) for argument in arguments)
    if (
        len(arguments) > _MAX_ARGUMENTS
        or total_bytes > _MAX_ARGUMENT_BYTES
        or any("\0" in argument for argument in arguments)
    ):
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "project_workload",
            "Project arguments exceed their count or byte limit",
            details={"argument_count": len(arguments), "argument_bytes": total_bytes},
        )
    if not math.isfinite(request.duration_seconds) or request.duration_seconds <= 0:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "project_workload",
            "Project collection duration must be finite and positive",
        )
    return project, executable, arguments


def _start_bootstrap(
    bootstrap: Path,
    project: Path,
    executable: Path,
    arguments: tuple[str, ...],
    *,
    release_read: int,
    ready_write: int,
) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(  # noqa: S603 - trusted bootstrap and canonical target
            [
                sys.executable,
                str(bootstrap),
                str(release_read),
                str(ready_write),
                str(executable),
                *arguments,
            ],
            cwd=project,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            pass_fds=(release_read, ready_write),
            start_new_session=True,
            env={
                "HOME": str(project),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
        )
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "project_workload",
            "Unable to start the unprivileged project workload bootstrap",
            recoverable=True,
            details={"executable": str(executable)},
        ) from exc


def _wait_until_ready(process: subprocess.Popen[bytes], ready_read: int) -> None:
    readable, _, _ = select.select(
        [ready_read],
        [],
        [],
        _BOOTSTRAP_READY_TIMEOUT_SECONDS,
    )
    if not readable or os.read(ready_read, 1) != b"R" or process.poll() is not None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "project_workload",
            "Project workload bootstrap did not become ready",
            recoverable=True,
        )


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if process.poll() is None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    process.wait()
