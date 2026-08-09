"""Unprivileged end-to-end acceptance probe for an installed Collector."""

from __future__ import annotations

import hashlib
import math
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from perflens import __version__
from perflens.collection.collector import DEFAULT_STAT_EVENTS
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectorAcceptanceArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_DURATION_SECONDS = 5.0
_PROBE_SOURCE = (
    "import time\n"
    "deadline = time.monotonic() + 30.0\n"
    "value = 1\n"
    "while time.monotonic() < deadline:\n"
    "    value = (value * 1103515245 + 12345) & 0x7fffffff\n"
)


def accept_collector(
    socket_path: Path,
    *,
    duration_seconds: float,
    authorized: bool,
    capabilities: CollectionCapabilityArtifact,
) -> CollectorAcceptanceArtifact:
    """Profile a fixed, self-owned CPU probe through the Collector and return evidence."""
    if not authorized:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Collector host acceptance requires explicit authorization",
            recoverable=True,
            suggested_actions=("Pass --authorize-host-acceptance.",),
        )
    if (
        not math.isfinite(duration_seconds)
        or duration_seconds < 0.1
        or duration_seconds > _MAX_DURATION_SECONDS
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_acceptance",
            "Collector acceptance duration must be between 0.1 and 5 seconds",
        )

    process: subprocess.Popen[bytes] | None = None
    try:
        process = _start_probe()
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=process.pid,
                duration_seconds=duration_seconds,
                events=DEFAULT_STAT_EVENTS,
                max_output_bytes=8 << 20,
            ),
            policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat",),
                max_duration_seconds=_MAX_DURATION_SECONDS,
                max_output_bytes=8 << 20,
                plan_ttl_seconds=60,
            ),
            capabilities=capabilities,
        )
        if plan.policy_status != "allowed":
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_acceptance",
                "Collector acceptance plan was denied",
                recoverable=True,
                details={"warnings": list(plan.warnings)},
            )
        try:
            collection = CollectorBrokerClient(
                socket_path,
                timeout_seconds=duration_seconds + 15,
            ).collect(plan)
        except ValueError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collector_acceptance",
                "Collector socket must be an existing absolute Unix socket",
                recoverable=True,
                details={"socket": str(socket_path)},
            ) from exc
        measured_metrics = tuple(
            metric
            for metric in collection.metrics
            if metric.status == "measured" and metric.value is not None
        )
        if not measured_metrics:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "collector_acceptance",
                "Collector acceptance produced no measured perf stat metrics",
                recoverable=True,
                details={
                    "collection_id": collection.collection_id,
                    "metric_statuses": [metric.status for metric in collection.metrics],
                },
                suggested_actions=(
                    "Inspect perf event support and the Collector journal, then retry.",
                    "虚拟机请在虚拟化平台启用虚拟 CPU 性能计数器 / "
                    "On a virtual machine, enable virtual CPU performance counters in the "
                    "hypervisor.",
                ),
            )

        identity = "\0".join(
            (
                collection.collection_id,
                str(plan.target_pid),
                str(plan.target_start_time_ticks),
                str(socket_path),
            )
        )
        return CollectorAcceptanceArtifact(
            perflens_version=__version__,
            acceptance_id=f"acceptance-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
            socket_path=str(socket_path),
            target_pid=plan.target_pid,
            target_uid=plan.target_uid,
            target_start_time_ticks=plan.target_start_time_ticks,
            requested_duration_seconds=plan.duration_seconds,
            collection_id=collection.collection_id,
            output_path=collection.output_path,
            output_sha256=collection.output_sha256,
            output_bytes=collection.output_bytes,
            metric_count=len(collection.metrics),
            started_at=collection.started_at,
            finished_at=collection.finished_at,
            warnings=tuple((*plan.warnings, *collection.warnings)),
        )
    finally:
        if process is not None:
            _stop_probe(process)


def _start_probe() -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(  # noqa: S603 - fixed interpreter and fixed probe source
            [sys.executable, "-I", "-c", _PROBE_SOURCE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "collector_acceptance",
            "Unable to start the built-in acceptance probe",
            recoverable=True,
        ) from exc


def _stop_probe(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
