"""Unprivileged end-to-end acceptance probe for an installed Collector."""

from __future__ import annotations

import hashlib
import math
import os
import signal
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from perflens import __version__
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.collection.collector import HARDWARE_STAT_EVENTS, SOFTWARE_STAT_EVENTS
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
    create_collection_plan,
)
from perflens.collector_broker.client import CollectorBrokerClient
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionCapabilityArtifact,
    CollectionPlanArtifact,
    CollectorAcceptanceArtifact,
    CollectorTraceModeAcceptance,
    PerfStatMetric,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceEvidenceArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_DURATION_SECONDS = 5.0
_PROBE_SOURCE = (
    "import os\n"
    "import threading\n"
    "import time\n"
    "deadline = time.monotonic() + 30.0\n"
    "lock = threading.Lock()\n"
    "def holder():\n"
    "    while time.monotonic() < deadline:\n"
    "        with lock:\n"
    "            time.sleep(0.01)\n"
    "        time.sleep(0)\n"
    "threading.Thread(target=holder, daemon=True).start()\n"
    "read_fd, write_fd = os.pipe()\n"
    "child = os.fork()\n"
    "if child == 0:\n"
    "    os.close(read_fd)\n"
    "    while time.monotonic() < deadline:\n"
    "        time.sleep(0.01)\n"
    "        os.write(write_fd, b'x')\n"
    "    os._exit(0)\n"
    "os.close(write_fd)\n"
    "value = 1\n"
    "try:\n"
    "    while time.monotonic() < deadline:\n"
    "        with lock:\n"
    "            for _ in range(2000):\n"
    "                value = (value * 1103515245 + 12345) & 0x7fffffff\n"
    "        os.read(read_fd, 1)\n"
    "finally:\n"
    "    os.close(read_fd)\n"
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
        client = _collector_client(socket_path, duration_seconds)
        health = client.health()
        feature_profile = health.feature_profile
        trace_modes = ("sched", "off_cpu", "lock")
        if feature_profile == "full_diagnostics" and not set(trace_modes).issubset(
            health.allowed_modes
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_acceptance",
                "Collector full_diagnostics health is missing an advanced mode",
                recoverable=True,
                details={"allowed_modes": list(health.allowed_modes)},
                suggested_actions=(
                    "Repair or switch the Collector profile, then rerun acceptance.",
                ),
            )
        policy = AutomaticCollectionPolicy(
            enabled=True,
            allowed_modes=(
                ("record", "stat", *trace_modes)
                if feature_profile == "full_diagnostics"
                else ("record", "stat")
            ),
            max_duration_seconds=_MAX_DURATION_SECONDS,
            max_output_bytes=8 << 20,
            plan_ttl_seconds=60,
        )
        hardware_collection = None
        hardware_reason = None
        hardware_plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=process.pid,
                duration_seconds=duration_seconds,
                events=HARDWARE_STAT_EVENTS[:2],
                event_source="hardware_required",
                max_output_bytes=8 << 20,
            ),
            policy=policy,
            capabilities=capabilities,
        )
        _require_allowed_plan(hardware_plan)
        try:
            hardware_collection = client.collect(hardware_plan)
        except PerfLensError as exc:
            if exc.code not in {ErrorCode.EXTERNAL_TOOL_FAILED, ErrorCode.PROFILE_PARSE_FAILED}:
                raise
            hardware_reason = "hardware_collection_failed"
        hardware_metrics = (
            _positive_measured_metrics(hardware_collection, HARDWARE_STAT_EVENTS)
            if hardware_collection is not None
            else ()
        )
        if hardware_collection is not None and not hardware_metrics:
            hardware_reason = "hardware_collection_produced_no_usable_counts"

        plan = create_collection_plan(
            CollectionPlanRequest(
                mode="stat",
                pid=process.pid,
                duration_seconds=duration_seconds,
                event_source="software_only",
                max_output_bytes=8 << 20,
            ),
            policy=policy,
            capabilities=capabilities,
        )
        _require_allowed_plan(plan)
        collection = client.collect(plan)
        measured_metrics = _positive_measured_metrics(collection, SOFTWARE_STAT_EVENTS)
        if not measured_metrics:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "collector_acceptance",
                "Collector acceptance produced no measured software perf stat metrics",
                recoverable=True,
                details={
                    "collection_id": collection.collection_id,
                    "metric_statuses": [metric.status for metric in collection.metrics],
                },
                suggested_actions=(
                    "Inspect software perf event support and the Collector journal, then retry.",
                ),
            )

        sampling_plan = create_collection_plan(
            CollectionPlanRequest(
                mode="record",
                pid=process.pid,
                duration_seconds=duration_seconds,
                event_source="software_only",
                max_output_bytes=8 << 20,
            ),
            policy=policy,
            capabilities=capabilities,
        )
        _require_allowed_plan(sampling_plan)
        sampling_collection = client.collect(sampling_plan)

        trace_acceptance = (
            _accept_trace_modes(
                client,
                process.pid,
                duration_seconds=duration_seconds,
                policy=policy,
                capabilities=capabilities,
            )
            if feature_profile == "full_diagnostics"
            else ()
        )

        identity = "\0".join(
            (
                collection.collection_id,
                str(plan.target_pid),
                str(plan.target_start_time_ticks),
                str(socket_path),
            )
        )
        hardware_available = hardware_reason is None
        hardware_collection_id = (
            hardware_collection.collection_id if hardware_collection is not None else None
        )
        warnings = [*plan.warnings, *collection.warnings, *sampling_collection.warnings]
        if not hardware_available:
            warnings.append(
                "硬件 PMU 当前不可用; PerfLens 已验证软件计数与 cpu-clock 采样, 性能优化仍可继续, "
                "但不能据此判断 IPC、硬件缓存未命中或分支未命中。"
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
            hardware_pmu_status="available" if hardware_available else "unavailable",
            hardware_pmu_reason=hardware_reason,
            software_counting_status="available",
            software_sampling_status="available",
            hardware_collection_id=hardware_collection_id,
            software_sampling_collection_id=sampling_collection.collection_id,
            feature_profile=feature_profile,
            trace_backend_status=(
                "available" if feature_profile == "full_diagnostics" else "not_requested"
            ),
            trace_modes=trace_acceptance,
            started_at=collection.started_at,
            finished_at=collection.finished_at,
            warnings=tuple(warnings),
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


def _collector_client(socket_path: Path, duration_seconds: float) -> CollectorBrokerClient:
    try:
        return CollectorBrokerClient(
            socket_path,
            timeout_seconds=duration_seconds + 15,
        )
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_acceptance",
            "Collector socket must be an existing absolute Unix socket",
            recoverable=True,
            details={"socket": str(socket_path)},
        ) from exc


def _require_allowed_plan(plan: CollectionPlanArtifact) -> None:
    if plan.policy_status != "allowed":
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_acceptance",
            "Collector acceptance plan was denied",
            recoverable=True,
            details={"warnings": list(plan.warnings)},
        )


def _positive_measured_metrics(
    collection: CollectionArtifact,
    allowed_events: tuple[str, ...],
) -> tuple[PerfStatMetric, ...]:
    return tuple(
        metric
        for metric in collection.metrics
        if metric.event in allowed_events
        and metric.status == "measured"
        and metric.value is not None
        and metric.value > 0
    )


def _accept_trace_modes(
    client: CollectorBrokerClient,
    pid: int,
    *,
    duration_seconds: float,
    policy: AutomaticCollectionPolicy,
    capabilities: CollectionCapabilityArtifact,
) -> tuple[CollectorTraceModeAcceptance, ...]:
    results: list[CollectorTraceModeAcceptance] = []
    for mode in ("sched", "off_cpu", "lock"):
        plan = create_collection_plan(
            CollectionPlanRequest(
                mode=mode,
                pid=pid,
                duration_seconds=duration_seconds,
                event_source="hardware_required",
                max_output_bytes=8 << 20,
            ),
            policy=policy,
            capabilities=capabilities,
        )
        _require_allowed_plan(plan)
        evidence = client.collect_trace(plan)
        analysis = build_trace_analysis(evidence)
        verification = verify_trace_analysis_artifact(analysis, evidence)
        require_usable_trace_analysis(verification)
        verification_status = verification.verification_status
        if verification_status == "failed":
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_acceptance",
                "Trace verification failure escaped the acceptance gate",
            )
        _require_substantive_trace(mode, evidence, analysis)
        results.append(
            CollectorTraceModeAcceptance(
                mode=mode,
                trace_evidence_id=evidence.trace_evidence_id,
                evidence_status=evidence.status,
                emitted_event_count=evidence.quality.emitted_event_count,
                analysis_id=_trace_analysis_id(analysis),
                analysis_status=analysis.status,
                verification_id=verification.verification_id,
                verification_status=verification_status,
            )
        )
    return tuple(results)


def _require_substantive_trace(
    mode: str,
    evidence: TraceEvidenceArtifact,
    analysis: SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact,
) -> None:
    if mode == "sched":
        substantive = (
            isinstance(analysis, SchedulerAnalysisArtifact)
            and analysis.total_context_switch_count > 0
        )
    elif mode == "off_cpu":
        substantive = isinstance(analysis, OffCpuAnalysisArtifact) and (
            analysis.total_complete_interval_count + analysis.total_incomplete_interval_count > 0
        )
    else:
        substantive = isinstance(analysis, LockAnalysisArtifact) and (
            analysis.total_exact_wait_count + analysis.total_candidate_wait_event_count > 0
        )
    if evidence.quality.emitted_event_count <= 0 or not substantive:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "collector_acceptance",
            f"Advanced Collector {mode} acceptance produced no substantive target evidence",
            recoverable=True,
            details={
                "mode": mode,
                "trace_evidence_id": evidence.trace_evidence_id,
                "emitted_event_count": evidence.quality.emitted_event_count,
            },
            suggested_actions=(
                "Inspect the Trace Helper capability, BTF, policy, and journal, then retry.",
            ),
        )


def _trace_analysis_id(
    analysis: SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact,
) -> str:
    if isinstance(analysis, SchedulerAnalysisArtifact):
        return analysis.scheduler_analysis_id
    if isinstance(analysis, OffCpuAnalysisArtifact):
        return analysis.off_cpu_analysis_id
    return analysis.lock_analysis_id


def _stop_probe(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
