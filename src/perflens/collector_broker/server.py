"""Minimal Unix-socket service for policy-bounded privileged collection."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import math
import os
import shutil
import signal
import socket
import stat
import struct
import sys
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType
from typing import Literal

from pydantic import ValidationError

from perflens import __version__
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    DEFAULT_RECORD_EVENT,
    HARDWARE_STAT_EVENTS,
    PID_ATTACH_AUTHORIZATION,
    SOFTWARE_RECORD_EVENT,
    SOFTWARE_STAT_EVENTS,
    CollectionRequest,
    CollectionTarget,
    collect_profile,
)
from perflens.collection.planning import assert_plan_current
from perflens.collector_broker.policy import (
    CollectorBrokerPolicy,
    load_broker_policy,
    validate_broker_policy,
)
from perflens.collector_broker.protocol import (
    BROKER_REQUEST_ADAPTER,
    MAX_BROKER_MESSAGE_BYTES,
    BrokerCollectRequest,
    BrokerError,
    BrokerHealthRequest,
    BrokerResponse,
)
from perflens.collector_broker.state import (
    collection_artifact_name,
    replay_marker,
    replay_marker_name,
    safe_replay_marker_metadata,
)
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionPlanArtifact,
    CollectorHealthArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError, stable_error_id
from perflens.metrics.perf_stat import PerfStatMetricAdapter
from perflens.privileged_helper.client import HelperClient
from perflens.privileged_helper.protocol import HelperCollectionResult

_PEER_CREDENTIALS = struct.Struct("3i")
_MAX_TRACKED_PLANS = 4096
_MAX_REQUEST_FRAME_TIMEOUT_SECONDS = 5.0
_MAX_OPERATIONAL_EVENT_BYTES = 2048
_LOGGER = logging.getLogger("perflens.collector")
_LOGGER.addHandler(logging.NullHandler())
_LOGGER.propagate = False
_HELPER_SOCKET = Path("/run/perflens-helper/helper.sock")
_HELPER_SPOOL_ROOT = Path("/var/lib/perflens-helper")
_ROOT_UID = 0
_HARDWARE_PROBE_MINIMUM_PLAN_SECONDS = 0.3
_HARDWARE_PROBE_MAX_SECONDS = 0.25
_HARDWARE_PROBE_EVENTS = HARDWARE_STAT_EVENTS[:2]
_POST_PROBE_FALLBACK_MINIMUM_SECONDS = 0.05


class CollectorBrokerServer:
    """Sequential broker whose only mutating operation is collect a verified PID."""

    def __init__(
        self,
        socket_path: Path,
        policy: CollectorBrokerPolicy,
        *,
        request_timeout_seconds: float = _MAX_REQUEST_FRAME_TIMEOUT_SECONDS,
        helper_client: HelperClient | None = None,
        helper_spool_root: Path = _HELPER_SPOOL_ROOT,
        expected_helper_uid: int = _ROOT_UID,
    ) -> None:
        if (
            isinstance(request_timeout_seconds, bool)
            or not math.isfinite(request_timeout_seconds)
            or request_timeout_seconds <= 0
            or request_timeout_seconds > _MAX_REQUEST_FRAME_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "Collector request timeout must be finite, positive, and no greater than "
                f"{_MAX_REQUEST_FRAME_TIMEOUT_SECONDS:g} seconds"
            )
        self._policy = validate_broker_policy(policy)
        self._helper_client = helper_client
        self._helper_spool_root = helper_spool_root
        self._expected_helper_uid = expected_helper_uid
        if self._policy.privilege_mode == "paranoid3_helper" and self._helper_client is None:
            self._helper_client = HelperClient(
                _HELPER_SOCKET,
                expected_helper_uid=expected_helper_uid,
                timeout_seconds=45,
            )
            self._helper_client.health()
        self._socket_path = _new_socket_path(socket_path)
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.bind(str(self._socket_path))
            os.chmod(self._socket_path, self._policy.socket_mode)
            self._socket.listen(8)
            self._socket.settimeout(0.5)
        except BaseException:
            self._socket.close()
            self._socket_path.unlink(missing_ok=True)
            raise

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            self.serve_once()

    def serve_once(self) -> None:
        try:
            connection, _ = self._socket.accept()
        except TimeoutError:
            return
        except OSError:
            if self._stop.is_set():
                return
            raise
        with connection:
            connection.settimeout(self._request_timeout_seconds)
            self._handle_connection(connection)

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._socket_path.unlink(missing_ok=True)

    def __enter__(self) -> CollectorBrokerServer:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _handle_connection(self, connection: socket.socket) -> None:
        request_id = "unknown"
        peer_uid = -1
        operation = "unknown"
        plan_id: str | None = None
        failure: PerfLensError | None = None
        try:
            peer_uid = _peer_uid(connection)
            payload = _read_frame(connection)
            request = BROKER_REQUEST_ADAPTER.validate_json(payload)
            request_id = request.request_id
            operation = request.operation
            if isinstance(request, BrokerHealthRequest):
                artifact = self._health(peer_uid)
            else:
                plan_id = request.plan.plan_id
                artifact = self._collect(peer_uid, request)
                _emit_operational_event(
                    logging.INFO,
                    "collection_completed",
                    request_id=request_id,
                    operation=operation,
                    plan_id=plan_id,
                    peer_uid=peer_uid,
                    mode=artifact.mode,
                    output_bytes=artifact.output_bytes,
                )
            response = BrokerResponse(
                request_id=request_id,
                ok=True,
                result=artifact.model_dump(mode="json"),
            )
        except PerfLensError as exc:
            failure = exc
            response = _error_response(request_id, exc)
        except ValidationError:
            failure = PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collector_broker",
                "Collector broker request failed schema validation",
                recoverable=True,
            )
            response = _error_response(request_id, failure)
        except Exception:
            failure = PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_broker",
                "Collector broker encountered an internal error",
            )
            response = _error_response(request_id, failure)
        if failure is not None:
            _emit_operational_event(
                logging.ERROR if failure.code is ErrorCode.INTERNAL_ERROR else logging.WARNING,
                "request_rejected",
                request_id=request_id,
                operation=operation,
                plan_id=plan_id,
                peer_uid=peer_uid,
                error_id=stable_error_id(failure),
                error_code=failure.code.value,
                stage=failure.stage,
                recoverable=failure.recoverable,
            )
        encoded = response.model_dump_json().encode("utf-8") + b"\n"
        if len(encoded) <= MAX_BROKER_MESSAGE_BYTES:
            with suppress(OSError):
                connection.sendall(encoded)

    def _collect(self, peer_uid: int, request: BrokerCollectRequest) -> CollectionArtifact:
        plan = request.plan
        self._authorize(peer_uid, plan)
        assert_plan_current(plan)
        effective_plan = self._narrow_fallback_to_collector_policy(plan)
        if self._policy.privilege_mode == "paranoid3_helper":
            artifact = self._collect_with_helper(peer_uid, effective_plan)
        else:
            self._authorize_spool_capacity(effective_plan)
            self._consume_plan(effective_plan)
            artifact = self._collect_with_cap_perfmon(effective_plan)
        if plan.fallback_allowed and not effective_plan.fallback_allowed:
            return artifact.model_copy(
                update={
                    "warnings": (
                        *artifact.warnings,
                        "Software fallback is disabled by Collector policy; this execution "
                        "required hardware evidence.",
                    )
                }
            )
        return artifact

    def _narrow_fallback_to_collector_policy(
        self,
        plan: CollectionPlanArtifact,
    ) -> CollectionPlanArtifact:
        if not plan.fallback_allowed or self._policy.allow_software_fallback:
            return plan
        return plan.model_copy(
            update={
                "fallback_allowed": False,
                "fallback_events": (),
                "fallback_record_event": None,
            }
        )

    def _collect_with_cap_perfmon(self, plan: CollectionPlanArtifact) -> CollectionArtifact:
        events = plan.events or self._policy.allowed_stat_events
        record_event: Literal["cycles", "cpu-clock"] = plan.record_event or DEFAULT_RECORD_EVENT
        duration_seconds = plan.duration_seconds
        fallback_used = False
        fallback_reason = None
        if plan.requested_event_source == "software_only":
            events = plan.events or SOFTWARE_STAT_EVENTS
            record_event = plan.record_event or SOFTWARE_RECORD_EVENT
        elif plan.fallback_allowed:
            use_hardware, fallback_reason, probe_seconds = self._probe_hardware_pmu(plan)
            duration_seconds -= probe_seconds
            if not use_hardware:
                fallback_used = True
                events = plan.fallback_events
                record_event = plan.fallback_record_event or SOFTWARE_RECORD_EVENT
        suffix = ".stat.csv" if plan.mode == "stat" else ".perf.data"
        output_path = self._policy.spool_root / f"{plan.plan_id}{suffix}"

        def execute_selected_profile() -> CollectionArtifact:
            # Probe and failed-attempt time create another PID-reuse/expiry boundary. Recheck the
            # original owner/start-time binding before every formal hardware or software attempt.
            assert_plan_current(plan)
            return collect_profile(
                CollectionRequest(
                    mode=plan.mode,
                    target=CollectionTarget(
                        pid=plan.target_pid,
                        duration_seconds=duration_seconds,
                    ),
                    output_path=output_path,
                    authorization=ACTIVE_COLLECTION_AUTHORIZATION,
                    pid_authorization=PID_ATTACH_AUTHORIZATION,
                    perf_path=self._policy.perf_path,
                    frequency_hz=plan.frequency_hz or 99,
                    call_graph=plan.call_graph or "dwarf",
                    events=events,
                    record_event=record_event,
                    requested_event_source=plan.requested_event_source,
                    fallback_used=fallback_used,
                    fallback_reason=fallback_reason,
                    timeout_seconds=min(duration_seconds + 10, 86_400),
                    max_output_bytes=plan.max_output_bytes,
                )
            )

        hardware_started = time.monotonic()
        try:
            artifact = execute_selected_profile()
        except PerfLensError as exc:
            remaining_seconds = duration_seconds - (time.monotonic() - hardware_started)
            if (
                plan.requested_event_source != "auto"
                or not plan.fallback_allowed
                or fallback_used
                or exc.code not in {ErrorCode.EXTERNAL_TOOL_FAILED, ErrorCode.PROFILE_PARSE_FAILED}
                or remaining_seconds < _POST_PROBE_FALLBACK_MINIMUM_SECONDS
            ):
                raise
            duration_seconds = remaining_seconds
            fallback_used = True
            fallback_reason = "hardware_execution_failed_after_probe"
            events = plan.fallback_events
            record_event = plan.fallback_record_event or SOFTWARE_RECORD_EVENT
            artifact = execute_selected_profile()
        try:
            os.chmod(artifact.output_path, self._policy.artifact_mode)
        except OSError as exc:
            Path(artifact.output_path).unlink(missing_ok=True)
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "collector_broker",
                "Unable to apply the configured collection artifact permissions",
                details={"path": artifact.output_path},
            ) from exc
        return artifact

    def _probe_hardware_pmu(
        self,
        plan: CollectionPlanArtifact,
    ) -> tuple[bool, str | None, float]:
        if plan.duration_seconds < _HARDWARE_PROBE_MINIMUM_PLAN_SECONDS:
            return False, "hardware_probe_skipped_for_short_collection", 0.0
        probe_seconds = min(_HARDWARE_PROBE_MAX_SECONDS, plan.duration_seconds / 4)
        probe_path = self._socket_path.parent / f".perflens-pmu-probe-{plan.plan_id}.stat.csv"
        probe_path.unlink(missing_ok=True)
        try:
            try:
                artifact = collect_profile(
                    CollectionRequest(
                        mode="stat",
                        target=CollectionTarget(
                            pid=plan.target_pid,
                            duration_seconds=probe_seconds,
                        ),
                        output_path=probe_path,
                        authorization=ACTIVE_COLLECTION_AUTHORIZATION,
                        pid_authorization=PID_ATTACH_AUTHORIZATION,
                        perf_path=self._policy.perf_path,
                        events=_HARDWARE_PROBE_EVENTS,
                        requested_event_source="hardware_required",
                        timeout_seconds=min(probe_seconds + 10, 86_400),
                        max_output_bytes=min(plan.max_output_bytes, 1 << 20),
                    )
                )
            except PerfLensError as exc:
                if exc.code not in {ErrorCode.EXTERNAL_TOOL_FAILED, ErrorCode.PROFILE_PARSE_FAILED}:
                    raise
                return False, "hardware_probe_failed", probe_seconds
            usable = any(
                metric.status == "measured"
                and metric.value is not None
                and metric.value > 0
                and metric.event in _HARDWARE_PROBE_EVENTS
                for metric in artifact.metrics
            )
            return (
                (True, None, probe_seconds)
                if usable
                else (False, "hardware_probe_produced_no_usable_counts", probe_seconds)
            )
        finally:
            probe_path.unlink(missing_ok=True)

    def _collect_with_helper(
        self,
        peer_uid: int,
        plan: CollectionPlanArtifact,
    ) -> CollectionArtifact:
        helper = self._helper_client
        if helper is None:
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "privileged_helper",
                "Privileged Helper client was not initialized",
            )
        result = helper.collect(plan, caller_uid=peer_uid)
        output_path = self._verify_helper_artifact(plan, result)
        metrics, warnings = (
            PerfStatMetricAdapter().parse(output_path) if plan.mode == "stat" else ((), ())
        )
        started = datetime.fromtimestamp(
            result.started_at_unix_milliseconds / 1000,
            tz=UTC,
        )
        finished = datetime.fromtimestamp(
            result.finished_at_unix_milliseconds / 1000,
            tz=UTC,
        )
        identity = f"{plan.plan_id}\0{result.output_sha256}\0paranoid3_helper"
        return CollectionArtifact(
            collection_id=f"collection-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
            mode=plan.mode,
            target_type="pid",
            target_argument_count=0,
            target_pid=plan.target_pid,
            output_path=str(output_path),
            output_sha256=result.output_sha256,
            output_bytes=result.output_bytes,
            output_format=result.output_format,
            output_owner_uid=self._expected_helper_uid,
            perf_executable=str(self._policy.perf_path),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=max(0.0, (finished - started).total_seconds()),
            frequency_hz=plan.frequency_hz if plan.mode == "record" else None,
            call_graph=plan.call_graph if plan.mode == "record" else None,
            events=result.events if plan.mode == "stat" else (),
            requested_event_source=plan.requested_event_source,
            actual_event_source=result.actual_event_source,
            fallback_used=result.fallback_used,
            fallback_reason=result.fallback_reason,
            evidence_limitations=(
                (
                    "instructions-per-cycle unavailable",
                    "hardware cache-miss evidence unavailable",
                    "hardware branch-miss evidence unavailable",
                )
                if result.actual_event_source == "software"
                else ()
            ),
            metrics=metrics,
            warnings=(
                *warnings,
                *(
                    (
                        "Hardware PMU evidence was unavailable; PerfLens continued with software "
                        "events.",
                    )
                    if result.fallback_used
                    else ()
                ),
            ),
        )

    def _verify_helper_artifact(
        self,
        plan: CollectionPlanArtifact,
        result: HelperCollectionResult,
    ) -> Path:
        candidate = self._helper_spool_root / result.artifact_name
        descriptor = -1
        try:
            root = self._helper_spool_root.resolve(strict=True)
            root_metadata = root.stat(follow_symlinks=False)
            if (
                root != self._helper_spool_root
                or not stat.S_ISDIR(root_metadata.st_mode)
                or root_metadata.st_uid != self._expected_helper_uid
                or root_metadata.st_mode & 0o022
            ):
                raise _unsafe_helper_artifact()
            descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != self._expected_helper_uid
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or metadata.st_size != result.output_bytes
                or candidate.parent / result.artifact_name != candidate
            ):
                raise _unsafe_helper_artifact()
            digest = hashlib.sha256()
            total = 0
            while chunk := os.read(descriptor, min(1 << 20, result.output_bytes - total + 1)):
                total += len(chunk)
                if total > result.output_bytes:
                    raise _unsafe_helper_artifact()
                digest.update(chunk)
            if total != result.output_bytes or digest.hexdigest() != result.output_sha256:
                raise _unsafe_helper_artifact()
        except PerfLensError:
            raise
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "privileged_helper",
                "Privileged Helper artifact cannot be verified",
                recoverable=True,
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        expected_name = (
            f"{plan.plan_id}.stat.csv" if plan.mode == "stat" else f"{plan.plan_id}.perf.data"
        )
        if result.artifact_name != expected_name:
            raise _unsafe_helper_artifact()
        return candidate

    def _health(self, peer_uid: int) -> CollectorHealthArtifact:
        if peer_uid != 0 and peer_uid not in self._policy.allowed_uids:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Peer UID is not allowed to inspect Collector health",
                recoverable=True,
            )
        return CollectorHealthArtifact(
            perflens_version=__version__,
            policy_version=self._policy.policy_version,
            service_pid=os.getpid(),
            service_uid=os.geteuid(),
            peer_uid=peer_uid,
            allowed_modes=tuple(self._policy.allowed_modes),
            spool_root=str(
                self._helper_spool_root
                if self._policy.privilege_mode == "paranoid3_helper"
                else self._policy.spool_root
            ),
            privilege_mode=self._policy.privilege_mode,
        )

    def _authorize(self, peer_uid: int, plan: CollectionPlanArtifact) -> None:
        if peer_uid not in self._policy.allowed_uids:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Peer UID is not allowed by collector policy",
                recoverable=True,
            )
        if plan.mode not in self._policy.allowed_modes:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collection mode is not allowed by collector policy",
                recoverable=True,
            )
        if not self._policy.allow_other_target_uids and plan.target_uid != peer_uid:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collector policy only permits targets owned by the requesting UID",
                recoverable=True,
            )
        if plan.duration_seconds > self._policy.max_duration_seconds:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collection duration exceeds collector policy",
                recoverable=True,
            )
        if plan.frequency_hz is not None and plan.frequency_hz > self._policy.max_frequency_hz:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Sampling frequency exceeds collector policy",
                recoverable=True,
            )
        if plan.max_output_bytes > self._policy.max_output_bytes:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Output size exceeds collector policy",
                recoverable=True,
            )
        expires_at = _plan_expiration(plan)
        if expires_at > datetime.now(tz=UTC) + timedelta(seconds=self._policy.max_plan_ttl_seconds):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collection plan lifetime exceeds collector policy",
                recoverable=True,
            )
        if plan.mode == "stat" and any(
            event not in self._policy.allowed_stat_events for event in plan.events
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "perf stat event is not allowed by collector policy",
                recoverable=True,
            )
        if self._policy.allow_software_fallback and plan.mode == "stat" and any(
            event not in self._policy.allowed_stat_events for event in plan.fallback_events
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "perf stat fallback event is not allowed by collector policy",
                recoverable=True,
            )
        if plan.fallback_allowed and plan.requested_event_source != "auto":
            raise _unsafe_event_source_plan()
        if plan.mode == "stat":
            if plan.record_event is not None or plan.fallback_record_event is not None:
                raise _unsafe_event_source_plan()
            if plan.requested_event_source == "software_only" and tuple(plan.events) != tuple(
                SOFTWARE_STAT_EVENTS
            ):
                raise _unsafe_event_source_plan()
            if plan.requested_event_source != "software_only" and (
                not plan.events or any(event not in HARDWARE_STAT_EVENTS for event in plan.events)
            ):
                raise _unsafe_event_source_plan()
            if plan.fallback_allowed and tuple(plan.fallback_events) != tuple(
                SOFTWARE_STAT_EVENTS
            ):
                raise _unsafe_event_source_plan()
            if not plan.fallback_allowed and plan.fallback_events:
                raise _unsafe_event_source_plan()
        elif plan.mode == "record":
            if plan.events or plan.fallback_events:
                raise _unsafe_event_source_plan()
            expected_record_event = (
                SOFTWARE_RECORD_EVENT
                if plan.requested_event_source == "software_only"
                else DEFAULT_RECORD_EVENT
            )
            if plan.record_event != expected_record_event:
                raise _unsafe_event_source_plan()
            if plan.fallback_allowed != (plan.fallback_record_event == SOFTWARE_RECORD_EVENT):
                raise _unsafe_event_source_plan()
        elif (
            plan.requested_event_source != "hardware_required"
            or plan.fallback_allowed
            or plan.fallback_events
            or plan.record_event is not None
            or plan.fallback_record_event is not None
        ):
            raise _unsafe_event_source_plan()

    def _authorize_spool_capacity(self, plan: CollectionPlanArtifact) -> None:
        artifact_count = 0
        spool_bytes = 0
        try:
            spool_metadata = self._policy.spool_root.stat(follow_symlinks=False)
            with os.scandir(self._policy.spool_root) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    if replay_marker(entry.name):
                        if not safe_replay_marker_metadata(
                            metadata,
                            expected_uid=spool_metadata.st_uid,
                            expected_gid=spool_metadata.st_gid,
                        ):
                            raise PerfLensError(
                                ErrorCode.PATH_SAFETY_VIOLATION,
                                "collector_broker",
                                "Collector spool contains an unsafe replay marker",
                                recoverable=True,
                                details={"entry": entry.name},
                            )
                        continue
                    if not collection_artifact_name(entry.name) or not entry.is_file(
                        follow_symlinks=False
                    ):
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            "collector_broker",
                            "Collector spool contains an unmanaged or non-regular entry",
                            recoverable=True,
                            details={"entry": entry.name},
                        )
                    artifact_count += 1
                    if artifact_count >= self._policy.max_spool_artifacts:
                        raise PerfLensError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "collector_broker",
                            "Collector spool artifact-count quota is exhausted",
                            recoverable=True,
                        )
                    spool_bytes += metadata.st_size
                    if spool_bytes + plan.max_output_bytes > self._policy.max_spool_bytes:
                        raise PerfLensError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "collector_broker",
                            "Collector spool byte quota cannot reserve the requested output",
                            recoverable=True,
                        )
            free_bytes = shutil.disk_usage(self._policy.spool_root).free
        except PerfLensError:
            raise
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "collector_broker",
                "Unable to inspect Collector spool capacity",
                recoverable=True,
            ) from exc
        if free_bytes - plan.max_output_bytes < self._policy.min_free_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector filesystem free-space reserve would be violated",
                recoverable=True,
            )

    def _consume_plan(self, plan: CollectionPlanArtifact) -> None:
        _persist_consumed_plan(self._policy, plan, now=datetime.now(tz=UTC))


def _persist_consumed_plan(
    policy: CollectorBrokerPolicy,
    plan: CollectionPlanArtifact,
    *,
    now: datetime,
) -> None:
    spool_descriptor = -1
    marker_descriptor = -1
    marker_name = replay_marker_name(plan.plan_id)
    try:
        spool_descriptor = os.open(
            policy.spool_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        spool_metadata = os.fstat(spool_descriptor)
        path_metadata = policy.spool_root.stat(follow_symlinks=False)
        if (
            spool_metadata.st_uid != os.geteuid()
            or spool_metadata.st_mode & 0o022
            or (spool_metadata.st_dev, spool_metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector spool identity or permissions changed after policy validation",
                recoverable=True,
            )
        fcntl.flock(spool_descriptor, fcntl.LOCK_EX)
        active_markers = _prune_replay_markers(
            spool_descriptor,
            preserve_name=marker_name,
            expected_uid=spool_metadata.st_uid,
            expected_gid=spool_metadata.st_gid,
            cutoff=now - timedelta(seconds=policy.max_plan_ttl_seconds),
        )
        if active_markers >= _MAX_TRACKED_PLANS:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker replay state reached its bounded capacity",
                recoverable=True,
            )
        try:
            marker_descriptor = os.open(
                marker_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=spool_descriptor,
            )
        except FileExistsError as exc:
            raise _replayed_plan(plan.plan_id) from exc
        marker_metadata = os.fstat(marker_descriptor)
        if not safe_replay_marker_metadata(
            marker_metadata,
            expected_uid=spool_metadata.st_uid,
            expected_gid=spool_metadata.st_gid,
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "Collector could not create a safe replay marker",
                recoverable=True,
            )
        os.fsync(marker_descriptor)
        os.close(marker_descriptor)
        marker_descriptor = -1
        os.fsync(spool_descriptor)
    except PerfLensError:
        raise
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collector_broker",
            "Collector could not persist single-use plan state",
            recoverable=True,
            details={"plan_id": plan.plan_id},
        ) from exc
    finally:
        if marker_descriptor >= 0:
            os.close(marker_descriptor)
        if spool_descriptor >= 0:
            os.close(spool_descriptor)


def _prune_replay_markers(
    spool_descriptor: int,
    *,
    preserve_name: str,
    expected_uid: int,
    expected_gid: int,
    cutoff: datetime,
) -> int:
    active_markers = 0
    removed_marker = False
    with os.scandir(spool_descriptor) as entries:
        for entry in entries:
            if not replay_marker(entry.name):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if not safe_replay_marker_metadata(
                metadata,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "collector_broker",
                    "Collector spool contains an unsafe replay marker",
                    recoverable=True,
                    details={"entry": entry.name},
                )
            if entry.name == preserve_name:
                raise _replayed_plan(preserve_name.removeprefix(".perflens-consumed-"))
            if metadata.st_mtime_ns <= int(cutoff.timestamp() * 1_000_000_000):
                os.unlink(entry.name, dir_fd=spool_descriptor)
                removed_marker = True
            else:
                active_markers += 1
    if removed_marker:
        os.fsync(spool_descriptor)
    return active_markers


def _replayed_plan(plan_id: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "authorization",
        "Collection plan was already consumed by the collector broker",
        recoverable=True,
        details={"plan_id": plan_id},
    )


def _error_response(request_id: str, error: PerfLensError) -> BrokerResponse:
    return BrokerResponse(
        request_id=request_id,
        ok=False,
        error=BrokerError(
            code=error.code.value,
            stage=error.stage,
            message=error.message,
            recoverable=error.recoverable,
        ),
    )


def _unsafe_helper_artifact() -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "privileged_helper",
        "Privileged Helper artifact identity, permissions, or digest are unsafe",
        recoverable=True,
    )


def _unsafe_event_source_plan() -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "authorization",
        "Collection event-source or fallback fields violate the fixed broker policy",
        recoverable=True,
    )


def _configure_operational_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.handlers[:] = [handler]
    _LOGGER.setLevel(logging.INFO)


def _emit_operational_event(level: int, event: str, **fields: object) -> None:
    payload: dict[str, object] = {
        "event_schema_version": "1.0",
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "severity": logging.getLevelName(level).lower(),
        "event": event,
    }
    payload.update({name: value for name, value in fields.items() if value is not None})
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > _MAX_OPERATIONAL_EVENT_BYTES:
        encoded = json.dumps(
            {
                "event_schema_version": "1.0",
                "timestamp": payload["timestamp"],
                "severity": "error",
                "event": "operational_event_truncated",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    _LOGGER.log(level, encoded)


def _new_socket_path(path: Path) -> Path:
    if not path.expanduser().is_absolute():
        raise ValueError("Collector socket path must be absolute")
    parent = path.expanduser().parent.resolve(strict=True)
    metadata = parent.stat()
    if not parent.is_dir() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise ValueError(
            "Collector socket directory must be owned by the service UID and not group/world "
            "writable"
        )
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("Collector socket path already exists")
    return candidate


def _peer_uid(connection: socket.socket) -> int:
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size)
        _pid, uid, _gid = _PEER_CREDENTIALS.unpack(raw)
        return uid
    except (AttributeError, OSError, struct.error) as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "authorization",
            "Unable to authenticate collector broker peer credentials",
        ) from exc


def _read_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        remaining = MAX_BROKER_MESSAGE_BYTES - len(received)
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker request exceeds the protocol limit",
            )
        try:
            chunk = connection.recv(min(16 << 10, remaining))
        except TimeoutError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collector_broker",
                "Collector broker request timed out before a complete frame",
                recoverable=True,
            ) from exc
        if not chunk:
            break
        received.extend(chunk)
    line, separator, trailing = bytes(received).partition(b"\n")
    if not separator or trailing:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_broker",
            "Collector broker requires exactly one newline-delimited request",
            recoverable=True,
        )
    return line


def _plan_expiration(plan: CollectionPlanArtifact) -> datetime:
    try:
        expiration = datetime.fromisoformat(plan.expires_at)
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection plan has an invalid expiration timestamp",
        ) from exc
    if expiration.tzinfo is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collection_plan",
            "Collection plan expiration timestamp must include a timezone",
        )
    return expiration


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the restricted PerfLens collector broker")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    arguments = parser.parse_args()
    _configure_operational_logging()
    started = False
    try:
        policy = load_broker_policy(arguments.policy)
        with CollectorBrokerServer(arguments.socket, policy) as server:

            def close_server(_signum: int, _frame: FrameType | None) -> None:
                server.close()

            signal.signal(signal.SIGTERM, close_server)
            signal.signal(signal.SIGINT, close_server)
            started = True
            _emit_operational_event(
                logging.INFO,
                "collector_started",
                service_pid=os.getpid(),
                service_uid=os.geteuid(),
                perflens_version=__version__,
                policy_version=policy.policy_version,
            )
            try:
                server.serve_forever()
            finally:
                server.close()
                _emit_operational_event(
                    logging.INFO,
                    "collector_stopped",
                    service_pid=os.getpid(),
                    service_uid=os.geteuid(),
                )
    except Exception as exc:
        if isinstance(exc, PerfLensError):
            failure = exc
        elif isinstance(exc, ValueError):
            failure = PerfLensError(
                ErrorCode.INVALID_INPUT,
                "collector_startup",
                "Collector startup validation failed",
            )
        else:
            failure = PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "collector_service" if started else "collector_startup",
                "Collector service failed unexpectedly" if started else "Collector startup failed",
            )
        _emit_operational_event(
            logging.ERROR,
            "collector_failed" if started else "collector_start_failed",
            error_id=stable_error_id(failure),
            error_code=failure.code.value,
            stage=failure.stage,
            recoverable=failure.recoverable,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
