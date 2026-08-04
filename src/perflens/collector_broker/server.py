"""Minimal Unix-socket service for policy-bounded privileged collection."""

from __future__ import annotations

import argparse
import fcntl
import math
import os
import shutil
import signal
import socket
import struct
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType

from pydantic import ValidationError

from perflens import __version__
from perflens.collection.collector import (
    ACTIVE_COLLECTION_AUTHORIZATION,
    PID_ATTACH_AUTHORIZATION,
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
from perflens.domain.errors import ErrorCode, PerfLensError

_PEER_CREDENTIALS = struct.Struct("3i")
_MAX_TRACKED_PLANS = 4096
_MAX_REQUEST_FRAME_TIMEOUT_SECONDS = 5.0


class CollectorBrokerServer:
    """Sequential broker whose only mutating operation is collect a verified PID."""

    def __init__(
        self,
        socket_path: Path,
        policy: CollectorBrokerPolicy,
        *,
        request_timeout_seconds: float = _MAX_REQUEST_FRAME_TIMEOUT_SECONDS,
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
        try:
            peer_uid = _peer_uid(connection)
            payload = _read_frame(connection)
            request = BROKER_REQUEST_ADAPTER.validate_json(payload)
            request_id = request.request_id
            if isinstance(request, BrokerHealthRequest):
                artifact = self._health(peer_uid)
            else:
                artifact = self._collect(peer_uid, request)
            response = BrokerResponse(
                request_id=request_id,
                ok=True,
                result=artifact.model_dump(mode="json"),
            )
        except PerfLensError as exc:
            response = BrokerResponse(
                request_id=request_id,
                ok=False,
                error={
                    "code": exc.code.value,
                    "stage": exc.stage,
                    "message": exc.message,
                    "recoverable": exc.recoverable,
                },
            )
        except ValidationError:
            response = BrokerResponse(
                request_id=request_id,
                ok=False,
                error={
                    "code": ErrorCode.INVALID_INPUT.value,
                    "stage": "collector_broker",
                    "message": "Collector broker request failed schema validation",
                    "recoverable": True,
                },
            )
        except Exception:
            response = BrokerResponse(
                request_id=request_id,
                ok=False,
                error={
                    "code": ErrorCode.INTERNAL_ERROR.value,
                    "stage": "collector_broker",
                    "message": "Collector broker encountered an internal error",
                    "recoverable": False,
                },
            )
        encoded = response.model_dump_json().encode("utf-8") + b"\n"
        if len(encoded) <= MAX_BROKER_MESSAGE_BYTES:
            with suppress(OSError):
                connection.sendall(encoded)

    def _collect(self, peer_uid: int, request: BrokerCollectRequest) -> CollectionArtifact:
        plan = request.plan
        self._authorize(peer_uid, plan)
        assert_plan_current(plan)
        self._authorize_spool_capacity(plan)
        self._consume_plan(plan)
        suffix = ".stat.csv" if plan.mode == "stat" else ".perf.data"
        output_path = self._policy.spool_root / f"{plan.plan_id}{suffix}"
        artifact = collect_profile(
            CollectionRequest(
                mode=plan.mode,
                target=CollectionTarget(
                    pid=plan.target_pid,
                    duration_seconds=plan.duration_seconds,
                ),
                output_path=output_path,
                authorization=ACTIVE_COLLECTION_AUTHORIZATION,
                pid_authorization=PID_ATTACH_AUTHORIZATION,
                perf_path=self._policy.perf_path,
                frequency_hz=plan.frequency_hz or 99,
                call_graph=plan.call_graph or "dwarf",
                events=plan.events or self._policy.allowed_stat_events,
                timeout_seconds=min(plan.duration_seconds + 10, 86_400),
                max_output_bytes=plan.max_output_bytes,
            )
        )
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
            spool_root=str(self._policy.spool_root),
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
    policy = load_broker_policy(arguments.policy)
    with CollectorBrokerServer(arguments.socket, policy) as server:

        def close_server(_signum: int, _frame: FrameType | None) -> None:
            server.close()

        signal.signal(signal.SIGTERM, close_server)
        signal.signal(signal.SIGINT, close_server)
        server.serve_forever()


if __name__ == "__main__":
    main()
