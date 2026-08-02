"""Minimal Unix-socket service for policy-bounded privileged collection."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    MAX_BROKER_MESSAGE_BYTES,
    BrokerCollectRequest,
    BrokerResponse,
)
from perflens.contracts.artifacts import CollectionArtifact, CollectionPlanArtifact
from perflens.domain.errors import ErrorCode, PerfLensError

_PEER_CREDENTIALS = struct.Struct("3i")
_MAX_TRACKED_PLANS = 4096


class CollectorBrokerServer:
    """Sequential broker whose only mutating operation is collect a verified PID."""

    def __init__(self, socket_path: Path, policy: CollectorBrokerPolicy) -> None:
        self._policy = validate_broker_policy(policy)
        self._socket_path = _new_socket_path(socket_path)
        self._stop = threading.Event()
        self._consumed_plans: dict[str, datetime] = {}
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
        with connection:
            connection.settimeout(self._policy.max_duration_seconds + 15)
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
            request = BrokerCollectRequest.model_validate_json(payload)
            request_id = request.request_id
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
        if expires_at > datetime.now(tz=UTC) + timedelta(
            seconds=self._policy.max_plan_ttl_seconds
        ):
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

    def _consume_plan(self, plan: CollectionPlanArtifact) -> None:
        now = datetime.now(tz=UTC)
        self._consumed_plans = {
            plan_id: expiration
            for plan_id, expiration in self._consumed_plans.items()
            if expiration > now
        }
        if plan.plan_id in self._consumed_plans:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Collection plan was already consumed by the collector broker",
                recoverable=True,
                details={"plan_id": plan.plan_id},
            )
        if len(self._consumed_plans) >= _MAX_TRACKED_PLANS:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker replay cache reached its bounded capacity",
                recoverable=True,
            )
        self._consumed_plans[plan.plan_id] = _plan_expiration(plan)


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
        remaining = MAX_BROKER_MESSAGE_BYTES + 1 - len(received)
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "collector_broker",
                "Collector broker request exceeds the protocol limit",
            )
        chunk = connection.recv(min(16 << 10, remaining))
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
    with CollectorBrokerServer(arguments.socket, policy) as server, suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
