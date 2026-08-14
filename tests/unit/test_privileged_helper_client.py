from __future__ import annotations

import json
import os
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest

import perflens.privileged_helper as privileged_helper
from perflens.contracts.artifacts import CollectionPlanArtifact
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.privileged_helper.client import HelperClient
from perflens.privileged_helper.protocol import (
    HELPER_SCHEMA_VERSION,
    HelperCollectionReadyResult,
    HelperCollectionResult,
    HelperErrorBody,
    HelperHealthResult,
    HelperResponse,
)


def test_privileged_helper_package_lazily_exports_only_helper_client() -> None:
    assert privileged_helper.HelperClient is HelperClient
    with pytest.raises(AttributeError, match="not_exported"):
        privileged_helper.__getattr__("not_exported")


def test_helper_client_authenticates_health_peer_and_response(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            request = _read_frame(connection)
            request_id = request.decode("utf-8").split('"request_id":"', 1)[1].split('"', 1)[0]
            response = HelperResponse(
                schema_version=HELPER_SCHEMA_VERSION,
                request_id=request_id,
                ok=True,
                result=HelperHealthResult(
                    kind="health",
                    helper_version="0.2.0",
                    helper_pid=os.getpid(),
                    helper_uid=os.geteuid(),
                    privilege_mode="paranoid3_helper",
                    ready=True,
                ),
            )
            connection.sendall(response.model_dump_json().encode("utf-8") + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = HelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
        ).health()
    finally:
        server.join(timeout=2)
        listener.close()
    assert result.ready is True
    assert result.helper_uid == os.geteuid()


def test_helper_client_rejects_unsafe_socket_permissions(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o666)
    listener.listen(1)
    try:
        with pytest.raises(PerfLensError):
            HelperClient(socket_path, expected_helper_uid=os.geteuid()).health()
    finally:
        listener.close()


def test_helper_client_rejects_invalid_constructor_limits(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="UID"):
        HelperClient(tmp_path / "helper.sock", expected_helper_uid=-1)
    with pytest.raises(ValueError, match="45 seconds"):
        HelperClient(
            tmp_path / "helper.sock",
            expected_helper_uid=os.geteuid(),
            timeout_seconds=46,
        )


def _collection_plan(*, mode: Literal["stat", "sched"] = "stat") -> CollectionPlanArtifact:
    return CollectionPlanArtifact(
        plan_id="plan-0123456789abcdefabcd",
        mode=mode,
        target_type="pid",
        target_pid=1234,
        target_uid=os.geteuid(),
        target_start_time_ticks=5678,
        backend="privileged_broker",
        duration_seconds=1.0,
        events=("cycles",) if mode == "stat" else (),
        requested_event_source="hardware_required",
        max_output_bytes=1024,
        expires_at=(datetime.now(tz=UTC) + timedelta(seconds=30)).isoformat(),
        policy_status="allowed",
        required_privilege="cap_sys_admin_or_policy_change",
    )


def test_helper_client_submits_typed_collection_and_binds_result(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    plan = _collection_plan()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            request = _read_frame(connection)
            payload = json.loads(request)
            assert payload["operation"] == "collect_pid"
            assert payload["caller_uid"] == os.geteuid()
            assert payload["report_ready"] is False
            response = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionResult(
                    kind="collection",
                    plan_id=plan.plan_id,
                    mode="stat",
                    target_pid=plan.target_pid,
                    artifact_name=f"{plan.plan_id}.stat.csv",
                    output_bytes=30,
                    output_sha256="a" * 64,
                    output_format="perf_stat_delimited",
                    actual_event_source="hardware",
                    fallback_used=False,
                    events=("cycles",),
                    started_at_unix_milliseconds=1,
                    finished_at_unix_milliseconds=2,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = HelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
        ).collect(plan, caller_uid=os.geteuid())
    finally:
        server.join(timeout=2)
        listener.close()
    assert result.plan_id == plan.plan_id


def test_helper_client_authenticates_ready_frame_before_callback(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    plan = _collection_plan()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            assert payload["report_ready"] is True
            ready = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionReadyResult(
                    kind="collection_ready",
                    plan_id=plan.plan_id,
                    target_pid=plan.target_pid,
                ),
            )
            complete = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionResult(
                    kind="collection",
                    plan_id=plan.plan_id,
                    mode="stat",
                    target_pid=plan.target_pid,
                    artifact_name=f"{plan.plan_id}.stat.csv",
                    output_bytes=30,
                    output_sha256="a" * 64,
                    output_format="perf_stat_delimited",
                    actual_event_source="hardware",
                    fallback_used=False,
                    events=("cycles",),
                    started_at_unix_milliseconds=1,
                    finished_at_unix_milliseconds=2,
                ),
            )
            connection.sendall(
                ready.model_dump_json().encode()
                + b"\n"
                + complete.model_dump_json().encode()
                + b"\n"
            )

    server = threading.Thread(target=serve)
    server.start()
    callbacks: list[str] = []
    try:
        result = HelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
        ).collect(
            plan,
            caller_uid=os.geteuid(),
            ready_callback=lambda: callbacks.append("ready"),
        )
    finally:
        server.join(timeout=2)
        listener.close()

    assert callbacks == ["ready"]
    assert result.plan_id == plan.plan_id


def test_helper_client_rejects_mismatched_ready_identity_before_callback(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    plan = _collection_plan()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            response = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionReadyResult(
                    kind="collection_ready",
                    plan_id=plan.plan_id,
                    target_pid=plan.target_pid + 1,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    callbacks: list[str] = []
    try:
        with pytest.raises(PerfLensError) as mismatch:
            HelperClient(
                socket_path,
                expected_helper_uid=os.geteuid(),
            ).collect(
                plan,
                caller_uid=os.geteuid(),
                ready_callback=lambda: callbacks.append("ready"),
            )
    finally:
        server.join(timeout=2)
        listener.close()

    assert callbacks == []
    assert mismatch.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_helper_client_rejects_unsupported_broker_mode_before_exchange(
    tmp_path: Path,
) -> None:
    client = HelperClient(tmp_path / "missing.sock", expected_helper_uid=os.geteuid())
    with pytest.raises(PerfLensError, match="supports only record and stat") as captured:
        client.collect(_collection_plan(mode="sched"), caller_uid=os.geteuid())
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_helper_client_preserves_typed_helper_rejection(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            response = HelperResponse(
                request_id=payload["request_id"],
                ok=False,
                error=HelperErrorBody(
                    code="RESOURCE_LIMIT_EXCEEDED",
                    stage="privileged_helper",
                    message="fixed spool is full",
                    recoverable=True,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError, match="fixed spool is full") as captured:
            HelperClient(socket_path, expected_helper_uid=os.geteuid()).collect(
                _collection_plan(),
                caller_uid=os.geteuid(),
            )
    finally:
        server.join(timeout=2)
        listener.close()
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert captured.value.recoverable is True


def test_helper_client_rejects_collection_result_not_bound_to_plan(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    plan = _collection_plan()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            response = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionResult(
                    kind="collection",
                    plan_id=plan.plan_id,
                    mode="stat",
                    target_pid=plan.target_pid + 1,
                    artifact_name=f"{plan.plan_id}.stat.csv",
                    output_bytes=30,
                    output_sha256="a" * 64,
                    output_format="perf_stat_delimited",
                    actual_event_source="hardware",
                    fallback_used=False,
                    events=("cycles",),
                    started_at_unix_milliseconds=1,
                    finished_at_unix_milliseconds=2,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError, match="identity is unsafe"):
            HelperClient(socket_path, expected_helper_uid=os.geteuid()).collect(
                plan,
                caller_uid=os.geteuid(),
            )
    finally:
        server.join(timeout=2)
        listener.close()


def test_helper_client_rejects_result_with_forged_event_source(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    plan = _collection_plan()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            response = HelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=HelperCollectionResult(
                    kind="collection",
                    plan_id=plan.plan_id,
                    mode="stat",
                    target_pid=plan.target_pid,
                    artifact_name=f"{plan.plan_id}.stat.csv",
                    output_bytes=30,
                    output_sha256="a" * 64,
                    output_format="perf_stat_delimited",
                    actual_event_source="software",
                    fallback_used=False,
                    events=(
                        "task-clock",
                        "context-switches",
                        "cpu-migrations",
                        "page-faults",
                    ),
                    started_at_unix_milliseconds=1,
                    finished_at_unix_milliseconds=2,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError, match="identity is unsafe"):
            HelperClient(socket_path, expected_helper_uid=os.geteuid()).collect(
                plan,
                caller_uid=os.geteuid(),
            )
    finally:
        server.join(timeout=2)
        listener.close()


def test_helper_client_rejects_mismatched_response_id(tmp_path: Path) -> None:
    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            _read_frame(connection)
            response = HelperResponse(
                request_id="request-ffffffffffffffff",
                ok=True,
                result=HelperHealthResult(
                    kind="health",
                    helper_version="0.2.0",
                    helper_pid=os.getpid(),
                    helper_uid=os.geteuid(),
                    privilege_mode="paranoid3_helper",
                    ready=True,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError, match="ID does not match"):
            HelperClient(socket_path, expected_helper_uid=os.geteuid()).health()
    finally:
        server.join(timeout=2)
        listener.close()


def _read_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        chunk = connection.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)
