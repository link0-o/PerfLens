from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.trace_helper.client import TraceHelperClient
from perflens.trace_helper.protocol import (
    TraceHelperCollectionReadyResult,
    TraceHelperCollectionResult,
    TraceHelperCollectPidRequest,
    TraceHelperErrorBody,
    TraceHelperHealthResult,
    TraceHelperResponse,
    TraceHelperTarget,
)


def _request() -> TraceHelperCollectPidRequest:
    return TraceHelperCollectPidRequest(
        request_id="request-0123456789abcdef",
        plan_id="trace-plan-0123456789abcdefabcd",
        caller_uid=os.geteuid(),
        target=TraceHelperTarget(
            pid=4321,
            uid=os.geteuid(),
            start_time_ticks=998877,
        ),
        mode="sched",
        duration_milliseconds=1000,
        max_output_bytes=1 << 20,
        expires_at_unix_milliseconds=4_102_444_760_000,
        expected_policy_sha256="a" * 64,
        expected_capture_backend="target_filtered_kernel_v1",
        report_ready=False,
    )


def test_trace_helper_client_authenticates_unavailable_health(tmp_path: Path) -> None:
    socket_path, listener = _listener(tmp_path)

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            request = json.loads(_read_frame(connection))
            response = TraceHelperResponse(
                request_id=request["request_id"],
                ok=True,
                result=TraceHelperHealthResult(
                    kind="health",
                    helper_version="0.3.0",
                    helper_pid=os.getpid(),
                    helper_uid=os.geteuid(),
                    ready=True,
                    capture_backend="target_filtered_kernel_v1",
                    capture_backend_status="unavailable",
                    supported_modes=(),
                    policy_sha256="a" * 64,
                    max_duration_milliseconds=10_000,
                    max_output_bytes=67_108_864,
                    max_concurrent_collections=1,
                    target_filter_before_userspace=False,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        health = TraceHelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
        ).health()
    finally:
        server.join(timeout=2)
        listener.close()

    assert health.capture_backend_status == "unavailable"
    assert not health.target_filter_before_userspace


def test_trace_helper_client_surfaces_fail_closed_backend_rejection(
    tmp_path: Path,
) -> None:
    socket_path, listener = _listener(tmp_path)
    request = _request()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            assert set(payload) == {
                "schema_version",
                "operation",
                "request_id",
                "plan_id",
                "caller_uid",
                "target",
                "mode",
                "duration_milliseconds",
                "max_output_bytes",
                "expires_at_unix_milliseconds",
                "expected_policy_sha256",
                "expected_capture_backend",
                "report_ready",
            }
            response = TraceHelperResponse(
                request_id=payload["request_id"],
                ok=False,
                error=TraceHelperErrorBody(
                    code="UNSUPPORTED_FORMAT",
                    stage="trace_backend",
                    message="Target-filtered kernel Trace backend is unavailable",
                    recoverable=True,
                ),
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError) as captured:
            TraceHelperClient(
                socket_path,
                expected_helper_uid=os.geteuid(),
            ).collect(request)
    finally:
        server.join(timeout=2)
        listener.close()

    assert captured.value.code is ErrorCode.UNSUPPORTED_FORMAT
    assert captured.value.stage == "trace_backend"


def test_trace_helper_client_binds_ready_and_collection_result(
    tmp_path: Path,
) -> None:
    socket_path, listener = _listener(tmp_path)
    request = _request().model_copy(update={"report_ready": True})

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            ready = TraceHelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=TraceHelperCollectionReadyResult(
                    kind="collection_ready",
                    plan_id=request.plan_id,
                    target_pid=request.target.pid,
                ),
            )
            complete = TraceHelperResponse(
                request_id=payload["request_id"],
                ok=True,
                result=TraceHelperCollectionResult(
                    kind="collection",
                    plan_id=request.plan_id,
                    mode=request.mode,
                    target_pid=request.target.pid,
                    target_start_time_ticks=request.target.start_time_ticks,
                    artifact_name=f"{request.plan_id}.trace.ndjson",
                    output_bytes=512,
                    output_sha256="b" * 64,
                    output_format="target_filtered_trace_ndjson",
                    capture_backend=request.expected_capture_backend,
                    policy_sha256=request.expected_policy_sha256,
                    observed_target_tids=(request.target.pid,),
                    event_count=2,
                    lost_event_count=0,
                    truncated=False,
                    started_at_monotonic_nanoseconds=10,
                    finished_at_monotonic_nanoseconds=20,
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
        result = TraceHelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
        ).collect(request, ready_callback=lambda: callbacks.append("ready"))
    finally:
        server.join(timeout=2)
        listener.close()

    assert callbacks == ["ready"]
    assert result.observed_target_tids == (request.target.pid,)


def test_trace_helper_client_rejects_result_not_bound_to_plan(
    tmp_path: Path,
) -> None:
    socket_path, listener = _listener(tmp_path)
    request = _request()

    def serve() -> None:
        connection, _address = listener.accept()
        with connection:
            payload = json.loads(_read_frame(connection))
            result = TraceHelperCollectionResult(
                kind="collection",
                plan_id=request.plan_id,
                mode=request.mode,
                target_pid=request.target.pid + 1,
                target_start_time_ticks=request.target.start_time_ticks,
                artifact_name=f"{request.plan_id}.trace.ndjson",
                output_bytes=512,
                output_sha256="b" * 64,
                output_format="target_filtered_trace_ndjson",
                capture_backend=request.expected_capture_backend,
                policy_sha256=request.expected_policy_sha256,
                observed_target_tids=(request.target.pid,),
                event_count=1,
                lost_event_count=0,
                truncated=False,
                started_at_monotonic_nanoseconds=10,
                finished_at_monotonic_nanoseconds=20,
            )
            response = TraceHelperResponse(
                request_id=payload["request_id"], ok=True, result=result
            )
            connection.sendall(response.model_dump_json().encode() + b"\n")

    server = threading.Thread(target=serve)
    server.start()
    try:
        with pytest.raises(PerfLensError) as captured:
            TraceHelperClient(
                socket_path,
                expected_helper_uid=os.geteuid(),
            ).collect(request)
    finally:
        server.join(timeout=2)
        listener.close()

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_trace_helper_client_rejects_unsafe_socket_and_constructor(
    tmp_path: Path,
) -> None:
    socket_path, listener = _listener(tmp_path)
    socket_path.chmod(0o666)
    try:
        with pytest.raises(PerfLensError) as captured:
            TraceHelperClient(
                socket_path,
                expected_helper_uid=os.geteuid(),
            ).health()
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    finally:
        listener.close()

    with pytest.raises(ValueError, match="UID"):
        TraceHelperClient(socket_path, expected_helper_uid=-1)
    with pytest.raises(ValueError, match="15 seconds"):
        TraceHelperClient(
            socket_path,
            expected_helper_uid=os.geteuid(),
            timeout_seconds=16,
        )


def _listener(tmp_path: Path) -> tuple[Path, socket.socket]:
    socket_path = tmp_path / "trace-helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    return socket_path, listener


def _read_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        received.extend(connection.recv(4096))
    return bytes(received[: received.index(b"\n")])
