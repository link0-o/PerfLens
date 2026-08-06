from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.privileged_helper.client import HelperClient
from perflens.privileged_helper.protocol import (
    HELPER_SCHEMA_VERSION,
    HelperHealthResult,
    HelperResponse,
)


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


def _read_frame(connection: socket.socket) -> bytes:
    received = bytearray()
    while b"\n" not in received:
        chunk = connection.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)
