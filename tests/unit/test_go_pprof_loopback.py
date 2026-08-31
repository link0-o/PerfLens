from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks.go_pprof_loopback import (
    capture_go_pprof_loopback_profile,
    cleanup_go_pprof_loopback_capture,
    inspect_go_pprof_loopback_target,
    open_go_pprof_loopback_capture,
)

_SERVER = r"""
import http.server
import sys

port = int(sys.argv[1])
body = bytes.fromhex(sys.argv[2])
address = sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in {"/debug/pprof/mutex?debug=0", "/debug/pprof/block?debug=0"}:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer((address, port), Handler)
print("ready", flush=True)
server.serve_forever()
"""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _server(body: bytes, *, address: str = "127.0.0.1") -> tuple[subprocess.Popen[str], int]:
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test program
        (sys.executable, "-c", _SERVER, str(port), body.hex(), address),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "ready"
    return process, port


def _stop(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def test_loopback_capture_binds_pid_socket_and_private_file(tmp_path: Path) -> None:
    process, port = _server(b"bounded-profile")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    try:
        target = inspect_go_pprof_loopback_target(process.pid, port)
        assert target.target_uid == os.geteuid()
        assert target.loopback_address == "127.0.0.1"
        capture = capture_go_pprof_loopback_profile(
            target,
            "mutex",
            private_output_root=private,
        )
        descriptor = open_go_pprof_loopback_capture(capture)
        try:
            assert os.read(descriptor, 100) == b"bounded-profile"
        finally:
            os.close(descriptor)
        cleanup_go_pprof_loopback_capture(capture)
        assert not capture.profile_path.exists()
        cleanup_go_pprof_loopback_capture(capture)
    finally:
        _stop(process)


def test_loopback_rejects_wildcard_listener() -> None:
    process, port = _server(b"profile", address="0.0.0.0")  # noqa: S104 - rejection fixture
    try:
        with pytest.raises(PerfLensError, match="literal-loopback"):
            inspect_go_pprof_loopback_target(process.pid, port)
    finally:
        _stop(process)


def test_loopback_rejects_replaced_private_profile(tmp_path: Path) -> None:
    process, port = _server(b"profile")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    try:
        target = inspect_go_pprof_loopback_target(process.pid, port)
        capture = capture_go_pprof_loopback_profile(
            target,
            "block",
            private_output_root=private,
        )
        capture.profile_path.unlink()
        capture.profile_path.write_bytes(b"replace")
        capture.profile_path.chmod(0o600)
        with pytest.raises(PerfLensError, match="replaced file"):
            cleanup_go_pprof_loopback_capture(capture)
    finally:
        _stop(process)


def test_loopback_rejects_response_over_limit(tmp_path: Path) -> None:
    process, port = _server(b"too-large")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    try:
        target = inspect_go_pprof_loopback_target(process.pid, port)
        with pytest.raises(PerfLensError, match="exceeds its fixed bound"):
            capture_go_pprof_loopback_profile(
                target,
                "mutex",
                private_output_root=private,
                maximum_bytes=2,
            )
        assert list(private.iterdir()) == []
    finally:
        _stop(process)


def test_loopback_target_change_is_rejected(tmp_path: Path) -> None:
    process, port = _server(b"profile")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = inspect_go_pprof_loopback_target(process.pid, port)
    _stop(process)
    for _ in range(100):
        if not Path(f"/proc/{process.pid}").exists():
            break
        time.sleep(0.01)
    with pytest.raises(PerfLensError, match=r"does not exist|cannot be verified"):
        capture_go_pprof_loopback_profile(
            target,
            "mutex",
            private_output_root=private,
        )
