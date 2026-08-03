from __future__ import annotations

import sys
from pathlib import Path

import pytest

from perflens.workloads import _bootstrap


def test_project_bootstrap_rejects_invalid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["bootstrap"])
    with pytest.raises(SystemExit) as missing:
        _bootstrap.main()
    assert missing.value.code == 125

    monkeypatch.setattr(sys, "argv", ["bootstrap", "bad", "2", "/app"])
    with pytest.raises(SystemExit) as invalid:
        _bootstrap.main()
    assert invalid.value.code == 125


def test_project_bootstrap_releases_exact_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "app"
    calls: list[object] = []

    def record_write(fd: int, data: bytes) -> int:
        calls.append((fd, data))
        return 1

    def record_close(fd: int) -> None:
        calls.append(("close", fd))

    def release(_fd: int, _size: int) -> bytes:
        return b"1"

    def record_exec(path: str, args: list[str]) -> None:
        calls.append(("execv", path, args))

    monkeypatch.setattr(sys, "argv", ["bootstrap", "10", "11", str(executable), "arg"])
    monkeypatch.setattr(_bootstrap.os, "write", record_write)
    monkeypatch.setattr(_bootstrap.os, "close", record_close)
    monkeypatch.setattr(_bootstrap.os, "read", release)
    monkeypatch.setattr(_bootstrap.os, "execv", record_exec)

    _bootstrap.main()

    assert (11, b"R") in calls
    assert ("execv", str(executable), [str(executable), "arg"]) in calls


def test_project_bootstrap_maps_release_and_exec_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def write_ready(_fd: int, _data: bytes) -> int:
        return 1

    def close_fd(_fd: int) -> None:
        return None

    def reject_release(_fd: int, _size: int) -> bytes:
        return b"x"

    def accept_release(_fd: int, _size: int) -> bytes:
        return b"1"

    monkeypatch.setattr(sys, "argv", ["bootstrap", "10", "11", "/app"])
    monkeypatch.setattr(_bootstrap.os, "write", write_ready)
    monkeypatch.setattr(_bootstrap.os, "close", close_fd)
    monkeypatch.setattr(_bootstrap.os, "read", reject_release)
    with pytest.raises(SystemExit) as rejected:
        _bootstrap.main()
    assert rejected.value.code == 125

    monkeypatch.setattr(_bootstrap.os, "read", accept_release)

    def fail_exec(_path: str, _args: list[str]) -> None:
        raise OSError("failed")

    monkeypatch.setattr(_bootstrap.os, "execv", fail_exec)
    with pytest.raises(SystemExit) as failed:
        _bootstrap.main()
    assert failed.value.code == 126
