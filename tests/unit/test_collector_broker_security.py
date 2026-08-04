from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
import socket
import struct
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from perflens.collector_broker.client import CollectorBrokerClient
from perflens.collector_broker.policy import CollectorBrokerPolicy, validate_broker_policy
from perflens.collector_broker.protocol import MAX_BROKER_MESSAGE_BYTES
from perflens.collector_broker.server import (
    CollectorBrokerServer,
    _new_socket_path,
    _peer_uid,
    _read_frame,
)
from perflens.contracts.artifacts import CollectionPlanArtifact
from perflens.domain.errors import ErrorCode, PerfLensError


def _fake_perf(tmp_path: Path) -> Path:
    executable = tmp_path / "perf"
    executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    executable.chmod(0o555)
    return executable


def _policy(tmp_path: Path) -> CollectorBrokerPolicy:
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o750)
    return validate_broker_policy(
        CollectorBrokerPolicy(
            spool_root=spool,
            perf_path=_fake_perf(tmp_path),
            allowed_uids=(os.geteuid(),),
            allowed_modes=("record", "stat"),
            max_duration_seconds=10,
            max_frequency_hz=99,
            max_output_bytes=1024,
            allowed_stat_events=("cycles", "instructions"),
        )
    )


def _plan() -> CollectionPlanArtifact:
    return CollectionPlanArtifact(
        plan_id="plan-0123456789abcdefabcd",
        mode="record",
        target_type="pid",
        target_pid=os.getppid(),
        target_uid=os.geteuid(),
        target_start_time_ticks=1,
        backend="privileged_broker",
        duration_seconds=1,
        frequency_hz=99,
        call_graph="dwarf",
        max_output_bytes=1024,
        expires_at=(datetime.now(tz=UTC) + timedelta(minutes=1)).isoformat(),
        policy_status="allowed",
        required_privilege="cap_perfmon",
    )


def _broker_with_policy(policy: CollectorBrokerPolicy) -> CollectorBrokerServer:
    broker = object.__new__(CollectorBrokerServer)
    broker._policy = policy
    return broker


def test_broker_authorization_denies_every_out_of_policy_dimension(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    broker = _broker_with_policy(policy)
    base = _plan()
    denied = (
        (os.geteuid() + 1, base),
        (os.geteuid(), base.model_copy(update={"mode": "off_cpu"})),
        (os.geteuid(), base.model_copy(update={"target_uid": os.geteuid() + 1})),
        (os.geteuid(), base.model_copy(update={"duration_seconds": 11})),
        (os.geteuid(), base.model_copy(update={"frequency_hz": 100})),
        (os.geteuid(), base.model_copy(update={"max_output_bytes": 1025})),
        (
            os.geteuid(),
            base.model_copy(
                update={
                    "expires_at": (datetime.now(tz=UTC) + timedelta(minutes=10)).isoformat()
                }
            ),
        ),
        (
            os.geteuid(),
            base.model_copy(update={"mode": "stat", "events": ("branches",)}),
        ),
    )
    for peer_uid, plan in denied:
        with pytest.raises(PerfLensError) as captured:
            broker._authorize(peer_uid, plan)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    broker._authorize(
        os.geteuid(),
        base.model_copy(update={"mode": "stat", "events": ("cycles",)}),
    )
    other_target_policy = replace(policy, allow_other_target_uids=True)
    _broker_with_policy(other_target_policy)._authorize(
        os.geteuid(),
        base.model_copy(update={"target_uid": os.geteuid() + 1}),
    )


def test_broker_health_allows_root_admin_without_relaxing_user_policy(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path)
    broker = _broker_with_policy(policy)

    root_health = broker._health(0)
    assert root_health.status == "ready"
    assert root_health.peer_uid == 0
    assert root_health.policy_version == policy.policy_version

    with pytest.raises(PerfLensError) as denied:
        broker._health(os.geteuid() + 1)
    assert denied.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_broker_denies_exhausted_or_unsafe_spool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path)
    spool = policy.spool_root
    plan = _plan()

    filler = spool / "existing.perf.data"
    filler.write_bytes(b"x" * 513)
    byte_limited = replace(
        policy,
        max_spool_bytes=1536,
        max_spool_artifacts=10,
        min_free_bytes=0,
    )
    with pytest.raises(PerfLensError) as byte_error:
        _broker_with_policy(byte_limited)._authorize_spool_capacity(plan)
    assert byte_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    count_limited = replace(
        policy,
        max_spool_artifacts=1,
        min_free_bytes=0,
    )
    with pytest.raises(PerfLensError) as count_error:
        _broker_with_policy(count_limited)._authorize_spool_capacity(plan)
    assert count_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    filler.unlink()

    def exhausted_disk(_path: object) -> SimpleNamespace:
        return SimpleNamespace(free=1023)

    monkeypatch.setattr(
        "perflens.collector_broker.server.shutil.disk_usage",
        exhausted_disk,
    )
    no_free_space = replace(policy, min_free_bytes=0)
    with pytest.raises(PerfLensError) as free_space_error:
        _broker_with_policy(no_free_space)._authorize_spool_capacity(plan)
    assert free_space_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    unexpected = spool / "unexpected"
    unexpected.mkdir()
    with pytest.raises(PerfLensError) as unsafe_entry:
        _broker_with_policy(policy)._authorize_spool_capacity(plan)
    assert unsafe_entry.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_socket_path_and_client_require_safe_existing_socket(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        _new_socket_path(Path("relative.sock"))
    with pytest.raises(ValueError, match="must be absolute"):
        CollectorBrokerClient(Path("relative.sock"))
    with pytest.raises(ValueError, match="does not exist"):
        CollectorBrokerClient(tmp_path / "missing.sock")

    regular = tmp_path / "regular"
    regular.write_text("not a socket", encoding="utf-8")
    with pytest.raises(ValueError, match="not a Unix socket"):
        CollectorBrokerClient(regular)
    with pytest.raises(ValueError, match="timeout"):
        CollectorBrokerClient(regular, timeout_seconds=0)

    unsafe_runtime = tmp_path / "unsafe"
    unsafe_runtime.mkdir()
    unsafe_runtime.chmod(0o770)
    with pytest.raises(ValueError, match="not group/world writable"):
        _new_socket_path(unsafe_runtime / "collector.sock")

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime.chmod(0o750)
    occupied = runtime / "collector.sock"
    occupied.write_text("occupied", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        _new_socket_path(occupied)


def test_broker_frames_are_bounded_and_peer_authenticated() -> None:
    class FakePeer:
        def getsockopt(self, _level: int, _option: int, _size: int) -> bytes:
            return struct.pack("3i", 123, os.geteuid(), os.getegid())

    assert _peer_uid(cast(socket.socket, FakePeer())) == os.geteuid()

    class FakeConnection:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def recv(self, size: int) -> bytes:
            chunk = self.payload[:size]
            self.payload = self.payload[size:]
            return chunk

    valid = cast(socket.socket, FakeConnection(b'{"ok":true}\n'))
    assert _read_frame(valid) == b'{"ok":true}'

    trailing = cast(socket.socket, FakeConnection(b"one\ntwo"))
    with pytest.raises(PerfLensError, match="exactly one"):
        _read_frame(trailing)

    oversized = cast(
        socket.socket,
        FakeConnection(b"x" * (MAX_BROKER_MESSAGE_BYTES + 1)),
    )
    with pytest.raises(PerfLensError) as captured:
        _read_frame(oversized)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
