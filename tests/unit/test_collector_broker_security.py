from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from perflens.collection.collector import SOFTWARE_STAT_EVENTS
from perflens.collector_broker.client import (
    CollectorBrokerClient,
    _read_response_frame,
    _socket_identity,
    _validate_connected_peer,
    _verify_collection_artifact,
)
from perflens.collector_broker.policy import (
    CollectorBrokerPolicy,
    broker_policy_sha256,
    validate_broker_policy,
)
from perflens.collector_broker.protocol import (
    BROKER_SCHEMA_VERSION,
    MAX_BROKER_MESSAGE_BYTES,
    BrokerCollectionReady,
    BrokerCollectRequest,
    BrokerError,
    BrokerResponse,
)
from perflens.collector_broker.server import (
    CollectorBrokerServer,
    _new_socket_path,
    _peer_uid,
    _read_frame,
)
from perflens.collector_broker.state import replay_marker_name
from perflens.contracts.artifacts import (
    CollectionArtifact,
    CollectionPlanArtifact,
    ContainerCollectionCgroupBinding,
    ContainerCollectionNamespaceBinding,
    ContainerCollectionTargetBinding,
)
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
        requested_event_source="hardware_required",
        record_event="cycles",
        max_output_bytes=1024,
        expires_at=(datetime.now(tz=UTC) + timedelta(minutes=1)).isoformat(),
        policy_status="allowed",
        required_privilege="cap_perfmon",
    )


def test_collector_policy_fingerprint_covers_every_effective_limit(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    fingerprint = broker_policy_sha256(policy)
    assert fingerprint == broker_policy_sha256(policy)
    assert fingerprint != broker_policy_sha256(
        replace(policy, max_duration_seconds=policy.max_duration_seconds - 1)
    )
    assert fingerprint != broker_policy_sha256(
        replace(policy, allow_software_fallback=True)
    )


def _docker_plan(
    *,
    target_uid: int,
    uid_mapping: Literal[
        "rootless_same_uid",
        "rootful_same_uid",
        "rootful_cross_uid",
    ],
    rootful_risk_authorized: bool,
) -> CollectionPlanArtifact:
    target = ContainerCollectionTargetBinding(
        target_id="container-target-0123456789abcdefabcd",
        target_kind="existing_container",
        target_content_sha256="a" * 64,
        container_identity_sha256="b" * 64,
        image_identity_sha256="c" * 64,
        identity_fingerprint="d" * 64,
        container_pid=1,
        host_pid=4242,
        host_uid=target_uid,
        host_start_time_ticks=12345,
        executable_name="worker",
        namespace=ContainerCollectionNamespaceBinding(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCollectionCgroupBinding(
            inode=105,
            identity_sha256="e" * 64,
        ),
        uid_mapping=uid_mapping,
        rootful_risk_authorized=rootful_risk_authorized,
        adapter_recipe_id="local-docker-read-v1",
        adapter_sha256="f" * 64,
    )
    return _plan().model_copy(
        update={
            "target_pid": target.host_pid,
            "target_uid": target.host_uid,
            "target_start_time_ticks": target.host_start_time_ticks,
            "target_runtime": "docker",
            "container_target": target,
        }
    )


def _broker_with_policy(policy: CollectorBrokerPolicy) -> CollectorBrokerServer:
    broker = object.__new__(CollectorBrokerServer)
    broker._policy = policy
    return broker


def _listening_socket(tmp_path: Path, name: str = "collector.sock") -> tuple[socket.socket, Path]:
    runtime = tmp_path / name
    runtime.mkdir()
    runtime.chmod(0o750)
    socket_path = runtime / "s"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chmod(socket_path, 0o660)
    listener.listen(1)
    return listener, socket_path


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
                update={"expires_at": (datetime.now(tz=UTC) + timedelta(minutes=10)).isoformat()}
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
        base.model_copy(
            update={
                "mode": "stat",
                "events": ("cycles",),
                "frequency_hz": None,
                "call_graph": None,
                "record_event": None,
            }
        ),
    )
    software_event_policy = replace(
        policy,
        allowed_stat_events=("cycles", "instructions", *SOFTWARE_STAT_EVENTS),
    )
    with pytest.raises(PerfLensError, match="event-source"):
        _broker_with_policy(software_event_policy)._authorize(
            os.geteuid(),
            base.model_copy(
                update={
                    "mode": "stat",
                    "events": ("task-clock",),
                    "frequency_hz": None,
                    "call_graph": None,
                    "record_event": None,
                }
            ),
        )
    other_target_policy = replace(policy, allow_other_target_uids=True)
    _broker_with_policy(other_target_policy)._authorize(
        os.geteuid(),
        base.model_copy(update={"target_uid": os.geteuid() + 1}),
    )


def test_broker_authorizes_rootless_and_requires_dedicated_rootful_policy(
    tmp_path: Path,
) -> None:
    peer_uid = 1234
    base_policy = replace(_policy(tmp_path), allowed_uids=(peer_uid,))
    rootless = _docker_plan(
        target_uid=peer_uid,
        uid_mapping="rootless_same_uid",
        rootful_risk_authorized=False,
    )
    _broker_with_policy(base_policy)._authorize(peer_uid, rootless)

    rootful = _docker_plan(
        target_uid=0,
        uid_mapping="rootful_cross_uid",
        rootful_risk_authorized=True,
    )
    generic_cross_uid = replace(base_policy, allow_other_target_uids=True)
    with pytest.raises(PerfLensError, match="dedicated policy"):
        _broker_with_policy(generic_cross_uid)._authorize(peer_uid, rootful)
    with pytest.raises(PerfLensError, match="dedicated policy"):
        _broker_with_policy(base_policy)._authorize(peer_uid, rootful)

    rootful_policy = replace(
        base_policy,
        privilege_mode="paranoid3_helper",
        allow_rootful_container_targets=True,
    )
    _broker_with_policy(rootful_policy)._authorize(peer_uid, rootful)

    forged_host = rootful.model_copy(
        update={"target_runtime": "host", "container_target": None}
    )
    with pytest.raises(PerfLensError):
        _broker_with_policy(rootful_policy)._authorize(peer_uid, forged_host)


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


def test_legacy_collector_policy_narrows_auto_plan_to_hardware_only(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    broker = _broker_with_policy(policy)
    plan = _plan().model_copy(
        update={
            "requested_event_source": "auto",
            "fallback_allowed": True,
            "fallback_record_event": "cpu-clock",
        }
    )

    broker._authorize(os.geteuid(), plan)
    narrowed = broker._narrow_fallback_to_collector_policy(plan)

    assert narrowed.requested_event_source == "auto"
    assert narrowed.fallback_allowed is False
    assert narrowed.fallback_events == ()
    assert narrowed.fallback_record_event is None


def test_broker_denies_exhausted_or_unsafe_spool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path)
    spool = policy.spool_root
    plan = _plan()

    filler = spool / "plan-00000000000000000001.perf.data"
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
    unexpected.write_bytes(b"unmanaged")
    with pytest.raises(PerfLensError) as unmanaged_entry:
        _broker_with_policy(policy)._authorize_spool_capacity(plan)
    assert unmanaged_entry.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    unexpected.unlink()

    unexpected.mkdir()
    with pytest.raises(PerfLensError) as non_regular_entry:
        _broker_with_policy(policy)._authorize_spool_capacity(plan)
    assert non_regular_entry.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_consumed_plan_marker_survives_broker_recreation_and_expires_safely(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path)
    plan = _plan()
    marker = policy.spool_root / replay_marker_name(plan.plan_id)

    _broker_with_policy(policy)._consume_plan(plan)

    assert marker.is_file()
    assert marker.stat().st_mode & 0o777 == 0o600
    assert marker.stat().st_size == 0
    marker_ignored_by_evidence_quota = replace(
        policy,
        max_spool_artifacts=1,
        min_free_bytes=0,
    )
    _broker_with_policy(marker_ignored_by_evidence_quota)._authorize_spool_capacity(plan)
    with pytest.raises(PerfLensError, match="already consumed") as replayed:
        _broker_with_policy(policy)._consume_plan(plan)
    assert replayed.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    expired_timestamp = (datetime.now(tz=UTC) - timedelta(hours=1)).timestamp()
    os.utime(marker, times=(expired_timestamp, expired_timestamp))
    next_plan = plan.model_copy(update={"plan_id": "plan-0123456789abcdefabce"})
    _broker_with_policy(policy)._consume_plan(next_plan)

    assert not marker.exists()
    assert (policy.spool_root / replay_marker_name(next_plan.plan_id)).is_file()


def test_broker_rejects_unsafe_persistent_replay_markers(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    marker = policy.spool_root / replay_marker_name(_plan().plan_id)
    marker.write_bytes(b"not-empty")
    marker.chmod(0o600)

    with pytest.raises(PerfLensError, match="unsafe replay marker") as captured:
        _broker_with_policy(policy)._authorize_spool_capacity(_plan())
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


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


@pytest.mark.parametrize("timeout_seconds", [True, float("nan"), float("inf"), 86_501])
def test_client_rejects_non_finite_or_ambiguous_timeouts(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="timeout"):
        CollectorBrokerClient(tmp_path / "missing.sock", timeout_seconds=timeout_seconds)


def test_client_rejects_unsafe_socket_permissions_and_replacement(tmp_path: Path) -> None:
    unsafe_runtime = tmp_path / "unsafe-client-runtime"
    unsafe_runtime.mkdir()
    unsafe_runtime.chmod(0o770)
    unsafe_path = unsafe_runtime / "collector.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(unsafe_path))
        os.chmod(unsafe_path, 0o660)
        with pytest.raises(ValueError, match="directory is group/world writable"):
            CollectorBrokerClient(unsafe_path)

    listener, socket_path = _listening_socket(tmp_path, "w")
    with listener:
        os.chmod(socket_path, 0o666)  # noqa: S103 - intentionally unsafe test fixture
        with pytest.raises(ValueError, match="accessible to other users"):
            CollectorBrokerClient(socket_path)

    first_listener, replacement_path = _listening_socket(tmp_path, "r")
    identity = _socket_identity(replacement_path)
    first_listener.close()
    replacement_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
        replacement.bind(str(replacement_path))
        os.chmod(replacement_path, 0o660)
        replacement.listen(1)
        current = _socket_identity(replacement_path)
        reused_inode_identity = replace(
            identity,
            device=current.device,
            inode=current.inode,
            ctime_ns=current.ctime_ns - 1,
            uid=current.uid,
            gid=current.gid,
            mode=current.mode,
        )
        with pytest.raises(PerfLensError, match="identity changed") as changed:
            _validate_connected_peer(
                reused_inode_identity,
                os.getpid(),
                os.geteuid(),
            )
    assert changed.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def _broker_error() -> BrokerError:
    return BrokerError(
        code=ErrorCode.INVALID_INPUT.value,
        stage="collector_broker",
        message="rejected",
        recoverable=True,
    )


@pytest.mark.parametrize(
    ("ok", "result", "error"),
    [
        (True, None, None),
        (True, {"value": 1}, _broker_error()),
        (False, None, None),
        (False, {"value": 1}, _broker_error()),
    ],
)
def test_broker_response_requires_exactly_one_typed_payload(
    ok: bool,
    result: dict[str, object] | None,
    error: BrokerError | None,
) -> None:
    with pytest.raises(ValidationError):
        BrokerResponse(
            request_id="request-0123456789abcdef",
            ok=ok,
            result=result,
            error=error,
        )


def test_broker_ready_request_is_strict_and_uses_versioned_protocol() -> None:
    plan = _plan()
    request = BrokerCollectRequest(
        request_id="request-0123456789abcdef",
        plan=plan,
        report_ready=True,
    )
    assert request.schema_version == BROKER_SCHEMA_VERSION == "1.1"
    with pytest.raises(ValidationError):
        BrokerCollectRequest(
            request_id="request-0123456789abcdef",
            plan=plan,
            report_ready=1,  # type: ignore[arg-type] - verifies strict protocol rejection
        )


def test_client_rejects_mismatched_response_id_over_real_socket(tmp_path: Path) -> None:
    listener, socket_path = _listening_socket(tmp_path, "m")

    def respond() -> None:
        with listener:
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.recv(4096).partition(b"\n")[0])
                assert request["operation"] == "health"
                response = BrokerResponse(
                    request_id="unknown",
                    ok=False,
                    error=_broker_error(),
                )
                connection.sendall(response.model_dump_json().encode("utf-8") + b"\n")

    worker = threading.Thread(target=respond, daemon=True)
    worker.start()
    with pytest.raises(PerfLensError, match="request ID does not match") as mismatch:
        CollectorBrokerClient(socket_path, timeout_seconds=2).health()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert mismatch.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_client_rejects_mismatched_ready_identity_before_callback(tmp_path: Path) -> None:
    listener, socket_path = _listening_socket(tmp_path, "ready-mismatch")
    plan = _plan()

    def respond() -> None:
        with listener:
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.recv(16 << 10).partition(b"\n")[0])
                assert request["schema_version"] == BROKER_SCHEMA_VERSION
                assert request["report_ready"] is True
                response = BrokerResponse(
                    request_id=request["request_id"],
                    ok=True,
                    result=BrokerCollectionReady(
                        plan_id=plan.plan_id,
                        target_pid=plan.target_pid + 1,
                    ).model_dump(mode="json"),
                )
                connection.sendall(response.model_dump_json().encode("utf-8") + b"\n")

    worker = threading.Thread(target=respond, daemon=True)
    worker.start()
    callbacks: list[str] = []
    with pytest.raises(PerfLensError, match="does not match the authorized plan") as mismatch:
        CollectorBrokerClient(socket_path, timeout_seconds=2).collect(
            plan,
            ready_callback=lambda: callbacks.append("ready"),
        )
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert callbacks == []
    assert mismatch.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_client_classifies_incomplete_response_timeout(tmp_path: Path) -> None:
    listener, socket_path = _listening_socket(tmp_path, "t")

    def stall() -> None:
        with listener:
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                time.sleep(0.2)

    worker = threading.Thread(target=stall, daemon=True)
    worker.start()
    with pytest.raises(PerfLensError, match="timed out") as timed_out:
        CollectorBrokerClient(socket_path, timeout_seconds=0.05).health()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert timed_out.value.code is ErrorCode.EXTERNAL_TOOL_TIMEOUT
    assert timed_out.value.recoverable is True
    assert timed_out.value.retryable is True


def test_client_rejects_collection_result_that_does_not_match_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener, socket_path = _listening_socket(tmp_path, "x")
    listener.close()
    plan = _plan()
    artifact = CollectionArtifact(
        collection_id="collection-wrong-target",
        mode=plan.mode,
        target_type="pid",
        target_argument_count=0,
        target_pid=plan.target_pid + 1,
        output_path="/var/lib/perflens/wrong.perf.data",
        output_sha256="a" * 64,
        output_bytes=1,
        output_format="perf_data",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-04T00:00:00+00:00",
        finished_at="2026-08-04T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=plan.frequency_hz,
        call_graph=plan.call_graph,
        requested_event_source="hardware_required",
        actual_event_source="hardware",
    )

    def wrong_exchange(
        _self: CollectorBrokerClient,
        _payload: bytes,
        *,
        expected_request_id: str,
        expected_ready: tuple[str, int] | None = None,
        ready_callback: Callable[[], None] | None = None,
    ) -> tuple[BrokerResponse, int, int]:
        assert expected_ready is None
        assert ready_callback is None
        return (
            BrokerResponse(
                request_id=expected_request_id,
                ok=True,
                result=artifact.model_dump(mode="json"),
            ),
            os.getpid(),
            os.geteuid(),
        )

    monkeypatch.setattr(CollectorBrokerClient, "_exchange", wrong_exchange)
    with pytest.raises(PerfLensError, match="does not match") as mismatch:
        CollectorBrokerClient(socket_path).collect(plan)
    assert mismatch.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_client_rejects_collection_result_with_different_container_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener, socket_path = _listening_socket(tmp_path, "docker-result-mismatch")
    listener.close()
    plan = _docker_plan(
        target_uid=os.geteuid(),
        uid_mapping="rootless_same_uid",
        rootful_risk_authorized=False,
    )
    artifact = CollectionArtifact(
        collection_id="collection-missing-docker-binding",
        mode=plan.mode,
        target_type="pid",
        target_argument_count=0,
        target_pid=plan.target_pid,
        target_runtime="host",
        output_path="/var/lib/perflens/wrong.perf.data",
        output_sha256="a" * 64,
        output_bytes=1,
        output_format="perf_data",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-04T00:00:00+00:00",
        finished_at="2026-08-04T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=plan.frequency_hz,
        call_graph=plan.call_graph,
        record_event=plan.record_event,
        requested_event_source="hardware_required",
        actual_event_source="hardware",
    )

    def wrong_exchange(
        _self: CollectorBrokerClient,
        _payload: bytes,
        *,
        expected_request_id: str,
        expected_ready: tuple[str, int] | None = None,
        ready_callback: Callable[[], None] | None = None,
    ) -> tuple[BrokerResponse, int, int]:
        assert expected_ready is None
        assert ready_callback is None
        return (
            BrokerResponse(
                request_id=expected_request_id,
                ok=True,
                result=artifact.model_dump(mode="json"),
            ),
            os.getpid(),
            os.geteuid(),
        )

    monkeypatch.setattr(CollectorBrokerClient, "_exchange", wrong_exchange)
    with pytest.raises(PerfLensError, match="does not match"):
        CollectorBrokerClient(socket_path).collect(plan)


def test_client_verifies_collection_file_identity_permissions_and_digest(tmp_path: Path) -> None:
    listener, socket_path = _listening_socket(tmp_path, "v")
    socket_identity = _socket_identity(socket_path)
    listener.close()
    plan = _plan()
    spool = tmp_path / "evidence"
    spool.mkdir()
    spool.chmod(0o750)
    output = spool / f"{plan.plan_id}.perf.data"
    payload = b"PERFILE2-verified"
    output.write_bytes(payload)
    output.chmod(0o640)
    artifact = CollectionArtifact(
        collection_id="collection-verified-output",
        mode=plan.mode,
        target_type="pid",
        target_argument_count=0,
        target_pid=plan.target_pid,
        output_path=str(output),
        output_sha256=hashlib.sha256(payload).hexdigest(),
        output_bytes=len(payload),
        output_format="perf_data",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-04T00:00:00+00:00",
        finished_at="2026-08-04T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=plan.frequency_hz,
        call_graph=plan.call_graph,
        record_event=plan.record_event,
        requested_event_source=plan.requested_event_source,
        actual_event_source="hardware",
    )

    _verify_collection_artifact(artifact, plan, socket_identity, os.geteuid())

    auto_plan = plan.model_copy(
        update={
            "requested_event_source": "auto",
            "fallback_allowed": True,
            "fallback_record_event": "cpu-clock",
        }
    )
    software_artifact = artifact.model_copy(
        update={
            "requested_event_source": "auto",
            "actual_event_source": "software",
            "record_event": "cpu-clock",
            "fallback_used": True,
            "fallback_reason": "hardware_probe_failed",
            "evidence_limitations": (
                "instructions-per-cycle unavailable",
                "hardware cache-miss evidence unavailable",
                "hardware branch-miss evidence unavailable",
            ),
        }
    )
    _verify_collection_artifact(software_artifact, auto_plan, socket_identity, os.geteuid())
    with pytest.raises(PerfLensError, match="artifact policy"):
        _verify_collection_artifact(
            software_artifact.model_copy(update={"fallback_reason": "forged"}),
            auto_plan,
            socket_identity,
            os.geteuid(),
        )

    sched_plan = plan.model_copy(
        update={
            "mode": "sched",
            "frequency_hz": None,
            "call_graph": None,
            "record_event": None,
        }
    )
    sched_artifact = artifact.model_copy(
        update={
            "mode": "sched",
                "frequency_hz": None,
                "call_graph": None,
                "record_event": None,
                "actual_event_source": "unknown",
            }
        )
    _verify_collection_artifact(sched_artifact, sched_plan, socket_identity, os.geteuid())

    with pytest.raises(PerfLensError, match="artifact policy") as forged_source:
        _verify_collection_artifact(
            artifact.model_copy(update={"actual_event_source": "software"}),
            plan,
            socket_identity,
            os.geteuid(),
        )
    assert forged_source.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError, match="artifact policy") as forged_fallback:
        _verify_collection_artifact(
            artifact.model_copy(
                update={
                    "fallback_used": True,
                    "fallback_reason": "forged",
                    "actual_event_source": "software",
                    "evidence_limitations": (
                        "instructions-per-cycle unavailable",
                        "hardware cache-miss evidence unavailable",
                        "hardware branch-miss evidence unavailable",
                    ),
                }
            ),
            plan,
            socket_identity,
            os.geteuid(),
        )
    assert forged_fallback.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError, match="integrity metadata") as wrong_digest:
        _verify_collection_artifact(
            artifact.model_copy(update={"output_sha256": "0" * 64}),
            plan,
            socket_identity,
            os.geteuid(),
        )
    assert wrong_digest.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    output.chmod(0o660)
    with pytest.raises(PerfLensError, match="artifact policy"):
        _verify_collection_artifact(artifact, plan, socket_identity, os.geteuid())
    output.chmod(0o640)

    second_name = spool / "second-link"
    os.link(output, second_name)
    with pytest.raises(PerfLensError, match="artifact policy"):
        _verify_collection_artifact(artifact, plan, socket_identity, os.geteuid())
    second_name.unlink()

    output.write_bytes(b"X" * len(payload))
    output.chmod(0o640)
    with pytest.raises(PerfLensError, match="integrity metadata"):
        _verify_collection_artifact(artifact, plan, socket_identity, os.geteuid())


@pytest.mark.parametrize("timeout_seconds", [False, 0, -1, 5.01, float("inf"), float("nan")])
def test_broker_rejects_unbounded_request_frame_timeouts(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="request timeout"):
        CollectorBrokerServer(
            tmp_path / "collector.sock",
            _policy(tmp_path),
            request_timeout_seconds=timeout_seconds,
        )


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

    maximum = cast(
        socket.socket,
        FakeConnection(b"x" * (MAX_BROKER_MESSAGE_BYTES - 1) + b"\n"),
    )
    assert len(_read_frame(maximum)) == MAX_BROKER_MESSAGE_BYTES - 1

    trailing = cast(socket.socket, FakeConnection(b"one\ntwo"))
    with pytest.raises(PerfLensError, match="exactly one"):
        _read_frame(trailing)

    oversized = cast(
        socket.socket,
        FakeConnection(b"x" * MAX_BROKER_MESSAGE_BYTES + b"\n"),
    )
    with pytest.raises(PerfLensError) as captured:
        _read_frame(oversized)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    maximum_response = cast(
        socket.socket,
        FakeConnection(b"x" * (MAX_BROKER_MESSAGE_BYTES - 1) + b"\n"),
    )
    assert len(_read_response_frame(maximum_response)) == MAX_BROKER_MESSAGE_BYTES - 1

    oversized_response = cast(
        socket.socket,
        FakeConnection(b"x" * MAX_BROKER_MESSAGE_BYTES + b"\n"),
    )
    with pytest.raises(PerfLensError) as oversized_error:
        _read_response_frame(oversized_response)
    assert oversized_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    trailing_response = cast(socket.socket, FakeConnection(b"one\ntwo"))
    with pytest.raises(PerfLensError, match="malformed"):
        _read_response_frame(trailing_response)

    class TimeoutConnection:
        def recv(self, _size: int) -> bytes:
            raise TimeoutError

    timed_out = cast(socket.socket, TimeoutConnection())
    with pytest.raises(PerfLensError, match="timed out") as timeout:
        _read_frame(timed_out)
    assert timeout.value.code is ErrorCode.INVALID_INPUT
    assert timeout.value.recoverable is True
