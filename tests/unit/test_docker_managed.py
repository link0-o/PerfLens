from __future__ import annotations

import os
import socket
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from tests.support.docker import write_self_contained_test_elf

import perflens.docker.managed as managed_module
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import ContainerWorkloadSpecArtifact
from perflens.docker.adapter import (
    DockerCliIdentity,
    DockerCommandAdapter,
    DockerEndpointSnapshot,
    ManagedDockerCreateRequest,
)
from perflens.docker.identity import KernelProcessIdentity, NamespaceIdentity
from perflens.docker.managed import (
    ManagedDockerCoordinator,
    build_container_run_artifact,
)
from perflens.docker.session import (
    EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
    AuthorizedDockerSession,
    DockerRunLease,
    DockerSessionAuthority,
)
from perflens.docker.workload import (
    build_container_workload_spec,
    inspect_container_gate,
    inspect_managed_project_root,
)
from perflens.domain.errors import ErrorCode, PerfLensError

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)
CLIENT = "a" * 64
POLICY = "b" * 64
CONTAINER_ID = "c" * 64
READY = b"PERFLENS_GATE_V1 READY\n"
EXEC = b"PERFLENS_GATE_V1 EXEC\n"


@dataclass(slots=True)
class _FakeReader:
    host_pid: int
    identity_allowed: threading.Event | None = None
    host_uid: int = os.geteuid()

    def inspect_process(self, host_pid: int) -> KernelProcessIdentity:
        if host_pid != self.host_pid:
            raise AssertionError("unexpected managed host PID")
        if self.identity_allowed is not None and not self.identity_allowed.is_set():
            raise AssertionError("managed identity was read before Gate readiness")
        return KernelProcessIdentity(
            host_pid=host_pid,
            host_uid=self.host_uid,
            host_start_time_ticks=987_654,
            container_pid=1,
            nspid=(host_pid, 1),
            executable_name="perflens-conta",
            namespace=NamespaceIdentity(pid=101, user=102, mount=103, cgroup=104),
            cgroup_relative_path="/docker/managed-test",
            cgroup_inode=105,
        )


class _FakeManagedAdapter:
    def __init__(
        self,
        *,
        gate_pid: int | None = None,
        tamper: str | None = None,
        gate_frame: bytes = READY,
    ) -> None:
        self.gate_pid = os.getpid() if gate_pid is None else gate_pid
        self.tamper = tamper
        self.gate_frame = gate_frame
        self.request: ManagedDockerCreateRequest | None = None
        self.state = "absent"
        self.operations: list[str] = []
        self.released = False
        self.gate_error: BaseException | None = None
        self._gate_thread: threading.Thread | None = None

    @property
    def cli_identity(self) -> DockerCliIdentity:
        return DockerCliIdentity(
            path=Path("/usr/bin/docker"),
            sha256="d" * 64,
            device=1,
            inode=2,
            size=1024,
            trusted_owner_uids=(0,),
        )

    @property
    def endpoint_identity(self) -> DockerEndpointSnapshot:
        return DockerEndpointSnapshot(
            path=Path("/run/user/1000/docker.sock"),
            kind="local_rootless",
            device=3,
            inode=4,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o600,
        )

    def create_managed_container(self, request: ManagedDockerCreateRequest) -> str:
        assert self.state == "absent"
        self.request = request
        self.state = "created"
        self.operations.append("create")
        return CONTAINER_ID

    def start_managed_container(self, container_id: str) -> None:
        assert container_id == CONTAINER_ID and self.request is not None
        assert self.state == "created"
        self.state = "running"
        self.operations.append("start")
        self._gate_thread = threading.Thread(target=self._gate_client, daemon=True)
        self._gate_thread.start()

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        assert container_id == CONTAINER_ID and self.request is not None
        if self.state in {"absent", "removed"}:
            raise AssertionError("container is unavailable")
        running = self.state == "running"
        request = self.request
        data: dict[str, Any] = {
            "Id": CONTAINER_ID,
            "Image": request.image_digest,
            "Name": f"/{request.container_name}",
            "State": {"Running": running, "Pid": self.gate_pid if running else 0},
            "Config": {
                "Image": request.image_digest,
                "User": request.container_user,
                "WorkingDir": request.working_directory,
                "Entrypoint": ["/usr/lib/perflens/perflens-container-gate"],
                "Cmd": [
                    "--control",
                    "/run/perflens-gate/control.sock",
                    "--",
                    request.workload_entrypoint,
                    *request.workload_arguments,
                ],
                "OpenStdin": False,
                "Tty": False,
                "AttachStdin": False,
                "Labels": {
                    "image.label": "private-image-metadata",
                    "io.perflens.managed": "true",
                    "io.perflens.session-sha256": request.session_identity_sha256,
                    "io.perflens.workload-sha256": request.workload_spec_sha256,
                    "io.perflens.receipt-sha256": request.creation_receipt_sha256,
                },
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "PidMode": "",
                "IpcMode": "private",
                "UsernsMode": "",
                "CgroupnsMode": "private",
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "Devices": [],
                "DeviceRequests": [],
                "AutoRemove": False,
                "RestartPolicy": {"Name": "no"},
                "SecurityOpt": ["no-new-privileges"],
                "NanoCpus": int(float(request.cpus) * 1_000_000_000),
                "Memory": request.memory_bytes,
                "PidsLimit": request.pids,
            },
            "Mounts": [
                _mount(request.project_root, "/workspace", False),
                _mount(request.scratch_root, "/perflens-scratch", True),
                _mount(request.control_root, "/run/perflens-gate", False),
                _mount(
                    request.gate_path,
                    "/usr/lib/perflens/perflens-container-gate",
                    False,
                ),
            ],
        }
        if self.tamper == "privileged":
            data["HostConfig"]["Privileged"] = True
        elif self.tamper == "host_network":
            data["HostConfig"]["NetworkMode"] = "host"
        elif self.tamper == "capability":
            data["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        elif self.tamper == "command":
            data["Config"]["Cmd"] = ["/bin/sh"]
        elif self.tamper == "receipt_label":
            data["Config"]["Labels"]["io.perflens.receipt-sha256"] = "f" * 64
        elif self.tamper == "resource":
            data["HostConfig"]["Memory"] = request.memory_bytes + 1
        elif self.tamper == "extra_mount":
            data["Mounts"].append(_mount(Path("/etc"), "/host-etc", True))
        elif self.tamper is not None:
            raise AssertionError(f"unknown fake tamper: {self.tamper}")
        return data

    def wait_managed_container(self, container_id: str, *, timeout_seconds: int) -> int:
        assert container_id == CONTAINER_ID and timeout_seconds > 0
        assert self._gate_thread is not None
        self._gate_thread.join(timeout=2)
        if self._gate_thread.is_alive():
            raise AssertionError("fake Gate did not finish")
        if self.gate_error is not None:
            raise self.gate_error
        self.state = "stopped"
        self.operations.append("wait")
        return 7

    def stop_managed_container(self, container_id: str) -> None:
        assert container_id == CONTAINER_ID
        self.state = "stopped"
        self.operations.append("stop")
        if self._gate_thread is not None:
            self._gate_thread.join(timeout=2)

    def remove_managed_container(self, container_id: str) -> None:
        assert container_id == CONTAINER_ID and self.state == "stopped"
        self.state = "removed"
        self.operations.append("remove")

    def _gate_client(self) -> None:
        assert self.request is not None
        directory_descriptor = -1
        try:
            directory_descriptor = os.open(
                self.request.control_root,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect(
                    f"/proc/self/fd/{directory_descriptor}/control.sock"
                )
                connection.sendall(self.gate_frame)
                response = _receive_exact(connection, len(EXEC))
                trailing = connection.recv(1)
                if response == EXEC and trailing == b"":
                    self.released = True
        except BaseException as exc:  # test double records the protocol failure
            self.gate_error = exc
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)


def _mount(source: Path, destination: str, writable: bool) -> dict[str, object]:
    return {
        "Type": "bind",
        "Source": str(source),
        "Destination": destination,
        "RW": writable,
    }


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        chunk = connection.recv(size - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _setup(
    tmp_path: Path,
    *,
    adapter: _FakeManagedAdapter | None = None,
    reader_host_uid: int | None = None,
    identity_allowed: threading.Event | None = None,
) -> tuple[
    ManagedDockerCoordinator,
    _FakeManagedAdapter,
    ContainerWorkloadSpecArtifact,
    DockerSessionAuthority,
    AuthorizedDockerSession,
    DockerRunLease,
    Path,
]:
    project_path = tmp_path / "project"
    runtime_root = tmp_path / "runtime"
    project_path.mkdir(mode=0o700)
    runtime_root.mkdir(mode=0o700)
    gate_path = tmp_path / "perflens-container-gate"
    write_self_contained_test_elf(gate_path)
    project = inspect_managed_project_root(project_path)
    gate = inspect_container_gate(gate_path, trusted_owner_uids=(os.geteuid(),))
    workload = build_container_workload_spec(
        project=project,
        gate=gate,
        image_digest="sha256:" + "e" * 64,
        entrypoint="/usr/bin/python3",
        arguments=("/workspace/bench.py",),
        container_user=f"{os.geteuid()}:{os.getegid()}",
        cpus=2,
        memory_bytes=128 << 20,
        pids=64,
        created_at=NOW,
    )
    authority = DockerSessionAuthority(
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 100.0,
    )
    authorized = authority.authorize_managed_workload(
        workload,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        explicit_authorization=EXPLICIT_DOCKER_SESSION_AUTHORIZATION,
        max_evidence_bytes=1 << 20,
    )
    lease = authority.begin_run(
        authorized.access,
        project_identity_sha256=project.identity_sha256,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=workload.content_sha256,
        requested_modes=("stat", "record"),
        reserve_active_seconds=30,
        reserve_evidence_bytes=1 << 20,
    )
    selected = adapter or _FakeManagedAdapter()
    coordinator = ManagedDockerCoordinator(
        adapter=cast(DockerCommandAdapter, selected),
        runtime_root=runtime_root,
        project=project,
        gate=gate,
        reader=cast(
            Any,
            _FakeReader(
                selected.gate_pid,
                identity_allowed,
                os.geteuid() if reader_host_uid is None else reader_host_uid,
            ),
        ),
        token_hex=lambda _bytes: "1" * 20,
        wall_clock=lambda: NOW,
        gate_wait_seconds=1,
    )
    return coordinator, selected, workload, authority, authorized, lease, runtime_root


def _prepare(
    coordinator: ManagedDockerCoordinator,
    workload: ContainerWorkloadSpecArtifact,
    authority: DockerSessionAuthority,
    authorized: AuthorizedDockerSession,
    lease: DockerRunLease,
):
    return coordinator.prepare(
        workload=workload,
        authority=authority,
        access=authorized.access,
        lease=lease,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
    )


def test_managed_coordinator_binds_gate_runs_and_cleans_exact_container(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    assert prepared.state == "prepared"
    assert prepared.target.artifact.target_kind == "managed_temporary_container"
    assert prepared.target.artifact.adapter_recipe_id == "local-docker-managed-v1"
    assert adapter.operations == ["create", "start"]
    assert not adapter.released

    coordinator.release(prepared)
    assert prepared.state == "released"
    assert adapter.released
    assert coordinator.wait(prepared, timeout_seconds=30) == 7
    assert coordinator.cleanup(prepared) == "removed"
    assert adapter.operations == ["create", "start", "wait", "remove"]
    assert not (runtime_root / ("run-" + "1" * 20)).exists()

    run = build_container_run_artifact(
        prepared=prepared,
        workload=workload,
        finished_at=NOW + timedelta(seconds=1),
        status="exited",
        cleanup_status="removed",
    )
    assert run.exit_code == 7
    assert run.content_sha256 == contract_content_sha256(
        run,
        exclude={"content_sha256"},
    )
    serialized = run.model_dump_json()
    assert CONTAINER_ID not in serialized
    assert str(runtime_root) not in serialized


def test_managed_coordinator_authenticates_gate_before_kernel_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_allowed = threading.Event()
    original_accept_gate = managed_module._accept_gate  # pyright: ignore[reportPrivateUsage]

    def tracked_accept_gate(*args: Any, **kwargs: Any) -> tuple[socket.socket, int]:
        accepted = original_accept_gate(*args, **kwargs)
        identity_allowed.set()
        return accepted

    monkeypatch.setattr(managed_module, "_accept_gate", tracked_accept_gate)
    coordinator, _adapter, workload, authority, authorized, lease, _runtime_root = _setup(
        tmp_path,
        identity_allowed=identity_allowed,
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    coordinator.release(prepared)
    coordinator.wait(prepared, timeout_seconds=30)
    assert coordinator.cleanup(prepared) == "removed"


@pytest.mark.parametrize(
    "tamper",
    (
        "privileged",
        "host_network",
        "capability",
        "command",
        "receipt_label",
        "resource",
        "extra_mount",
    ),
)
def test_managed_coordinator_preserves_container_when_inspect_policy_is_tampered(
    tmp_path: Path,
    tamper: str,
) -> None:
    adapter = _FakeManagedAdapter(tamper=tamper)
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path,
        adapter=adapter,
    )
    with pytest.raises(PerfLensError) as captured:
        _prepare(coordinator, workload, authority, authorized, lease)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert adapter.operations == ["create"]
    assert adapter.state == "created"
    assert (runtime_root / ("run-" + "1" * 20)).is_dir()
    assert captured.value.details["managed_container_cleanup_status"] == (
        "preserved_for_manual_cleanup"
    )
    assert "manual review is required" in captured.value.message
    assert CONTAINER_ID not in str(captured.value)
    assert str(runtime_root) not in str(captured.value)


@pytest.mark.parametrize("gate_frame", (b"BAD GATE FRAME\n", READY + b"EXTRA"))
def test_managed_coordinator_rejects_invalid_or_extra_gate_frame_then_cleans(
    tmp_path: Path,
    gate_frame: bytes,
) -> None:
    adapter = _FakeManagedAdapter(gate_frame=gate_frame)
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path,
        adapter=adapter,
    )
    with pytest.raises(PerfLensError) as captured:
        _prepare(coordinator, workload, authority, authorized, lease)
    assert captured.value.details["managed_container_cleanup_status"] == "removed"
    assert "verified temporary container was removed" in captured.value.message
    assert adapter.operations == ["create", "start", "stop", "remove"]
    assert not (runtime_root / ("run-" + "1" * 20)).exists()


def test_managed_coordinator_rejects_gate_peer_pid_then_cleans_verified_instance(
    tmp_path: Path,
) -> None:
    adapter = _FakeManagedAdapter(gate_pid=os.getpid() + 1)
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path,
        adapter=adapter,
    )
    with pytest.raises(PerfLensError) as captured:
        _prepare(coordinator, workload, authority, authorized, lease)
    assert "peer identity" in captured.value.message
    assert adapter.operations == ["create", "start", "stop", "remove"]
    assert adapter.state == "removed"
    assert not (runtime_root / ("run-" + "1" * 20)).exists()


def test_managed_coordinator_rejects_gate_peer_uid_after_kernel_identity(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path,
        reader_host_uid=os.geteuid() + 1,
    )
    with pytest.raises(PerfLensError) as captured:
        _prepare(coordinator, workload, authority, authorized, lease)
    assert "peer UID" in captured.value.message
    assert adapter.operations == ["create", "start", "stop", "remove"]
    assert adapter.state == "removed"
    assert not (runtime_root / ("run-" + "1" * 20)).exists()


def test_managed_coordinator_reconciles_stale_public_lease_before_create(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path
    )
    expired = replace(lease, expires_at=(NOW - timedelta(seconds=1)).isoformat())
    with pytest.raises(PerfLensError):
        _prepare(coordinator, workload, authority, authorized, expired)
    assert adapter.operations == []
    assert tuple(runtime_root.iterdir()) == ()
    next_lease = authority.begin_run(
        authorized.access,
        project_identity_sha256=workload.project_identity_sha256,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=workload.content_sha256,
        requested_modes=("stat",),
        reserve_active_seconds=1,
        reserve_evidence_bytes=1,
    )
    assert next_lease.run_number == 2


def test_forged_private_lease_token_does_not_consume_real_active_lease(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, _runtime_root = _setup(
        tmp_path
    )
    tampered = replace(lease, token="forged-private-token")  # noqa: S106
    with pytest.raises(PerfLensError):
        _prepare(coordinator, workload, authority, authorized, tampered)
    assert adapter.operations == []
    current = authority.assert_run_current(
        authorized.access,
        lease,
        project_identity_sha256=workload.project_identity_sha256,
        client_connection_identity_sha256=CLIENT,
        policy_identity_sha256=POLICY,
        binding_sha256=workload.content_sha256,
        mode="stat",
    )
    assert current.state == "active"


def test_managed_coordinator_rejects_runtime_root_replacement_before_create(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path
    )
    displaced = runtime_root.with_name("runtime-displaced")
    runtime_root.rename(displaced)
    runtime_root.mkdir(mode=0o700)
    with pytest.raises(PerfLensError) as captured:
        _prepare(coordinator, workload, authority, authorized, lease)
    assert "runtime root changed" in captured.value.message
    assert adapter.operations == []
    assert tuple(runtime_root.iterdir()) == ()


def test_managed_gate_release_and_cleanup_are_single_use(tmp_path: Path) -> None:
    coordinator, _adapter, workload, authority, authorized, lease, _runtime_root = _setup(
        tmp_path
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    coordinator.release(prepared)
    with pytest.raises(PerfLensError):
        coordinator.release(prepared)
    coordinator.wait(prepared, timeout_seconds=30)
    assert coordinator.cleanup(prepared) == "removed"
    with pytest.raises(PerfLensError):
        coordinator.cleanup(prepared)


def test_cleanup_preserves_on_receipt_change_and_allows_verified_retry(
    tmp_path: Path,
) -> None:
    coordinator, adapter, workload, authority, authorized, lease, runtime_root = _setup(
        tmp_path
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    coordinator.release(prepared)
    coordinator.wait(prepared, timeout_seconds=30)
    adapter.tamper = "receipt_label"
    assert coordinator.cleanup(prepared) == "preserved_for_manual_cleanup"
    assert adapter.state == "stopped"
    assert (runtime_root / ("run-" + "1" * 20)).is_dir()
    adapter.tamper = None
    assert coordinator.cleanup(prepared) == "removed"


def test_runtime_directory_replacement_is_never_recursively_deleted(tmp_path: Path) -> None:
    coordinator, _adapter, workload, authority, authorized, lease, _runtime_root = _setup(
        tmp_path
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    coordinator.release(prepared)
    coordinator.wait(prepared, timeout_seconds=30)
    original = prepared.receipt.runtime_directory
    displaced = original.with_name(original.name + "-displaced")
    original.rename(displaced)
    original.mkdir(mode=0o700)
    marker = original / "must-survive"
    marker.write_text("replacement", encoding="utf-8")
    assert coordinator.cleanup(prepared) == "removed"
    assert marker.read_text(encoding="utf-8") == "replacement"


def test_run_artifact_rejects_duplicate_evidence_identity(tmp_path: Path) -> None:
    coordinator, _adapter, workload, authority, authorized, lease, _runtime_root = _setup(
        tmp_path
    )
    prepared = _prepare(coordinator, workload, authority, authorized, lease)
    coordinator.release(prepared)
    coordinator.wait(prepared, timeout_seconds=30)
    coordinator.cleanup(prepared)
    collection_id = "collection-" + "a" * 16
    with pytest.raises(PerfLensError):
        build_container_run_artifact(
            prepared=prepared,
            workload=workload,
            finished_at=NOW + timedelta(seconds=1),
            status="exited",
            cleanup_status="removed",
            collection_ids=(collection_id, collection_id),
        )
