"""Prepare, release, observe, and conservatively clean managed Docker workloads."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import socket
import stat
import struct
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, cast

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    ContainerOptimizationSessionArtifact,
    ContainerRunArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.docker.adapter import DockerCommandAdapter, ManagedDockerCreateRequest
from perflens.docker.identity import (
    LinuxContainerIdentityReader,
    ResolvedContainerTarget,
    build_managed_container_target_artifact,
    parse_container_instance,
)
from perflens.docker.session import (
    DockerRunLease,
    DockerSessionAuthority,
    SessionAccess,
)
from perflens.docker.workload import (
    ContainerGateIdentity,
    ManagedProjectIdentity,
    assert_container_gate_current,
    assert_managed_project_current,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_READY_FRAME = b"PERFLENS_GATE_V1 READY\n"
_EXEC_FRAME = b"PERFLENS_GATE_V1 EXEC\n"
_PEER_CREDENTIALS = struct.Struct("3i")
_SESSION_LABEL = "io.perflens.session-sha256"
_WORKLOAD_LABEL = "io.perflens.workload-sha256"
_RECEIPT_LABEL = "io.perflens.receipt-sha256"
_MANAGED_LABEL = "io.perflens.managed"
_GATE_CONTAINER_PATH = "/usr/lib/perflens/perflens-container-gate"
_CONTROL_CONTAINER_PATH = "/run/perflens-gate"
_CONTROL_SOCKET_PATH = f"{_CONTROL_CONTAINER_PATH}/control.sock"
_MAX_GATE_WAIT_SECONDS = 30


@dataclass(frozen=True, slots=True, repr=False)
class ManagedContainerReceipt:
    container_id: str
    container_name: str
    session_identity_sha256: str
    workload_spec_sha256: str
    creation_receipt_sha256: str
    runtime_directory: Path
    scratch_directory: Path
    control_directory: Path
    control_socket: Path
    runtime_device: int
    runtime_inode: int
    runtime_owner_uid: int


@dataclass(frozen=True, slots=True, repr=False)
class _BoundGateListener:
    socket: socket.socket
    path: Path
    device: int
    inode: int
    owner_uid: int

    def close(self) -> None:
        self.socket.close()


@dataclass(slots=True, repr=False)
class PreparedManagedContainer:
    receipt: ManagedContainerReceipt
    request: ManagedDockerCreateRequest
    session: ContainerOptimizationSessionArtifact
    target: ResolvedContainerTarget
    control: socket.socket
    started_at: datetime
    state: Literal["prepared", "released", "finished", "cleaned"] = "prepared"
    exit_code: int | None = None


class ManagedDockerCoordinator:
    """Coordinate one Gate-bound container without exposing generic Docker control."""

    def __init__(
        self,
        *,
        adapter: DockerCommandAdapter,
        runtime_root: Path,
        project: ManagedProjectIdentity,
        gate: ContainerGateIdentity,
        reader: LinuxContainerIdentityReader | None = None,
        invoking_uid: int | None = None,
        allow_rootful_cross_uid: bool = False,
        token_hex: Callable[[int], str] = secrets.token_hex,
        wall_clock: Callable[[], datetime] | None = None,
        gate_wait_seconds: int = 10,
    ) -> None:
        self._invoking_uid = os.geteuid() if invoking_uid is None else invoking_uid
        if self._invoking_uid != os.geteuid():
            raise _managed_error(
                "Managed Docker coordinator cannot impersonate another invoking UID"
            )
        self._adapter = adapter
        self._runtime_root, self._runtime_root_identity = _validate_runtime_root(
            runtime_root,
            invoking_uid=self._invoking_uid,
            project_root=project.path,
        )
        self._project = project
        self._gate = gate
        self._reader = reader or LinuxContainerIdentityReader()
        self._allow_rootful_cross_uid = allow_rootful_cross_uid
        self._token_hex = token_hex
        self._wall_clock = wall_clock or (lambda: datetime.now(tz=UTC))
        if not 1 <= gate_wait_seconds <= _MAX_GATE_WAIT_SECONDS:
            raise _managed_error("Container Gate wait is outside its fixed bound")
        self._gate_wait_seconds = gate_wait_seconds

    def prepare(
        self,
        *,
        workload: ContainerWorkloadSpecArtifact,
        authority: DockerSessionAuthority,
        access: SessionAccess,
        lease: DockerRunLease,
        client_connection_identity_sha256: str,
        policy_identity_sha256: str,
    ) -> PreparedManagedContainer:
        now = self._now()
        if not lease.allowed_modes:
            raise _managed_error("Managed Docker run lease contains no collection mode")
        session = authority.assert_run_current(
            access,
            lease,
            project_identity_sha256=self._project.identity_sha256,
            client_connection_identity_sha256=client_connection_identity_sha256,
            policy_identity_sha256=policy_identity_sha256,
            binding_sha256=workload.content_sha256,
            mode=lease.allowed_modes[0],
        )
        try:
            return self._prepare_authorized(
                workload=workload,
                session=session,
                lease=lease,
                now=now,
            )
        except BaseException:
            # A failed reconciliation leaves the private lease fail-closed.
            with suppress(PerfLensError):
                authority.finish_run(
                    access,
                    lease,
                    actual_active_seconds=0,
                    actual_evidence_bytes=0,
                )
            raise

    def _prepare_authorized(
        self,
        *,
        workload: ContainerWorkloadSpecArtifact,
        session: ContainerOptimizationSessionArtifact,
        lease: DockerRunLease,
        now: datetime,
    ) -> PreparedManagedContainer:
        _validate_authorized_run(
            workload=workload,
            session=session,
            lease=lease,
            now=now,
        )
        _assert_runtime_root_current(
            self._runtime_root,
            self._runtime_root_identity,
        )
        assert_managed_project_current(self._project)
        assert_container_gate_current(self._gate)
        if workload.project_identity_sha256 != self._project.identity_sha256:
            raise _managed_error("Managed workload project identity changed after authorization")
        if workload.container_gate_sha256 != self._gate.sha256:
            raise _managed_error("Managed workload Gate identity changed after authorization")
        run_nonce = self._token_hex(10)
        if len(run_nonce) != 20 or any(value not in "0123456789abcdef" for value in run_nonce):
            raise _managed_error("Managed Docker run nonce source returned an invalid identity")
        session_identity = _sha256_text(
            "perflens-managed-session-v1",
            session.session_id,
            session.authorization_receipt_sha256,
            session.project_identity_sha256,
            session.client_connection_identity_sha256,
        )
        creation_receipt = _sha256_text(
            "perflens-managed-creation-v1",
            session_identity,
            workload.content_sha256,
            lease.lease_id,
            str(lease.run_number),
            run_nonce,
        )
        runtime_directory = self._runtime_root / f"run-{run_nonce}"
        scratch_directory = runtime_directory / "scratch"
        control_directory = runtime_directory / "control"
        listener: _BoundGateListener | None = None
        connection: socket.socket | None = None
        container_id: str | None = None
        request: ManagedDockerCreateRequest | None = None
        runtime_identity: tuple[int, int, int] | None = None
        try:
            runtime_identity = _create_private_run_directories(
                runtime_directory,
                scratch_directory,
                control_directory,
            )
            control_socket = control_directory / "control.sock"
            listener = _create_gate_listener(control_socket, self._gate_wait_seconds)
            request = ManagedDockerCreateRequest(
                container_name=f"perflens-{run_nonce}",
                image_digest=workload.image_digest,
                project_root=self._project.path,
                scratch_root=scratch_directory,
                control_root=control_directory,
                gate_path=self._gate.path,
                gate_sha256=self._gate.sha256,
                workload_entrypoint=workload.entrypoint,
                workload_arguments=workload.arguments,
                working_directory=workload.working_directory,
                container_user=workload.container_user,
                cpus=_format_cpu_limit(workload.resources.cpus),
                memory_bytes=workload.resources.memory_bytes,
                pids=workload.resources.pids,
                session_identity_sha256=session_identity,
                workload_spec_sha256=workload.content_sha256,
                creation_receipt_sha256=creation_receipt,
            )
            container_id = self._adapter.create_managed_container(request)
            _validate_managed_inspect(
                self._adapter.inspect_container(container_id),
                container_id=container_id,
                request=request,
                expected_running=False,
            )
            self._adapter.start_managed_container(container_id)
            running_data = self._adapter.inspect_container(container_id)
            _validate_managed_inspect(
                running_data,
                container_id=container_id,
                request=request,
                expected_running=True,
            )
            instance = parse_container_instance(running_data)
            kernel = self._reader.inspect_process(instance.init_host_pid)
            target_artifact = build_managed_container_target_artifact(
                adapter=self._adapter,
                instance=instance,
                target=kernel,
                invoking_uid=self._invoking_uid,
                allow_rootful_cross_uid=self._allow_rootful_cross_uid,
                created_at=now,
            )
            connection = _accept_gate(
                listener.socket,
                expected_pid=kernel.host_pid,
                expected_uid=kernel.host_uid,
                timeout_seconds=self._gate_wait_seconds,
            )
            _retire_gate_listener(listener)
            listener = None
            current_data = self._adapter.inspect_container(container_id)
            _validate_managed_inspect(
                current_data,
                container_id=container_id,
                request=request,
                expected_running=True,
            )
            current_instance = parse_container_instance(current_data)
            current_kernel = self._reader.inspect_process(instance.init_host_pid)
            if current_instance != instance or current_kernel != kernel:
                raise _managed_error(
                    "Managed Docker identity changed during Gate authorization",
                    recoverable=True,
                )
            receipt = ManagedContainerReceipt(
                container_id=container_id,
                container_name=request.container_name,
                session_identity_sha256=session_identity,
                workload_spec_sha256=workload.content_sha256,
                creation_receipt_sha256=creation_receipt,
                runtime_directory=runtime_directory,
                scratch_directory=scratch_directory,
                control_directory=control_directory,
                control_socket=control_socket,
                runtime_device=runtime_identity[0],
                runtime_inode=runtime_identity[1],
                runtime_owner_uid=runtime_identity[2],
            )
            return PreparedManagedContainer(
                receipt=receipt,
                request=request,
                session=session,
                target=ResolvedContainerTarget(instance, kernel, target_artifact),
                control=connection,
                started_at=now,
            )
        except BaseException:
            if connection is not None:
                connection.close()
            if listener is not None:
                listener.close()
            removable = container_id is None
            if container_id is not None and request is not None:
                removable = _cleanup_verified_container(
                    self._adapter,
                    container_id,
                    request,
                )
            if removable:
                _cleanup_runtime_directory(runtime_directory, runtime_identity)
            raise

    def release(self, prepared: PreparedManagedContainer) -> None:
        if prepared.state != "prepared":
            raise _managed_error("Container Gate release is not in the prepared state")
        self._assert_prepared_current(prepared)
        try:
            prepared.control.sendall(_EXEC_FRAME)
            prepared.control.shutdown(socket.SHUT_WR)
            prepared.control.settimeout(self._gate_wait_seconds)
            if prepared.control.recv(1) != b"":
                raise _managed_error("Container Gate did not close after the execution release")
        except OSError as exc:
            raise _managed_error(
                "Container Gate execution release failed",
                recoverable=True,
            ) from exc
        finally:
            prepared.control.close()
        prepared.state = "released"

    def wait(self, prepared: PreparedManagedContainer, *, timeout_seconds: int) -> int:
        if prepared.state != "released":
            raise _managed_error("Managed Docker wait requires one released workload")
        exit_code = self._adapter.wait_managed_container(
            prepared.receipt.container_id,
            timeout_seconds=timeout_seconds,
        )
        prepared.exit_code = exit_code
        prepared.state = "finished"
        return exit_code

    def cleanup(
        self,
        prepared: PreparedManagedContainer,
    ) -> Literal["removed", "preserved_for_manual_cleanup"]:
        if prepared.state == "cleaned":
            raise _managed_error("Managed Docker cleanup is single-use")
        prepared.control.close()
        removed = _cleanup_verified_container(
            self._adapter,
            prepared.receipt.container_id,
            prepared.request,
        )
        if not removed:
            return "preserved_for_manual_cleanup"
        _cleanup_runtime_directory(
            prepared.receipt.runtime_directory,
            (
                prepared.receipt.runtime_device,
                prepared.receipt.runtime_inode,
                prepared.receipt.runtime_owner_uid,
            ),
        )
        prepared.state = "cleaned"
        return "removed"

    def _assert_prepared_current(self, prepared: PreparedManagedContainer) -> None:
        data = self._adapter.inspect_container(prepared.receipt.container_id)
        _validate_managed_inspect(
            data,
            container_id=prepared.receipt.container_id,
            request=prepared.request,
            expected_running=True,
        )
        instance = parse_container_instance(data)
        kernel = self._reader.inspect_process(instance.init_host_pid)
        if instance != prepared.target.instance or kernel != prepared.target.kernel:
            raise _managed_error(
                "Managed Docker target changed before Gate release",
                recoverable=True,
            )

    def _now(self) -> datetime:
        value = self._wall_clock()
        if value.tzinfo is None:
            raise _managed_error("Managed Docker clock must return timezone-aware timestamps")
        return value


def build_container_run_artifact(
    *,
    prepared: PreparedManagedContainer,
    workload: ContainerWorkloadSpecArtifact,
    finished_at: datetime,
    status: Literal["exited", "terminated_after_collection", "failed_before_exec"],
    cleanup_status: Literal["removed", "preserved_for_manual_cleanup", "not_started"],
    collection_ids: tuple[str, ...] = (),
    build_artifact_sha256: tuple[str, ...] = (),
    resource_context_id: str | None = None,
    warnings: tuple[str, ...] = (),
) -> ContainerRunArtifact:
    session = prepared.session
    _verify_content(workload, workload.content_sha256, "workload")
    _verify_content(session, session.content_sha256, "session")
    if prepared.receipt.workload_spec_sha256 != workload.content_sha256:
        raise _managed_error("Container run workload identity differs from its creation receipt")
    if prepared.receipt.session_identity_sha256 != _sha256_text(
        "perflens-managed-session-v1",
        session.session_id,
        session.authorization_receipt_sha256,
        session.project_identity_sha256,
        session.client_connection_identity_sha256,
    ):
        raise _managed_error("Container run session identity differs from its creation receipt")
    if finished_at.tzinfo is None or finished_at <= prepared.started_at:
        raise _managed_error("Container run finish time must follow its Gate preparation")
    if prepared.exit_code is None and status != "failed_before_exec":
        raise _managed_error("Completed managed workload is missing its exit status")
    if prepared.exit_code is not None and status == "failed_before_exec":
        raise _managed_error("Pre-exec managed workload cannot carry an exit status")
    canonical_collections = _unique_sorted(
        collection_ids,
        "collection identities",
    )
    canonical_builds = _unique_sorted(
        build_artifact_sha256,
        "build artifact identities",
    )
    target = prepared.target.artifact
    identity = _sha256_text(
        "perflens-container-run-v1",
        session.session_id,
        prepared.receipt.creation_receipt_sha256,
        target.identity_fingerprint,
        prepared.started_at.isoformat(),
        finished_at.isoformat(),
    )
    provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        run_id=f"container-run-{identity[:20]}",
        created_at=finished_at.isoformat(),
        session_id=session.session_id,
        workload_spec_sha256=workload.content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        image_identity_sha256=target.image_identity_sha256,
        target_identity_sha256=target.identity_fingerprint,
        container_pid=target.container_pid,
        host_pid=target.host_pid,
        host_start_time_ticks=target.host_start_time_ticks,
        started_at=prepared.started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        status=status,
        exit_code=prepared.exit_code,
        collection_ids=canonical_collections,
        treatment_path_sha256=workload.treatment_path_sha256,
        build_artifact_sha256=canonical_builds,
        resource_context_id=resource_context_id,
        cleanup_status=cleanup_status,
        warnings=warnings,
        content_sha256="0" * 64,
    )
    return ContainerRunArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _validate_authorized_run(
    *,
    workload: ContainerWorkloadSpecArtifact,
    session: ContainerOptimizationSessionArtifact,
    lease: DockerRunLease,
    now: datetime,
) -> None:
    _verify_content(workload, workload.content_sha256, "workload")
    _verify_content(session, session.content_sha256, "session")
    if (
        session.state != "active"
        or session.target_kind != "managed_temporary_container"
        or session.workload_spec_sha256 != workload.content_sha256
        or session.project_identity_sha256 != workload.project_identity_sha256
        or lease.session_id != session.session_id
        or lease.target_kind != "managed_temporary_container"
        or lease.binding_sha256 != workload.content_sha256
        or lease.run_number <= 0
        or lease.run_number > session.workload_runs_used
        or any(mode not in session.allowed_modes for mode in lease.allowed_modes)
        or any(mode not in workload.allowed_modes for mode in lease.allowed_modes)
    ):
        raise _managed_error("Managed Docker run is outside its authorized session binding")
    try:
        lease_expiry = datetime.fromisoformat(lease.expires_at)
    except ValueError as exc:
        raise _managed_error("Managed Docker lease expiry is malformed") from exc
    try:
        session_expiry = datetime.fromisoformat(session.expires_at)
    except ValueError as exc:
        raise _managed_error("Managed Docker session expiry is malformed") from exc
    if (
        lease_expiry.tzinfo is None
        or session_expiry.tzinfo is None
        or lease_expiry <= now
        or session_expiry <= now
    ):
        raise _managed_error("Managed Docker run lease has expired")


def _validate_managed_inspect(
    data: dict[str, Any],
    *,
    container_id: str,
    request: ManagedDockerCreateRequest,
    expected_running: bool | None,
) -> None:
    if data.get("Id") != container_id or data.get("Image") != request.image_digest:
        raise _managed_error("Managed Docker inspect identity differs from its creation receipt")
    if data.get("Name") not in (request.container_name, f"/{request.container_name}"):
        raise _managed_error("Managed Docker name differs from its creation receipt")
    state = _dict_field(data, "State")
    running = state.get("Running")
    process_id = state.get("Pid")
    if type(running) is not bool or type(process_id) is not int:
        raise _managed_error("Managed Docker state has an invalid shape")
    if expected_running is not None and running is not expected_running:
        raise _managed_error("Managed Docker running state differs from the expected lifecycle")
    if (running and process_id <= 0) or (not running and process_id != 0):
        raise _managed_error("Managed Docker PID does not match its running state")
    config = _dict_field(data, "Config")
    expected_command = [
        "--control",
        _CONTROL_SOCKET_PATH,
        "--",
        request.workload_entrypoint,
        *request.workload_arguments,
    ]
    if (
        config.get("Image") != request.image_digest
        or config.get("User") != request.container_user
        or config.get("WorkingDir") != request.working_directory
        or config.get("Entrypoint") != [_GATE_CONTAINER_PATH]
        or config.get("Cmd") != expected_command
        or config.get("OpenStdin") is not False
        or config.get("Tty") is not False
        or config.get("AttachStdin") is not False
    ):
        raise _managed_error("Managed Docker command or interactive state differs from policy")
    labels = _dict_field(config, "Labels")
    expected_labels = {
        _MANAGED_LABEL: "true",
        _SESSION_LABEL: request.session_identity_sha256,
        _WORKLOAD_LABEL: request.workload_spec_sha256,
        _RECEIPT_LABEL: request.creation_receipt_sha256,
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise _managed_error("Managed Docker labels differ from the private creation receipt")
    host = _dict_field(data, "HostConfig")
    restart = _dict_field(host, "RestartPolicy")
    security_value = host.get("SecurityOpt")
    security = cast(list[object], security_value) if isinstance(security_value, list) else []
    no_new_privileges = any(
        isinstance(value, str) and value in ("no-new-privileges", "no-new-privileges=true")
        for value in security
    )
    if (
        host.get("NetworkMode") != "none"
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("PidMode") not in ("", None)
        or host.get("IpcMode") not in ("", "private", None)
        or host.get("UsernsMode") == "host"
        or host.get("CgroupnsMode") == "host"
        or not _empty_sequence(host.get("CapAdd"))
        or host.get("CapDrop") != ["ALL"]
        or not _empty_sequence(host.get("Devices"))
        or not _empty_sequence(host.get("DeviceRequests"))
        or host.get("AutoRemove") is not False
        or restart.get("Name") != "no"
        or not no_new_privileges
        or host.get("NanoCpus") != int(Decimal(request.cpus) * 1_000_000_000)
        or host.get("Memory") != request.memory_bytes
        or host.get("PidsLimit") != request.pids
    ):
        raise _managed_error("Managed Docker isolation or resource limits differ from policy")
    mounts_value = data.get("Mounts")
    if not isinstance(mounts_value, list):
        raise _managed_error("Managed Docker mount set differs from policy")
    mounts = cast(list[object], mounts_value)
    if len(mounts) != 4:
        raise _managed_error("Managed Docker mount set differs from policy")
    observed: dict[str, tuple[str, bool]] = {}
    for raw in mounts:
        if not isinstance(raw, dict):
            raise _managed_error("Managed Docker mount entry has an invalid shape")
        mount = cast(dict[str, object], raw)
        destination = mount.get("Destination")
        source = mount.get("Source")
        writable = mount.get("RW")
        if (
            mount.get("Type") != "bind"
            or not isinstance(destination, str)
            or not isinstance(source, str)
            or type(writable) is not bool
            or destination in observed
        ):
            raise _managed_error("Managed Docker mount entry differs from fixed bind policy")
        observed[destination] = (source, writable)
    expected_mounts = {
        "/workspace": (str(request.project_root), False),
        "/perflens-scratch": (str(request.scratch_root), True),
        _CONTROL_CONTAINER_PATH: (str(request.control_root), False),
        _GATE_CONTAINER_PATH: (str(request.gate_path), False),
    }
    if observed != expected_mounts:
        raise _managed_error("Managed Docker mount source, target, or access differs from policy")


def _create_gate_listener(path: Path, timeout_seconds: int) -> _BoundGateListener:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    directory_descriptor = -1
    try:
        if path.name != "control.sock":
            raise _managed_error("Container Gate control Socket name is not fixed")
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        directory = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) != 0o700:
            raise _managed_error("Container Gate control directory identity is unsafe")
        listener.bind(f"/proc/self/fd/{directory_descriptor}/{path.name}")
        os.chmod(path, 0o600)
        listener.listen(1)
        listener.settimeout(timeout_seconds)
        pathname = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISSOCK(pathname.st_mode)
            or pathname.st_dev != directory.st_dev
            or pathname.st_uid != directory.st_uid
            or pathname.st_ino <= 0
            or stat.S_IMODE(pathname.st_mode) != 0o600
        ):
            raise _managed_error("Container Gate control Socket identity is unsafe")
        return _BoundGateListener(
            socket=listener,
            path=path,
            device=pathname.st_dev,
            inode=pathname.st_ino,
            owner_uid=pathname.st_uid,
        )
    except BaseException as exc:
        listener.close()
        if isinstance(exc, PerfLensError):
            raise
        raise _managed_error("Container Gate control Socket cannot be bound") from exc
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _accept_gate(
    listener: socket.socket,
    *,
    expected_pid: int,
    expected_uid: int,
    timeout_seconds: int,
) -> socket.socket:
    try:
        connection, _ = listener.accept()
    except OSError as exc:
        raise _managed_error("Container Gate did not reach the private control Socket") from exc
    try:
        connection.settimeout(timeout_seconds)
        credentials = _PEER_CREDENTIALS.unpack(
            connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                _PEER_CREDENTIALS.size,
            )
        )
        peer_pid, peer_uid, _peer_gid = credentials
        if peer_pid != expected_pid or peer_uid != expected_uid:
            raise _managed_error("Container Gate peer identity differs from the verified target")
        if _receive_exact(connection, len(_READY_FRAME)) != _READY_FRAME:
            raise _managed_error("Container Gate readiness frame is invalid")
        connection.setblocking(False)
        try:
            trailing = connection.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            trailing = None
        finally:
            connection.settimeout(timeout_seconds)
        if trailing is not None:
            raise _managed_error("Container Gate readiness contains an extra frame")
        return connection
    except BaseException as exc:
        connection.close()
        if isinstance(exc, PerfLensError):
            raise
        if isinstance(exc, OSError):
            raise _managed_error(
                "Container Gate readiness handshake failed",
                recoverable=True,
            ) from exc
        raise


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        chunk = connection.recv(size - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _cleanup_verified_container(
    adapter: DockerCommandAdapter,
    container_id: str,
    request: ManagedDockerCreateRequest,
) -> bool:
    try:
        data = adapter.inspect_container(container_id)
        _validate_managed_inspect(
            data,
            container_id=container_id,
            request=request,
            expected_running=None,
        )
        state = _dict_field(data, "State")
        if state.get("Running") is True:
            adapter.stop_managed_container(container_id)
            data = adapter.inspect_container(container_id)
            _validate_managed_inspect(
                data,
                container_id=container_id,
                request=request,
                expected_running=False,
            )
        adapter.remove_managed_container(container_id)
        return True
    except (OSError, PerfLensError):
        return False


def _validate_runtime_root(
    path: Path,
    *,
    invoking_uid: int,
    project_root: Path,
) -> tuple[Path, tuple[int, int, int]]:
    if not path.is_absolute() or path.is_symlink():
        raise _managed_error("Managed Docker runtime root must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _managed_error("Managed Docker runtime root is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != invoking_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved == project_root
        or resolved in project_root.parents
        or project_root in resolved.parents
    ):
        raise _managed_error("Managed Docker runtime root owner, mode, or isolation is unsafe")
    return resolved, (metadata.st_dev, metadata.st_ino, metadata.st_uid)


def _assert_runtime_root_current(
    path: Path,
    expected_identity: tuple[int, int, int],
) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _managed_error("Managed Docker runtime root disappeared") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid) != expected_identity
    ):
        raise _managed_error("Managed Docker runtime root changed after validation")


def _create_private_run_directories(*directories: Path) -> tuple[int, int, int]:
    created: list[Path] = []
    try:
        for directory in directories:
            directory.mkdir(mode=0o700)
            created.append(directory)
            metadata = directory.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise _managed_error("Managed Docker private directory mode is unsafe")
        runtime = directories[0].stat(follow_symlinks=False)
        return runtime.st_dev, runtime.st_ino, runtime.st_uid
    except BaseException as exc:
        for directory in reversed(created):
            directory.rmdir()
        if isinstance(exc, PerfLensError):
            raise
        raise _managed_error("Managed Docker private run directory cannot be created") from exc


def _cleanup_runtime_directory(
    path: Path,
    expected_identity: tuple[int, int, int] | None,
) -> None:
    if expected_identity is None:
        return
    try:
        metadata = path.stat(follow_symlinks=False)
        if (
            stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and (metadata.st_dev, metadata.st_ino, metadata.st_uid) == expected_identity
        ):
            shutil.rmtree(path)
    except OSError:
        return


def _retire_gate_listener(listener: _BoundGateListener) -> None:
    listener.close()
    try:
        metadata = listener.path.stat(follow_symlinks=False)
        if not stat.S_ISSOCK(metadata.st_mode) or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
        ) != (listener.device, listener.inode, listener.owner_uid):
            raise _managed_error("Container Gate control path was replaced")
        listener.path.unlink()
    except OSError as exc:
        raise _managed_error("Container Gate control path cannot be retired safely") from exc


def _dict_field(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise _managed_error("Managed Docker inspect omitted one required object")
    return cast(dict[str, Any], value)


def _empty_sequence(value: object) -> bool:
    return value is None or value == [] or value == ()


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(values)) != len(values):
        raise _managed_error(f"Managed Docker {label} contain duplicates")
    return tuple(sorted(values))


def _verify_content(artifact: object, expected: str, label: str) -> None:
    if not hmac.compare_digest(
        contract_content_sha256(cast(Any, artifact), exclude={"content_sha256"}),
        expected,
    ):
        raise _managed_error(f"Managed Docker {label} content digest does not match")


def _format_cpu_limit(value: float) -> str:
    formatted = format(Decimal(str(value)).normalize(), "f")
    if "." in formatted:
        formatted = formatted.rstrip("0").rstrip(".")
    return formatted


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _managed_error(message: str, *, recoverable: bool = False) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_managed_coordinator",
        message,
        recoverable=recoverable,
    )
