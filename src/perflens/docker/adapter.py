"""Fixed, bounded Docker CLI adapter for a local Unix endpoint only."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, cast

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner

_CONTAINER_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_DOCKER_BINARY_BYTES = 128 << 20
_MAX_JSON_BYTES = 1 << 20
_MAX_TOP_BYTES = 1 << 20
_MANAGED_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_MANAGED_CONTAINER_NAME = re.compile(r"^perflens-[a-f0-9]{20}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CONTAINER_USER = re.compile(r"^[0-9]{1,10}(?::[0-9]{1,10})?$")
_CANONICAL_CPUS = re.compile(r"^(?:0\.[0-9]{1,6}|[1-9][0-9]{0,3}(?:\.[0-9]{1,6})?)$")
_GATE_CONTAINER_PATH = "/usr/lib/perflens/perflens-container-gate"
_CONTROL_CONTAINER_PATH = "/run/perflens-gate"
_CONTROL_SOCKET_PATH = f"{_CONTROL_CONTAINER_PATH}/control.sock"


@dataclass(frozen=True, slots=True)
class DockerEndpointSnapshot:
    path: Path
    kind: Literal["local_rootful", "local_rootless"]
    device: int
    inode: int
    ctime_ns: int
    owner_uid: int
    owner_gid: int
    mode: int


@dataclass(frozen=True, slots=True)
class DockerCliIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    size: int
    trusted_owner_uids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ManagedDockerCreateRequest:
    """Strongly typed inputs for the one fixed managed-container recipe."""

    container_name: str
    image_digest: str
    project_root: Path
    scratch_root: Path
    control_root: Path
    gate_path: Path
    gate_sha256: str
    workload_entrypoint: str
    workload_arguments: tuple[str, ...]
    working_directory: str
    container_user: str
    cpus: str
    memory_bytes: int
    pids: int
    session_identity_sha256: str
    workload_spec_sha256: str
    creation_receipt_sha256: str


class DockerCommandAdapter:
    """Execute only reviewed local-Docker recipes with fixed argument layouts."""

    def __init__(
        self,
        *,
        docker_path: Path,
        endpoint_path: Path,
        endpoint_kind: Literal["local_rootful", "local_rootless"],
        config_directory: Path,
        trusted_cli_owner_uids: tuple[int, ...] = (0,),
        trusted_gate_owner_uids: tuple[int, ...] = (0,),
        invoking_uid: int | None = None,
    ) -> None:
        self._invoking_uid = os.geteuid() if invoking_uid is None else invoking_uid
        self._cli = inspect_docker_cli(
            docker_path,
            trusted_owner_uids=trusted_cli_owner_uids,
        )
        if not trusted_gate_owner_uids:
            raise _managed_error("Managed Container Gate requires trusted owner UIDs")
        self._trusted_gate_owner_uids = trusted_gate_owner_uids
        self._config_directory = inspect_empty_docker_config_directory(
            config_directory,
            trusted_owner_uids=trusted_cli_owner_uids,
        )
        self._endpoint = inspect_docker_endpoint(
            endpoint_path,
            kind=endpoint_kind,
            invoking_uid=self._invoking_uid,
        )
        self._runner = CommandRunner({self._cli.path})

    @property
    def cli_identity(self) -> DockerCliIdentity:
        return self._cli

    @property
    def endpoint_identity(self) -> DockerEndpointSnapshot:
        return self._endpoint

    def version_info(self) -> dict[str, Any]:
        return self._run_json(("version", "--format", "{{json .}}"))

    def daemon_info(self) -> dict[str, Any]:
        return self._run_json(("info", "--format", "{{json .}}"))

    def inspect_container(self, container_reference: str) -> dict[str, Any]:
        reference = _validate_container_reference(container_reference)
        return self._run_json(
            ("container", "inspect", "--format", "{{json .}}", reference)
        )

    def top_container(self, container_reference: str) -> str:
        reference = _validate_container_reference(container_reference)
        payload = self._run_bytes(
            ("container", "top", reference, "-eo", "pid,ppid,comm"),
            max_stdout_bytes=_MAX_TOP_BYTES,
        )
        try:
            return payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "docker_adapter",
                "Docker process inventory is not valid UTF-8",
                recoverable=True,
            ) from exc

    def create_managed_container(self, request: ManagedDockerCreateRequest) -> str:
        payload = self._run_bytes(
            _managed_create_arguments(
                request,
                invoking_uid=self._invoking_uid,
                trusted_gate_owner_uids=self._trusted_gate_owner_uids,
            ),
            max_stdout_bytes=128,
            timeout_seconds=15,
        )
        return _parse_managed_container_id(payload, "create")

    def start_managed_container(self, container_id: str) -> None:
        reference = _validate_full_container_id(container_id)
        payload = self._run_bytes(
            ("container", "start", reference),
            max_stdout_bytes=128,
            timeout_seconds=15,
        )
        if _parse_managed_container_id(payload, "start") != reference:
            raise _managed_error("Docker start returned a different container identity")

    def wait_managed_container(self, container_id: str, *, timeout_seconds: int) -> int:
        reference = _validate_full_container_id(container_id)
        if not 1 <= timeout_seconds <= 1_260:
            raise _managed_error("Managed Docker wait timeout is outside its fixed bound")
        payload = self._run_bytes(
            ("container", "wait", reference),
            max_stdout_bytes=32,
            timeout_seconds=timeout_seconds,
        )
        try:
            value = int(payload.decode("ascii", errors="strict").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise _managed_error("Docker wait returned an invalid exit status") from exc
        if not 0 <= value <= 255:
            raise _managed_error("Docker wait exit status is outside the process range")
        return value

    def stop_managed_container(self, container_id: str) -> None:
        reference = _validate_full_container_id(container_id)
        payload = self._run_bytes(
            ("container", "stop", "--time", "2", reference),
            max_stdout_bytes=128,
            timeout_seconds=10,
        )
        if _parse_managed_container_id(payload, "stop") != reference:
            raise _managed_error("Docker stop returned a different container identity")

    def remove_managed_container(self, container_id: str) -> None:
        reference = _validate_full_container_id(container_id)
        payload = self._run_bytes(
            ("container", "rm", reference),
            max_stdout_bytes=128,
            timeout_seconds=10,
        )
        if _parse_managed_container_id(payload, "remove") != reference:
            raise _managed_error("Docker remove returned a different container identity")

    def _run_json(self, args: tuple[str, ...]) -> dict[str, Any]:
        payload = self._run_bytes(args, max_stdout_bytes=_MAX_JSON_BYTES)
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "docker_adapter",
                "Docker returned malformed bounded JSON",
                recoverable=True,
            ) from exc
        if not isinstance(decoded, dict):
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "docker_adapter",
                "Docker returned an unexpected JSON shape",
                recoverable=True,
            )
        return cast(dict[str, Any], decoded)

    def _run_bytes(
        self,
        args: tuple[str, ...],
        *,
        max_stdout_bytes: int,
        timeout_seconds: int = 5,
    ) -> bytes:
        if not 1 <= timeout_seconds <= 1_260:
            raise _managed_error("Docker command timeout is outside its fixed bound")
        assert_docker_cli_current(self._cli)
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        output = io.BytesIO()
        self._runner.run_to_file(
            (
                str(self._cli.path),
                "--config",
                str(self._config_directory),
                "--host",
                f"unix://{self._endpoint.path}",
                *args,
            ),
            output,
            limits=CommandLimits(
                timeout_seconds=timeout_seconds,
                terminate_grace_seconds=0.5,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=64 << 10,
            ),
        )
        assert_docker_cli_current(self._cli)
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        return output.getvalue()


def _managed_create_arguments(
    request: ManagedDockerCreateRequest,
    *,
    invoking_uid: int,
    trusted_gate_owner_uids: tuple[int, ...],
) -> tuple[str, ...]:
    if not _MANAGED_CONTAINER_NAME.fullmatch(request.container_name):
        raise _managed_error("Managed Docker container name is invalid")
    if not _IMAGE_DIGEST.fullmatch(request.image_digest):
        raise _managed_error("Managed Docker image must use one immutable digest")
    if any(
        not _SHA256.fullmatch(value)
        for value in (
            request.session_identity_sha256,
            request.workload_spec_sha256,
            request.creation_receipt_sha256,
        )
    ):
        raise _managed_error("Managed Docker labels require bounded SHA-256 identities")
    project = _validate_mount_source(
        request.project_root,
        kind="directory",
        expected_uid=invoking_uid,
        require_private=False,
    )
    scratch = _validate_mount_source(
        request.scratch_root,
        kind="directory",
        expected_uid=invoking_uid,
        require_private=True,
    )
    control = _validate_mount_source(
        request.control_root,
        kind="directory",
        expected_uid=invoking_uid,
        require_private=True,
    )
    gate = _validate_mount_source(
        request.gate_path,
        kind="executable",
        expected_uid=None,
        require_private=False,
        trusted_owner_uids=trusted_gate_owner_uids,
        expected_sha256=request.gate_sha256,
    )
    if len({project, scratch, control, gate}) != 4:
        raise _managed_error("Managed Docker mount sources must be distinct")
    if any(
        _paths_overlap(left, right)
        for left, right in ((project, scratch), (project, control), (scratch, control))
    ):
        raise _managed_error("Managed Docker project, scratch, and control roots must be disjoint")
    _validate_container_path(request.workload_entrypoint, "workload entrypoint")
    _validate_container_path(request.working_directory, "working directory")
    if (
        len(request.workload_arguments) > 256
        or sum(len(value.encode("utf-8")) for value in request.workload_arguments) > 65_536
        or any(
            "\x00" in value or len(value.encode("utf-8")) > 4096
            for value in request.workload_arguments
        )
    ):
        raise _managed_error("Managed Docker workload arguments exceed their fixed bound")
    if not _CONTAINER_USER.fullmatch(request.container_user):
        raise _managed_error("Managed Docker user must be a numeric UID or UID:GID")
    user_ids = tuple(int(value) for value in request.container_user.split(":"))
    if any(value > 4_294_967_295 for value in user_ids):
        raise _managed_error("Managed Docker UID/GID exceeds the Linux range")
    try:
        cpus = Decimal(request.cpus)
    except InvalidOperation as exc:
        raise _managed_error("Managed Docker CPU limit is invalid") from exc
    if (
        not _CANONICAL_CPUS.fullmatch(request.cpus)
        or not cpus.is_finite()
        or cpus <= 0
        or cpus > 1024
    ):
        raise _managed_error("Managed Docker CPU limit is outside its fixed bound")
    if not 6 << 20 <= request.memory_bytes <= 1 << 50 or not 1 <= request.pids <= 1_000_000:
        raise _managed_error("Managed Docker memory or PID limit is outside its fixed bound")
    labels = (
        "io.perflens.managed=true",
        f"io.perflens.session-sha256={request.session_identity_sha256}",
        f"io.perflens.workload-sha256={request.workload_spec_sha256}",
        f"io.perflens.receipt-sha256={request.creation_receipt_sha256}",
    )
    arguments: list[str] = [
        "container",
        "create",
        "--name",
        request.container_name,
        "--pull",
        "never",
        "--network",
        "none",
        "--restart",
        "no",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        request.container_user,
        "--workdir",
        request.working_directory,
        "--cpus",
        request.cpus,
        "--memory",
        str(request.memory_bytes),
        "--pids-limit",
        str(request.pids),
    ]
    for label in labels:
        arguments.extend(("--label", label))
    arguments.extend(
        (
            "--mount",
            f"type=bind,src={project},dst=/workspace,readonly",
            "--mount",
            f"type=bind,src={scratch},dst=/perflens-scratch",
            "--mount",
            f"type=bind,src={control},dst={_CONTROL_CONTAINER_PATH},readonly",
            "--mount",
            f"type=bind,src={gate},dst={_GATE_CONTAINER_PATH},readonly",
            "--entrypoint",
            _GATE_CONTAINER_PATH,
            request.image_digest,
            "--control",
            _CONTROL_SOCKET_PATH,
            "--",
            request.workload_entrypoint,
            *request.workload_arguments,
        )
    )
    return tuple(arguments)


def _validate_mount_source(
    path: Path,
    *,
    kind: Literal["directory", "executable"],
    expected_uid: int | None,
    require_private: bool,
    trusted_owner_uids: tuple[int, ...] = (),
    expected_sha256: str | None = None,
) -> Path:
    if not path.is_absolute() or path.is_symlink() or any(
        value in str(path) for value in (",", "\x00", "\n", "\r")
    ):
        raise _managed_error("Managed Docker mount source path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _managed_error("Managed Docker mount source is unavailable") from exc
    if resolved != path or metadata.st_nlink < 1:
        raise _managed_error("Managed Docker mount source identity is unsafe")
    if kind == "directory":
        valid_type = stat.S_ISDIR(metadata.st_mode)
    else:
        valid_type = stat.S_ISREG(metadata.st_mode) and bool(metadata.st_mode & 0o111)
    if not valid_type or (expected_uid is not None and metadata.st_uid != expected_uid):
        raise _managed_error("Managed Docker mount source type or owner is unsafe")
    if trusted_owner_uids and metadata.st_uid not in trusted_owner_uids:
        raise _managed_error("Managed Docker Gate owner is outside the trusted policy")
    if require_private and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise _managed_error("Managed Docker private mount source must use mode 0700")
    if kind == "executable" and (metadata.st_nlink != 1 or metadata.st_mode & 0o022):
        raise _managed_error("Managed Docker Gate mount is writable or multiply linked")
    if expected_sha256 is not None:
        if not _SHA256.fullmatch(expected_sha256):
            raise _managed_error("Managed Docker Gate SHA-256 is invalid")
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise _managed_error("Managed Docker Gate cannot be hashed") from exc
        if digest != expected_sha256:
            raise _managed_error("Managed Docker Gate content differs from the authorized binary")
    return resolved


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_container_path(value: str, label: str) -> None:
    if (
        not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
        or "//" in value
        or "/../" in f"{value}/"
        or "/./" in f"{value}/"
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _managed_error(f"Managed Docker {label} is not absolute and normalized")


def _validate_full_container_id(value: str) -> str:
    if not _MANAGED_CONTAINER_ID.fullmatch(value):
        raise _managed_error("Managed Docker lifecycle requires one full container ID")
    return value


def _parse_managed_container_id(payload: bytes, operation: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise _managed_error(f"Docker {operation} returned a non-ASCII identity") from exc
    return _validate_full_container_id(value)


def _managed_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_managed_adapter",
        message,
        recoverable=True,
    )


def inspect_docker_cli(
    path: Path,
    *,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> DockerCliIdentity:
    if not path.is_absolute() or not trusted_owner_uids:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI must be an absolute path with a trusted owner policy",
        )
    _validate_trusted_parents(path, trusted_owner_uids=trusted_owner_uids)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI cannot be opened without following a symbolic link",
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in trusted_owner_uids
            or before.st_mode & 0o022
            or not before.st_mode & 0o111
            or before.st_size <= 0
            or before.st_size > _MAX_DOCKER_BINARY_BYTES
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_adapter",
                "Docker CLI owner, type, mode, size, or executable bits are unsafe",
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_adapter",
                "Docker CLI changed while its identity was being measured",
            )
        resolved = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        if resolved != path:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_adapter",
                "Docker CLI resolved to an unexpected path",
            )
        return DockerCliIdentity(
            path=resolved,
            sha256=digest.hexdigest(),
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            trusted_owner_uids=trusted_owner_uids,
        )
    finally:
        os.close(descriptor)


def assert_docker_cli_current(identity: DockerCliIdentity) -> None:
    current = inspect_docker_cli(
        identity.path,
        trusted_owner_uids=identity.trusted_owner_uids,
    )
    if current != identity:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI identity changed after validation",
            recoverable=True,
        )


def inspect_docker_endpoint(
    path: Path,
    *,
    kind: Literal["local_rootful", "local_rootless"],
    invoking_uid: int,
) -> DockerEndpointSnapshot:
    if not path.is_absolute() or path.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker endpoint must be an absolute, non-symlink Unix socket",
        )
    expected_owner = 0 if kind == "local_rootful" else invoking_uid
    _validate_trusted_parents(path, trusted_owner_uids=(0, expected_owner))
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "docker_adapter",
            "Local Docker endpoint is unavailable",
            recoverable=True,
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or metadata.st_mode & 0o002
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker endpoint type, owner, or permissions are unsafe",
        )
    return DockerEndpointSnapshot(
        path=path,
        kind=kind,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        ctime_ns=metadata.st_ctime_ns,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def assert_docker_endpoint_current(
    identity: DockerEndpointSnapshot,
    *,
    invoking_uid: int,
) -> None:
    current = inspect_docker_endpoint(
        identity.path,
        kind=identity.kind,
        invoking_uid=invoking_uid,
    )
    if current != identity:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker endpoint identity changed after validation",
            recoverable=True,
        )


def inspect_empty_docker_config_directory(
    path: Path,
    *,
    trusted_owner_uids: tuple[int, ...],
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI config directory must be absolute and non-symlinked",
        )
    _validate_trusted_parents(path, trusted_owner_uids=trusted_owner_uids)
    try:
        metadata = path.stat(follow_symlinks=False)
        entries = tuple(path.iterdir())
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI config directory cannot be inspected safely",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in trusted_owner_uids
        or metadata.st_mode & 0o022
        or entries
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "docker_adapter",
            "Docker CLI config directory must be trusted, non-writable, and empty",
        )
    return path


def _validate_trusted_parents(path: Path, *, trusted_owner_uids: tuple[int, ...]) -> None:
    current = path.parent
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_adapter",
                "Docker adapter path parent cannot be inspected",
            ) from exc
        writable = bool(metadata.st_mode & 0o022)
        trusted_sticky_directory = bool(
            metadata.st_mode & stat.S_ISVTX and metadata.st_uid in trusted_owner_uids
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in trusted_owner_uids
            or (writable and not trusted_sticky_directory)
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "docker_adapter",
                "Docker adapter path has an unsafe writable or untrusted parent",
            )
        if current == current.parent:
            break
        current = current.parent


def _validate_container_reference(value: str) -> str:
    if not _CONTAINER_REFERENCE.fullmatch(value):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "docker_adapter",
            "Container name or ID contains unsupported characters",
        )
    return value
