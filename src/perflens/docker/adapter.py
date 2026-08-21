"""Fixed, bounded Docker CLI adapter for a local Unix endpoint only."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner

_CONTAINER_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_DOCKER_BINARY_BYTES = 128 << 20
_MAX_JSON_BYTES = 1 << 20
_MAX_TOP_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class DockerEndpointSnapshot:
    path: Path
    kind: Literal["local_rootful", "local_rootless"]
    device: int
    inode: int
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


class DockerCommandAdapter:
    """Execute only reviewed, read-only Docker commands with fixed arguments."""

    def __init__(
        self,
        *,
        docker_path: Path,
        endpoint_path: Path,
        endpoint_kind: Literal["local_rootful", "local_rootless"],
        config_directory: Path,
        trusted_cli_owner_uids: tuple[int, ...] = (0,),
        invoking_uid: int | None = None,
    ) -> None:
        self._invoking_uid = os.geteuid() if invoking_uid is None else invoking_uid
        self._cli = inspect_docker_cli(
            docker_path,
            trusted_owner_uids=trusted_cli_owner_uids,
        )
        self._config_directory = _validate_empty_config_directory(
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

    def _run_bytes(self, args: tuple[str, ...], *, max_stdout_bytes: int) -> bytes:
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
                timeout_seconds=5,
                terminate_grace_seconds=0.5,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=64 << 10,
            ),
        )
        assert_docker_cli_current(self._cli)
        assert_docker_endpoint_current(self._endpoint, invoking_uid=self._invoking_uid)
        return output.getvalue()


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


def _validate_empty_config_directory(
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
