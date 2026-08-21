"""Deterministic Docker-to-Linux process identity verification.

Docker discovery is only a hint.  A target becomes usable after its host PID,
UID, start time, namespace identities, and cgroup-v2 directory are read from
one pinned procfs process directory and matched to the container init process.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import ContainerTargetArtifact, DockerTargetKind
from perflens.docker.adapter import DockerCommandAdapter
from perflens.domain.errors import ErrorCode, PerfLensError

_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_NAMESPACE_LINK = re.compile(r"^(?P<kind>pid|user|mnt|cgroup):\[(?P<inode>[1-9][0-9]*)\]$")
_MAX_PROC_FILE_BYTES = 64 << 10
_MAX_TOP_ROWS = 256
_READ_RECIPE_ID = "local-docker-read-v1"
_MANAGED_RECIPE_ID = "local-docker-managed-v1"


@dataclass(frozen=True, slots=True)
class PrivateContainerInstance:
    """Private Docker identity; full IDs never enter public artifacts or errors."""

    container_id: str
    image_digest: str
    init_host_pid: int


@dataclass(frozen=True, slots=True)
class PrivateProcessHint:
    host_pid: int
    parent_host_pid: int
    executable_name: str


@dataclass(frozen=True, slots=True)
class NamespaceIdentity:
    pid: int
    user: int
    mount: int
    cgroup: int


@dataclass(frozen=True, slots=True)
class KernelProcessIdentity:
    host_pid: int
    host_uid: int
    host_start_time_ticks: int
    container_pid: int
    nspid: tuple[int, ...]
    executable_name: str
    namespace: NamespaceIdentity
    cgroup_relative_path: str
    cgroup_inode: int


@dataclass(frozen=True, slots=True)
class ResolvedContainerTarget:
    instance: PrivateContainerInstance
    kernel: KernelProcessIdentity
    artifact: ContainerTargetArtifact


class LinuxContainerIdentityReader:
    """Read fixed procfs and cgroup-v2 roots; roots are not user CLI inputs."""

    def __init__(
        self,
        *,
        proc_root: Path = Path("/proc"),
        cgroup_root: Path = Path("/sys/fs/cgroup"),
    ) -> None:
        self._proc_root = _validate_filesystem_root(proc_root, "procfs")
        self._cgroup_root = _validate_filesystem_root(cgroup_root, "cgroup v2")

    def inspect_process(self, host_pid: int) -> KernelProcessIdentity:
        if host_pid <= 0 or host_pid == os.getpid():
            raise _identity_error("Docker host PID is invalid")
        process_path = self._proc_root / str(host_pid)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(process_path, flags)
        except OSError as exc:
            raise _identity_error("Docker target process is unavailable", recoverable=True) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode):
                raise _identity_error("Docker target procfs entry is not a directory")
            first = self._read_snapshot(descriptor, host_pid, proc_owner_uid=opened.st_uid)
            second = self._read_snapshot(descriptor, host_pid, proc_owner_uid=opened.st_uid)
            if first != second:
                raise _identity_error(
                    "Docker target identity changed while it was being verified",
                    recoverable=True,
                )
            try:
                current = process_path.stat(follow_symlinks=False)
            except OSError as exc:
                raise _identity_error(
                    "Docker target exited during identity verification",
                    recoverable=True,
                ) from exc
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise _identity_error(
                    "Docker target PID was replaced during identity verification",
                    recoverable=True,
                )
            return first
        finally:
            os.close(descriptor)

    def inspect_cpu_time_ticks(self, identity: KernelProcessIdentity) -> int:
        """Read CPU ticks only after rebinding the exact PID incarnation."""
        process_path = self._proc_root / str(identity.host_pid)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(process_path, flags)
        except OSError as exc:
            raise _identity_error(
                "Docker process disappeared during CPU observation",
                recoverable=True,
            ) from exc
        try:
            opened = os.fstat(descriptor)
            start_time, cpu_ticks = _parse_stat_counters(
                _read_proc_text(descriptor, "stat")
            )
            if opened.st_uid != identity.host_uid or start_time != identity.host_start_time_ticks:
                raise _identity_error(
                    "Docker process identity changed during CPU observation",
                    recoverable=True,
                )
            try:
                current = process_path.stat(follow_symlinks=False)
            except OSError as exc:
                raise _identity_error(
                    "Docker process exited during CPU observation",
                    recoverable=True,
                ) from exc
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise _identity_error(
                    "Docker process PID was reused during CPU observation",
                    recoverable=True,
                )
            return cpu_ticks
        finally:
            os.close(descriptor)

    def _read_snapshot(
        self,
        descriptor: int,
        host_pid: int,
        *,
        proc_owner_uid: int,
    ) -> KernelProcessIdentity:
        stat_text = _read_proc_text(descriptor, "stat")
        status_text = _read_proc_text(descriptor, "status")
        cgroup_text = _read_proc_text(descriptor, "cgroup")
        comm_text = _read_proc_text(descriptor, "comm")
        start_time = _parse_start_time(stat_text)
        host_uid, nspid = _parse_status(status_text, expected_host_pid=host_pid)
        if host_uid != proc_owner_uid:
            raise _identity_error("Docker target has an unsupported changing UID identity")
        executable_name = _parse_executable_name(comm_text)
        namespace = NamespaceIdentity(
            pid=_read_namespace_inode(descriptor, "pid"),
            user=_read_namespace_inode(descriptor, "user"),
            mount=_read_namespace_inode(descriptor, "mnt"),
            cgroup=_read_namespace_inode(descriptor, "cgroup"),
        )
        cgroup_path = _parse_cgroup_v2_path(cgroup_text)
        cgroup_inode = self._read_cgroup_inode(cgroup_path)
        return KernelProcessIdentity(
            host_pid=host_pid,
            host_uid=host_uid,
            host_start_time_ticks=start_time,
            container_pid=nspid[-1],
            nspid=nspid,
            executable_name=executable_name,
            namespace=namespace,
            cgroup_relative_path=cgroup_path,
            cgroup_inode=cgroup_inode,
        )

    def _read_cgroup_inode(self, relative_path: str) -> int:
        parts = PurePosixPath(relative_path).parts[1:]
        candidate = self._cgroup_root.joinpath(*parts)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = candidate.stat(follow_symlinks=False)
        except OSError as exc:
            raise _identity_error(
                "Docker target cgroup is unavailable",
                recoverable=True,
            ) from exc
        if resolved != candidate or not stat.S_ISDIR(metadata.st_mode) or metadata.st_ino <= 0:
            raise _identity_error("Docker target cgroup path is unsafe or invalid")
        return metadata.st_ino


def parse_container_instance(data: dict[str, Any]) -> PrivateContainerInstance:
    container_id = data.get("Id")
    image_digest = data.get("Image")
    state = data.get("State")
    if not isinstance(state, dict):
        raise _identity_error("Docker inspect omitted the bounded container state")
    state_fields = cast(dict[str, object], state)
    running = state_fields.get("Running")
    init_pid = state_fields.get("Pid")
    if (
        not isinstance(container_id, str)
        or not _CONTAINER_ID.fullmatch(container_id)
        or not isinstance(image_digest, str)
        or not _IMAGE_DIGEST.fullmatch(image_digest)
        or running is not True
        or type(init_pid) is not int
        or init_pid <= 0
    ):
        raise _identity_error("Docker inspect returned an invalid or stopped container identity")
    return PrivateContainerInstance(
        container_id=container_id,
        image_digest=image_digest,
        init_host_pid=init_pid,
    )


def parse_container_top(text: str) -> tuple[PrivateProcessHint, ...]:
    if not text or len(text.encode("utf-8")) > 1 << 20 or "\x00" in text:
        raise _identity_error("Docker process inventory is empty or exceeds its fixed limit")
    lines = text.splitlines()
    if not lines or len(lines) > _MAX_TOP_ROWS + 1:
        raise _identity_error("Docker process inventory exceeds its row limit")
    header = lines[0].split()
    if len(header) != 3 or tuple(item.upper() for item in header) not in {
        ("PID", "PPID", "COMMAND"),
        ("PID", "PPID", "COMM"),
    }:
        raise _identity_error("Docker process inventory has an unexpected fixed header")
    hints: list[PrivateProcessHint] = []
    for line in lines[1:]:
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            raise _identity_error("Docker process inventory contains a malformed row")
        try:
            host_pid = int(fields[0])
            parent_pid = int(fields[1])
        except ValueError as exc:
            raise _identity_error("Docker process inventory contains an invalid PID") from exc
        name = _validate_executable_name(fields[2])
        if host_pid <= 0 or parent_pid < 0:
            raise _identity_error("Docker process inventory contains an out-of-range PID")
        hints.append(PrivateProcessHint(host_pid, parent_pid, name))
    host_pids = tuple(item.host_pid for item in hints)
    if len(set(host_pids)) != len(host_pids):
        raise _identity_error("Docker process inventory contains duplicate host PIDs")
    return tuple(hints)


def resolve_existing_container_target(
    adapter: DockerCommandAdapter,
    container_reference: str,
    *,
    host_pid: int | None = None,
    reader: LinuxContainerIdentityReader | None = None,
    allow_rootful_cross_uid: bool = False,
    invoking_uid: int | None = None,
    created_at: datetime | None = None,
) -> ResolvedContainerTarget:
    """Resolve one existing container process and return a privacy-safe public proof."""
    instance = parse_container_instance(adapter.inspect_container(container_reference))
    hints = parse_container_top(adapter.top_container(container_reference))
    selected = _select_process_hint(hints, host_pid=host_pid)
    if not any(item.host_pid == instance.init_host_pid for item in hints):
        raise _identity_error("Docker init PID is absent from the verified process inventory")
    identity_reader = reader or LinuxContainerIdentityReader()
    init_identity = identity_reader.inspect_process(instance.init_host_pid)
    target_identity = (
        init_identity
        if selected.host_pid == instance.init_host_pid
        else identity_reader.inspect_process(selected.host_pid)
    )
    assert_container_membership(instance, init_identity, target_identity, selected)
    current_instance = parse_container_instance(adapter.inspect_container(container_reference))
    current_hints = parse_container_top(adapter.top_container(container_reference))
    current_selected = _select_process_hint(current_hints, host_pid=selected.host_pid)
    if current_instance != instance or current_selected != selected:
        raise _identity_error(
            "Docker container or selected process changed during identity verification",
            recoverable=True,
        )
    if not any(item.host_pid == instance.init_host_pid for item in current_hints):
        raise _identity_error(
            "Docker init PID changed during identity verification",
            recoverable=True,
        )
    current_init_identity = identity_reader.inspect_process(instance.init_host_pid)
    current_target_identity = (
        current_init_identity
        if selected.host_pid == instance.init_host_pid
        else identity_reader.inspect_process(selected.host_pid)
    )
    if current_init_identity != init_identity or current_target_identity != target_identity:
        raise _identity_error(
            "Docker Linux process identity changed before target publication",
            recoverable=True,
        )
    uid_mapping = classify_container_uid_mapping(
        adapter,
        target_identity,
        invoking_uid=invoking_uid,
        allow_rootful_cross_uid=allow_rootful_cross_uid,
    )
    timestamp = created_at or datetime.now(tz=UTC)
    artifact = _build_container_target_artifact(
        adapter=adapter,
        instance=instance,
        target=target_identity,
        target_kind="existing_container",
        uid_mapping=uid_mapping,
        rootful_risk_authorized=uid_mapping == "rootful_cross_uid",
        created_at=timestamp,
    )
    return ResolvedContainerTarget(instance, target_identity, artifact)


def _select_process_hint(
    hints: tuple[PrivateProcessHint, ...],
    *,
    host_pid: int | None,
) -> PrivateProcessHint:
    if host_pid is None:
        if len(hints) != 1:
            raise _identity_error(
                "Container has multiple process candidates; an explicit target is required"
            )
        return hints[0]
    matches = tuple(item for item in hints if item.host_pid == host_pid)
    if len(matches) != 1:
        raise _identity_error("Selected host PID is not a current container process")
    return matches[0]


def assert_container_membership(
    instance: PrivateContainerInstance,
    init: KernelProcessIdentity,
    target: KernelProcessIdentity,
    hint: PrivateProcessHint,
) -> None:
    if init.host_pid != instance.init_host_pid or init.container_pid != 1 or len(init.nspid) < 2:
        raise _identity_error("Docker init process does not have an isolated PID namespace")
    if target.host_pid != hint.host_pid or target.executable_name != hint.executable_name:
        raise _identity_error("Docker process hint changed before Linux identity verification")
    if len(target.nspid) < 2:
        raise _identity_error("Docker target does not have an isolated container PID")
    if (
        target.namespace != init.namespace
        or target.cgroup_relative_path != init.cgroup_relative_path
        or target.cgroup_inode != init.cgroup_inode
    ):
        raise _identity_error("Selected process is outside the container kernel identity")


def container_identity_sha256(
    adapter: DockerCommandAdapter,
    instance: PrivateContainerInstance,
) -> str:
    endpoint = adapter.endpoint_identity
    return _sha256_text(
        "container",
        instance.container_id,
        endpoint.kind,
        str(endpoint.device),
        str(endpoint.inode),
    )


def classify_container_uid_mapping(
    adapter: DockerCommandAdapter,
    target: KernelProcessIdentity,
    *,
    invoking_uid: int | None = None,
    allow_rootful_cross_uid: bool = False,
) -> Literal["rootless_same_uid", "rootful_same_uid", "rootful_cross_uid"]:
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    endpoint_kind = adapter.endpoint_identity.kind
    if endpoint_kind == "local_rootless":
        if target.host_uid != uid:
            raise _identity_error("Rootless Docker target is not owned by the invoking user")
        return "rootless_same_uid"
    if target.host_uid == uid:
        return "rootful_same_uid"
    if not allow_rootful_cross_uid:
        raise _identity_error(
            "Rootful cross-UID Docker target requires explicit administrator policy"
        )
    return "rootful_cross_uid"


def build_managed_container_target_artifact(
    *,
    adapter: DockerCommandAdapter,
    instance: PrivateContainerInstance,
    target: KernelProcessIdentity,
    invoking_uid: int | None = None,
    allow_rootful_cross_uid: bool = False,
    created_at: datetime | None = None,
) -> ContainerTargetArtifact:
    if (
        target.host_pid != instance.init_host_pid
        or target.container_pid != 1
        or len(target.nspid) < 2
    ):
        raise _identity_error(
            "Managed Docker target must be the isolated container-init Gate process"
        )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _identity_error("Managed Docker target timestamp must include a timezone")
    uid_mapping = classify_container_uid_mapping(
        adapter,
        target,
        invoking_uid=invoking_uid,
        allow_rootful_cross_uid=allow_rootful_cross_uid,
    )
    return _build_container_target_artifact(
        adapter=adapter,
        instance=instance,
        target=target,
        target_kind="managed_temporary_container",
        uid_mapping=uid_mapping,
        rootful_risk_authorized=uid_mapping == "rootful_cross_uid",
        created_at=timestamp,
    )


def _build_container_target_artifact(
    *,
    adapter: DockerCommandAdapter,
    instance: PrivateContainerInstance,
    target: KernelProcessIdentity,
    target_kind: DockerTargetKind,
    uid_mapping: Literal["rootless_same_uid", "rootful_same_uid", "rootful_cross_uid"],
    rootful_risk_authorized: bool,
    created_at: datetime,
) -> ContainerTargetArtifact:
    recipe_id = (
        _READ_RECIPE_ID
        if target_kind == "existing_container"
        else _MANAGED_RECIPE_ID
    )
    endpoint = adapter.endpoint_identity
    container_identity = container_identity_sha256(adapter, instance)
    image_identity = instance.image_digest.removeprefix("sha256:")
    cgroup_identity = _sha256_text(
        "cgroup-v2",
        container_identity,
        target.cgroup_relative_path,
        str(target.cgroup_inode),
    )
    adapter_identity = _sha256_text(
        recipe_id,
        adapter.cli_identity.sha256,
        endpoint.kind,
        (
            "version|info|container-inspect|container-top-pid-ppid-comm"
            if target_kind == "existing_container"
            else "container-create|start|inspect|top|wait|stop|remove|gate-v1"
        ),
    )
    fingerprint = _sha256_text(
        container_identity,
        image_identity,
        str(target.host_pid),
        str(target.host_uid),
        str(target.host_start_time_ticks),
        str(target.container_pid),
        str(target.namespace.pid),
        str(target.namespace.user),
        str(target.namespace.mount),
        str(target.namespace.cgroup),
        str(target.cgroup_inode),
        cgroup_identity,
    )
    timestamp = created_at.isoformat()
    target_id = _sha256_text("target", fingerprint, timestamp)[:20]
    provisional = ContainerTargetArtifact.model_validate(
        {
            "schema_version": "1.0",
            "perflens_version": __version__,
            "target_id": f"container-target-{target_id}",
            "created_at": timestamp,
            "target_kind": target_kind,
            "container_identity_sha256": container_identity,
            "image_identity_sha256": image_identity,
            "container_pid": target.container_pid,
            "host_pid": target.host_pid,
            "host_uid": target.host_uid,
            "host_start_time_ticks": target.host_start_time_ticks,
            "executable_name": target.executable_name,
            "namespace": {
                "pid_namespace_inode": target.namespace.pid,
                "user_namespace_inode": target.namespace.user,
                "mount_namespace_inode": target.namespace.mount,
                "cgroup_namespace_inode": target.namespace.cgroup,
            },
            "cgroup": {
                "version": "v2",
                "inode": target.cgroup_inode,
                "identity_sha256": cgroup_identity,
            },
            "uid_mapping": uid_mapping,
            "rootful_risk_authorized": rootful_risk_authorized,
            "adapter_recipe_id": recipe_id,
            "adapter_sha256": adapter_identity,
            "identity_fingerprint": fingerprint,
            "allowed_conclusions": (
                "The selected host PID was verified inside the local container instance.",
                "The target PID incarnation, namespace, and cgroup-v2 identity were bound.",
                *(
                    (
                        "The managed target was bound before its fixed Container Gate release.",
                    )
                    if target_kind == "managed_temporary_container"
                    else ()
                ),
            ),
            "forbidden_conclusions": (
                "Container-wide performance attribution is not implied by one process target.",
                "Docker metadata is not a substitute for Linux kernel identity verification.",
            ),
            "content_sha256": "0" * 64,
        }
    )
    return ContainerTargetArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _read_proc_text(descriptor: int, name: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(name, flags, dir_fd=descriptor)
    except OSError as exc:
        raise _identity_error("Docker target procfs identity file is unavailable") from exc
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _identity_error("Docker target procfs identity entry is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(file_descriptor, min(8192, _MAX_PROC_FILE_BYTES - total + 1)):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_PROC_FILE_BYTES:
                raise _identity_error("Docker target procfs identity exceeds its fixed limit")
        try:
            return b"".join(chunks).decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise _identity_error("Docker target procfs identity is not ASCII") from exc
    finally:
        os.close(file_descriptor)


def _parse_start_time(text: str) -> int:
    return _parse_stat_counters(text)[0]


def _parse_stat_counters(text: str) -> tuple[int, int]:
    closing = text.rfind(")")
    try:
        if closing < 0:
            raise ValueError("missing process-name terminator")
        fields = text[closing + 2 :].split()
        user_ticks = int(fields[11])
        system_ticks = int(fields[12])
        start_time = int(fields[19])
    except (ValueError, IndexError) as exc:
        raise _identity_error("Docker target procfs stat is malformed") from exc
    if start_time <= 0 or user_ticks < 0 or system_ticks < 0:
        raise _identity_error("Docker target stat counters are invalid")
    return start_time, user_ticks + system_ticks


def _parse_status(text: str, *, expected_host_pid: int) -> tuple[int, tuple[int, ...]]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"Uid", "NSpid"}:
            if key in values:
                raise _identity_error(
                    "Docker target procfs status contains duplicate identity fields"
                )
            values[key] = value.strip()
    try:
        uids = tuple(int(item) for item in values["Uid"].split())
        nspid = tuple(int(item) for item in values["NSpid"].split())
    except (KeyError, ValueError) as exc:
        raise _identity_error("Docker target procfs status is missing UID or NSpid") from exc
    if len(uids) != 4 or len(set(uids)) != 1 or uids[0] < 0:
        raise _identity_error("Docker target has an unsupported multi-UID process identity")
    if not 1 <= len(nspid) <= 64 or nspid[0] != expected_host_pid or any(pid <= 0 for pid in nspid):
        raise _identity_error("Docker target NSpid hierarchy is invalid")
    return uids[0], nspid


def _read_namespace_inode(descriptor: int, namespace: str) -> int:
    try:
        target = os.readlink(f"ns/{namespace}", dir_fd=descriptor)
    except OSError as exc:
        raise _identity_error("Docker target namespace identity is unavailable") from exc
    matched = _NAMESPACE_LINK.fullmatch(target)
    if matched is None or matched.group("kind") != namespace:
        raise _identity_error("Docker target namespace identity is malformed")
    return int(matched.group("inode"))


def _parse_cgroup_v2_path(text: str) -> str:
    lines = tuple(line for line in text.splitlines() if line)
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise _identity_error("Docker target is not bound to one cgroup-v2 path")
    value = lines[0][3:]
    if not value.startswith("/") or "\x00" in value or len(value.encode("utf-8")) > 4096:
        raise _identity_error("Docker target cgroup-v2 path is invalid")
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value:
        raise _identity_error("Docker target cgroup-v2 path is not normalized")
    return value


def _parse_executable_name(text: str) -> str:
    return _validate_executable_name(text.removesuffix("\n"))


def _validate_executable_name(value: str) -> str:
    if (
        not 1 <= len(value.encode("utf-8")) <= 255
        or "/" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _identity_error("Docker target executable name is invalid")
    return value


def _validate_filesystem_root(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} root must be an absolute non-symlink directory")
    resolved = path.resolve(strict=True)
    if resolved != path or not path.is_dir():
        raise ValueError(f"{label} root must be a canonical directory")
    return resolved


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _identity_error(message: str, *, recoverable: bool = False) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_identity",
        message,
        recoverable=recoverable,
    )
