"""Build content-bound managed Docker workload specifications."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    AuthorizationMode,
    CollectionMode,
    ContainerResourceLimits,
    ContainerWorkloadSpecArtifact,
)
from perflens.docker.elf import validate_self_contained_elf
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_GATE_BYTES = 32 << 20
_CANONICAL_MODES: tuple[CollectionMode, ...] = (
    "stat",
    "record",
    "sched",
    "off_cpu",
    "lock",
)


@dataclass(frozen=True, slots=True)
class ManagedProjectIdentity:
    path: Path
    owner_uid: int
    device: int
    inode: int
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class ContainerGateIdentity:
    path: Path
    owner_uid: int
    device: int
    inode: int
    size: int
    modified_ns: int
    sha256: str
    trusted_owner_uids: tuple[int, ...]


def inspect_managed_project_root(
    path: Path,
    *,
    invoking_uid: int | None = None,
) -> ManagedProjectIdentity:
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    canonical, metadata = _inspect_canonical_path(path, require_directory=True)
    if metadata.st_uid != uid:
        raise _workload_error("Managed Docker project root must be owned by the invoking user")
    identity = _hash_parts(
        "perflens-managed-project-v1",
        str(canonical),
        str(metadata.st_dev),
        str(metadata.st_ino),
        str(metadata.st_uid),
    )
    return ManagedProjectIdentity(
        path=canonical,
        owner_uid=metadata.st_uid,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        identity_sha256=identity,
    )


def assert_managed_project_current(identity: ManagedProjectIdentity) -> None:
    current = inspect_managed_project_root(identity.path, invoking_uid=identity.owner_uid)
    if current != identity:
        raise _workload_error(
            "Managed Docker project root identity changed after authorization",
            recoverable=True,
        )


def inspect_container_gate(
    path: Path,
    *,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> ContainerGateIdentity:
    if not trusted_owner_uids:
        raise _workload_error("Container Gate requires a non-empty trusted owner policy")
    canonical, _ = _inspect_canonical_path(path, require_directory=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(canonical, flags)
    except OSError as exc:
        raise _workload_error("Container Gate cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted_owner_uids
            or before.st_mode & 0o022
            or not before.st_mode & 0o111
            or not 1 <= before.st_size <= _MAX_GATE_BYTES
        ):
            raise _workload_error(
                "Container Gate owner, link count, mode, size, or executable bits are unsafe"
            )
        try:
            validate_self_contained_elf(descriptor, file_size=before.st_size)
        except ValueError as exc:
            raise _workload_error(str(exc)) from exc
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise _workload_error("Container Gate changed while it was being hashed")
        return ContainerGateIdentity(
            path=canonical,
            owner_uid=before.st_uid,
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            sha256=digest.hexdigest(),
            trusted_owner_uids=trusted_owner_uids,
        )
    finally:
        os.close(descriptor)


def assert_container_gate_current(identity: ContainerGateIdentity) -> None:
    current = inspect_container_gate(
        identity.path,
        trusted_owner_uids=identity.trusted_owner_uids,
    )
    if current != identity:
        raise _workload_error(
            "Container Gate identity changed after authorization",
            recoverable=True,
        )


def build_container_workload_spec(
    *,
    project: ManagedProjectIdentity,
    gate: ContainerGateIdentity,
    image_digest: str,
    entrypoint: str,
    arguments: tuple[str, ...] = (),
    working_directory: str = "/workspace",
    container_user: str,
    cpus: float,
    memory_bytes: int,
    pids: int,
    allowed_modes: tuple[CollectionMode, ...] = ("stat", "record"),
    authorization_mode: AuthorizationMode = "bounded_session",
    max_workload_runs: int = 6,
    max_active_seconds: int = 1200,
    hard_expiry_seconds: int = 7200,
    trace_max_duration_seconds: int = 10,
    correctness_command_sha256: str | None = None,
    benchmark_output_contract_sha256: str | None = None,
    treatment_paths: tuple[str, ...] = (),
    created_at: datetime | None = None,
) -> ContainerWorkloadSpecArtifact:
    assert_managed_project_current(project)
    assert_container_gate_current(gate)
    modes = _canonical_modes(allowed_modes)
    treatment_path_sha256 = _treatment_path_hashes(treatment_paths)
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _workload_error("Container workload timestamp must include a timezone")
    fingerprint = _hash_parts(
        "perflens-container-workload-v1",
        project.identity_sha256,
        image_digest,
        gate.sha256,
        entrypoint,
        *arguments,
        working_directory,
        container_user,
        str(cpus),
        str(memory_bytes),
        str(pids),
        *modes,
        authorization_mode,
        str(max_workload_runs),
        str(max_active_seconds),
        str(hard_expiry_seconds),
        str(trace_max_duration_seconds),
        correctness_command_sha256 or "",
        benchmark_output_contract_sha256 or "",
        *treatment_path_sha256,
    )
    created_at_text = timestamp.isoformat()
    artifact_identity = _hash_parts(
        "perflens-container-workload-artifact-v1",
        __version__,
        fingerprint,
        created_at_text,
    )
    provisional = ContainerWorkloadSpecArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        workload_spec_id=f"container-workload-{artifact_identity[:20]}",
        created_at=created_at_text,
        project_identity_sha256=project.identity_sha256,
        image_digest=image_digest,
        container_gate_sha256=gate.sha256,
        entrypoint=entrypoint,
        arguments=arguments,
        working_directory=working_directory,
        container_user=container_user,
        resources=ContainerResourceLimits(
            cpus=cpus,
            memory_bytes=memory_bytes,
            pids=pids,
        ),
        allowed_modes=modes,
        authorization_mode=authorization_mode,
        max_workload_runs=max_workload_runs,
        max_active_seconds=max_active_seconds,
        hard_expiry_seconds=hard_expiry_seconds,
        trace_max_duration_seconds=trace_max_duration_seconds,
        correctness_command_sha256=correctness_command_sha256,
        benchmark_output_contract_sha256=benchmark_output_contract_sha256,
        treatment_path_sha256=treatment_path_sha256,
        workload_fingerprint=fingerprint,
        content_sha256="0" * 64,
    )
    return ContainerWorkloadSpecArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _canonical_modes(modes: tuple[CollectionMode, ...]) -> tuple[CollectionMode, ...]:
    if not modes or len(set(modes)) != len(modes):
        raise _workload_error("Container workload modes must be non-empty and unique")
    return tuple(mode for mode in _CANONICAL_MODES if mode in modes)


def _treatment_path_hashes(paths: tuple[str, ...]) -> tuple[str, ...]:
    if len(paths) > 32 or len(set(paths)) != len(paths):
        raise _workload_error("Container treatment paths must be unique and bounded")
    hashes: list[str] = []
    for value in paths:
        path = PurePosixPath(value)
        if (
            not value
            or value.startswith("/")
            or "\x00" in value
            or len(value.encode("utf-8")) > 4096
            or str(path) != value
            or value in {".", ".."}
            or ".." in path.parts
        ):
            raise _workload_error(
                "Container treatment path must be normalized and project-relative"
            )
        hashes.append(
            hashlib.sha256(f"perflens-container-treatment-path-v1\0{value}".encode()).hexdigest()
        )
    return tuple(sorted(hashes))


def _inspect_canonical_path(path: Path, *, require_directory: bool) -> tuple[Path, os.stat_result]:
    if not path.is_absolute() or path.is_symlink():
        raise _workload_error("Managed Docker host path must be absolute and non-symlinked")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _workload_error("Managed Docker host path is unavailable") from exc
    expected_type = (
        stat.S_ISDIR(metadata.st_mode) if require_directory else stat.S_ISREG(metadata.st_mode)
    )
    if canonical != path or not expected_type:
        raise _workload_error("Managed Docker host path type or canonical identity is invalid")
    return canonical, metadata


def _hash_parts(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _workload_error(message: str, *, recoverable: bool = False) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_workload",
        message,
        recoverable=recoverable,
    )
