"""Deterministic Docker build Recipe and private immutable context snapshots."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import stat
import tarfile
import tempfile
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import (
    DockerBuildContextArtifact,
    DockerBuildContextEntry,
    DockerBuildRecipeArtifact,
    DockerOptimizationBudget,
    derive_docker_build_context_id,
    derive_docker_build_recipe_id,
    docker_build_context_manifest_sha256,
)
from perflens.docker.project_config import DockerProjectPolicy
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_CONTEXT_ENTRIES = 100_000
_MAX_CONTEXT_FILE_BYTES = 512 << 20
_MAX_CONTEXT_TOTAL_BYTES = 2 << 30
_FORBIDDEN_COMPONENTS = frozenset(
    {
        ".aws",
        ".docker",
        ".git",
        ".gnupg",
        ".kube",
        ".ssh",
        ".terraform",
        "credentials",
    }
)
_DEPENDENCY_LOCK_NAMES = frozenset(
    {
        "Cargo.lock",
        "Gemfile.lock",
        "go.sum",
        "gradle.lockfile",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    owner_uid: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _PrivateContextEntry:
    relative_path: str
    absolute_path: Path
    entry_type: Literal["regular", "directory", "symlink"]
    mode: int
    size: int
    content_sha256: str | None
    symlink_target: str | None
    identity: _FileIdentity
    mutable: bool


@dataclass(frozen=True, slots=True)
class DockerBuildContextSnapshot:
    """Private archive handle plus its privacy-preserving public Artifact."""

    artifact: DockerBuildContextArtifact
    archive_path: Path
    archive_identity: _FileIdentity


class _HashingReader:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._stream.read(size)
        self._digest.update(chunk)
        self.bytes_read += len(chunk)
        return chunk

    @property
    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def build_docker_build_recipe(
    policy: DockerProjectPolicy,
    *,
    project_identity_sha256: str,
    created_at: datetime | None = None,
) -> DockerBuildRecipeArtifact:
    """Project schema 1.1 -> privacy-preserving, content-bound build Recipe."""
    optimization = policy.optimization
    if not optimization.enabled:
        raise _context_error("Docker optimization is disabled in the project policy")
    timestamp = (created_at or datetime.now(tz=UTC)).isoformat()
    context_hashes = tuple(
        sorted(_path_contract_sha256(path) for path in optimization.context_paths)
    )
    mutable_hashes = tuple(
        sorted(_path_contract_sha256(path) for path in optimization.mutable_paths)
    )
    dockerfile_mutable = any(
        _path_is_within(optimization.dockerfile, mutable) for mutable in optimization.mutable_paths
    )
    dependency_lock_mutable = any(
        PurePosixPath(path).name in _DEPENDENCY_LOCK_NAMES for path in optimization.mutable_paths
    )
    data = {
        "schema_version": "1.0",
        "perflens_version": __version__,
        "recipe_id": derive_docker_build_recipe_id(
            project_identity_sha256,
            policy.sha256,
            timestamp,
        ),
        "created_at": timestamp,
        "project_identity_sha256": project_identity_sha256,
        "project_policy_sha256": policy.sha256,
        "context_path_contract_sha256": context_hashes,
        "mutable_path_contract_sha256": mutable_hashes,
        "dockerfile_path_sha256": _path_contract_sha256(optimization.dockerfile),
        "target": optimization.target,
        "platform": optimization.platform,
        "build_arguments_sha256": _canonical_sha256(optimization.build_args),
        "base_image_digest": optimization.base_image_digest,
        "network_tier": optimization.network_tier,
        "builder_policy_id": optimization.builder_policy_id,
        "workload_contract_sha256": _canonical_sha256(
            {
                "entrypoint": policy.managed.entrypoint,
                "arguments": policy.managed.arguments,
                "working_directory": policy.managed.working_directory,
                "container_user": policy.managed.container_user,
            }
        ),
        "benchmark_contract_sha256": _canonical_sha256(
            {
                "output": policy.managed.benchmark_output,
                "format": policy.managed.benchmark_format,
                "name": policy.managed.benchmark_name,
            }
        ),
        "resource_contract_sha256": _canonical_sha256(
            {
                "cpus": policy.managed.cpus,
                "memory_bytes": policy.managed.memory_bytes,
                "pids": policy.managed.pids,
            }
        ),
        "mutable_dockerfile": dockerfile_mutable,
        "mutable_dependency_lock": dependency_lock_mutable,
        "budget": DockerOptimizationBudget(
            max_candidate_rounds=optimization.max_candidate_rounds,
            max_builds=optimization.max_builds,
            max_workload_runs=optimization.max_workload_runs,
            max_recoverable_retries=optimization.max_recoverable_retries,
            max_build_seconds=optimization.max_build_seconds,
            max_total_build_seconds=optimization.max_total_build_seconds,
            max_workload_active_seconds=optimization.max_workload_active_seconds,
            hard_expiry_seconds=optimization.hard_expiry_seconds,
            max_evidence_bytes=optimization.max_evidence_bytes,
            max_temporary_image_bytes=optimization.max_temporary_image_bytes,
            record_max_duration_seconds=optimization.record_max_duration_seconds,
            record_frequency_hz=optimization.record_frequency_hz,
            trace_max_duration_seconds=optimization.trace_max_duration_seconds,
        ),
        "content_sha256": "0" * 64,
    }
    provisional = DockerBuildRecipeArtifact.model_validate(data)
    return DockerBuildRecipeArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def capture_docker_build_context(
    policy: DockerProjectPolicy,
    recipe: DockerBuildRecipeArtifact,
    *,
    project_root: Path,
    private_directory: Path,
    invoking_uid: int | None = None,
    created_at: datetime | None = None,
) -> DockerBuildContextSnapshot:
    """Capture one verified context without exposing paths or bytes in the Artifact."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    root = _safe_directory(project_root, uid=uid, label="project root", private=False)
    private_root = _safe_directory(
        private_directory,
        uid=uid,
        label="private context directory",
        private=True,
    )
    if recipe.recipe_id != derive_docker_build_recipe_id(
        recipe.project_identity_sha256,
        policy.sha256,
        recipe.created_at,
    ) or recipe.content_sha256 != contract_content_sha256(recipe, exclude={"content_sha256"}):
        raise _context_error("Docker build Recipe does not match the current project policy")
    if tuple(sorted(_path_contract_sha256(path) for path in policy.optimization.context_paths)) != (
        recipe.context_path_contract_sha256
    ):
        raise _context_error("Docker build Recipe context paths do not match project policy")

    captured: dict[str, _PrivateContextEntry] = {}
    directory_identities: dict[Path, _FileIdentity] = {}
    for configured in policy.optimization.context_paths:
        candidate = root / configured
        _capture_entry(
            root=root,
            candidate=candidate,
            mutable_paths=policy.optimization.mutable_paths,
            invoking_uid=uid,
            captured=captured,
            directory_identities=directory_identities,
        )
    if not captured:
        raise _context_error("Docker build context is empty")
    _verify_symlink_targets(root, captured)
    regular_entries = tuple(entry for entry in captured.values() if entry.entry_type == "regular")
    total_regular_bytes = sum(entry.size for entry in regular_entries)
    if not regular_entries or total_regular_bytes > _MAX_CONTEXT_TOTAL_BYTES:
        raise _resource_error("Docker build context has no regular files or exceeds 2 GiB")
    if len(captured) > _MAX_CONTEXT_ENTRIES:
        raise _resource_error("Docker build context exceeds 100000 entries")

    archive_path: Path | None = None
    timestamp = (created_at or datetime.now(tz=UTC)).isoformat()
    try:
        descriptor, archive_name = tempfile.mkstemp(
            prefix="perflens-build-context-",
            suffix=".tar",
            dir=private_root,
        )
        archive_path = Path(archive_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w+b", closefd=True) as archive_stream:
            with tarfile.open(
                fileobj=archive_stream,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for entry in sorted(captured.values(), key=lambda item: item.relative_path):
                    _append_archive_entry(archive, entry)
            archive_stream.flush()
            os.fsync(archive_stream.fileno())
        archive_path.chmod(0o400)
        for directory, identity in directory_identities.items():
            if _identity(directory.lstat()) != identity:
                raise _context_error("Docker build context directory changed during capture")
        archive_sha256, archive_bytes = _hash_regular_file(archive_path)
        public_entries = tuple(
            sorted(
                (_public_entry(entry) for entry in captured.values()),
                key=lambda item: item.path_sha256,
            )
        )
        immutable_manifest = docker_build_context_manifest_sha256(
            tuple(entry for entry in public_entries if not entry.mutable)
        )
        mutable_manifest = docker_build_context_manifest_sha256(
            tuple(entry for entry in public_entries if entry.mutable)
        )
        if not any(entry.mutable for entry in captured.values()):
            raise _context_error("Docker build context captured no mutable entries")
        recipe_sha256 = recipe.content_sha256
        data = {
            "schema_version": "1.0",
            "perflens_version": __version__,
            "context_id": derive_docker_build_context_id(
                recipe_sha256,
                archive_sha256,
                timestamp,
            ),
            "created_at": timestamp,
            "recipe_id": recipe.recipe_id,
            "recipe_content_sha256": recipe_sha256,
            "project_identity_sha256": recipe.project_identity_sha256,
            "entry_count": len(public_entries),
            "regular_file_count": len(regular_entries),
            "mutable_entry_count": sum(entry.mutable for entry in public_entries),
            "total_regular_bytes": total_regular_bytes,
            "entries": public_entries,
            "immutable_manifest_sha256": immutable_manifest,
            "mutable_manifest_sha256": mutable_manifest,
            "archive_sha256": archive_sha256,
            "archive_bytes": archive_bytes,
            "quality_status": "verified",
            "limitations": (),
            "content_sha256": "0" * 64,
        }
        provisional = DockerBuildContextArtifact.model_validate(data)
        artifact = DockerBuildContextArtifact.model_validate(
            {
                **provisional.model_dump(mode="json"),
                "content_sha256": contract_content_sha256(
                    provisional,
                    exclude={"content_sha256"},
                ),
            }
        )
        archive_identity = _identity(archive_path.lstat())
        return DockerBuildContextSnapshot(
            artifact=artifact,
            archive_path=archive_path,
            archive_identity=archive_identity,
        )
    except Exception:
        if archive_path is not None:
            with suppress(OSError):
                archive_path.unlink(missing_ok=True)
        raise


def assert_docker_build_context_snapshot_current(snapshot: DockerBuildContextSnapshot) -> None:
    """Revalidate the private archive immediately before a typed build consumes it."""
    path = snapshot.archive_path
    if not path.is_absolute() or path.is_symlink():
        raise _context_error("Docker build context archive path changed or became a symlink")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _context_error("Docker build context archive is unavailable") from exc
    if (
        _identity(metadata) != snapshot.archive_identity
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise _context_error("Docker build context archive identity or permissions changed")
    sha256, size = _hash_regular_file(path)
    if sha256 != snapshot.artifact.archive_sha256 or size != snapshot.artifact.archive_bytes:
        raise _context_error("Docker build context archive content changed after capture")


@contextmanager
def open_docker_build_context_snapshot(
    snapshot: DockerBuildContextSnapshot,
) -> Generator[BinaryIO]:
    """Open the exact archive identity and re-hash it after the consumer returns."""
    assert_docker_build_context_snapshot_current(snapshot)
    try:
        descriptor = os.open(
            snapshot.archive_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _context_error("Docker build context archive cannot be opened safely") from exc
    try:
        if _identity(os.fstat(descriptor)) != snapshot.archive_identity:
            raise _context_error("Docker build context archive identity changed before use")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream
            stream.seek(0)
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
                size += len(chunk)
            if (
                _identity(os.fstat(descriptor)) != snapshot.archive_identity
                or digest.hexdigest() != snapshot.artifact.archive_sha256
                or size != snapshot.artifact.archive_bytes
            ):
                raise _context_error("Docker build context archive changed while it was consumed")
    finally:
        os.close(descriptor)


def _capture_entry(
    *,
    root: Path,
    candidate: Path,
    mutable_paths: tuple[str, ...],
    invoking_uid: int,
    captured: dict[str, _PrivateContextEntry],
    directory_identities: dict[Path, _FileIdentity],
) -> None:
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise _context_error("Docker build context path escapes the project") from exc
    if not relative or relative == "." or _is_forbidden(relative):
        raise _context_error("Docker build context contains a forbidden path")
    if relative in captured:
        return
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise _context_error("Docker build context entry cannot be inspected safely") from exc
    _validate_entry_metadata(before, invoking_uid=invoking_uid)
    identity = _identity(before)
    mutable = any(_path_is_within(relative, path) for path in mutable_paths)
    permissions = stat.S_IMODE(before.st_mode)
    if stat.S_ISREG(before.st_mode):
        if before.st_nlink != 1 or before.st_size > _MAX_CONTEXT_FILE_BYTES:
            raise _resource_error("Docker build context file has unsafe links or size")
        content_sha256 = _hash_verified_entry(candidate, identity)
        captured[relative] = _PrivateContextEntry(
            relative_path=relative,
            absolute_path=candidate,
            entry_type="regular",
            mode=permissions,
            size=before.st_size,
            content_sha256=content_sha256,
            symlink_target=None,
            identity=identity,
            mutable=mutable,
        )
        return
    if stat.S_ISLNK(before.st_mode):
        try:
            target = os.readlink(candidate)
            after = candidate.lstat()
        except OSError as exc:
            raise _context_error("Docker build context symlink cannot be read safely") from exc
        if _identity(after) != identity or not target or "\x00" in target or target.startswith("/"):
            raise _context_error("Docker build context symlink is absolute, empty, or unstable")
        captured[relative] = _PrivateContextEntry(
            relative_path=relative,
            absolute_path=candidate,
            entry_type="symlink",
            mode=permissions,
            size=len(target.encode("utf-8")),
            content_sha256=None,
            symlink_target=target,
            identity=identity,
            mutable=mutable,
        )
        return
    if not stat.S_ISDIR(before.st_mode):
        raise _context_error(
            "Docker build context contains a socket, device, FIFO, or special file"
        )
    captured[relative] = _PrivateContextEntry(
        relative_path=relative,
        absolute_path=candidate,
        entry_type="directory",
        mode=permissions,
        size=0,
        content_sha256=None,
        symlink_target=None,
        identity=identity,
        mutable=mutable,
    )
    directory_identities[candidate] = identity
    try:
        children = sorted(candidate.iterdir(), key=lambda item: os.fsencode(item.name))
    except OSError as exc:
        raise _context_error("Docker build context directory cannot be enumerated safely") from exc
    for child in children:
        _capture_entry(
            root=root,
            candidate=child,
            mutable_paths=mutable_paths,
            invoking_uid=invoking_uid,
            captured=captured,
            directory_identities=directory_identities,
        )
    if _identity(candidate.lstat()) != identity:
        raise _context_error("Docker build context directory changed while it was enumerated")


def _validate_entry_metadata(metadata: os.stat_result, *, invoking_uid: int) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        if metadata.st_uid != invoking_uid:
            raise _context_error("Docker build context symlinks must be user-owned")
        return
    if (
        metadata.st_uid != invoking_uid
        or (
            bool(metadata.st_mode & stat.S_IWGRP)
            and not _group_write_is_private(
                group_id=metadata.st_gid,
                invoking_uid=invoking_uid,
            )
        )
        or bool(metadata.st_mode & stat.S_IWOTH)
    ):
        raise _context_error(
            "Docker build context entries must be user-owned and not broadly writable"
        )


def _safe_directory(path: Path, *, uid: int, label: str, private: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _context_error(f"Docker build {label} must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise _context_error(f"Docker build {label} cannot be resolved safely") from exc
    if resolved != path or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
        raise _context_error(f"Docker build {label} identity or owner is unsafe")
    mode = stat.S_IMODE(metadata.st_mode)
    unsafe_project_write = bool(metadata.st_mode & stat.S_IWOTH) or (
        bool(metadata.st_mode & stat.S_IWGRP)
        and not _group_write_is_private(group_id=metadata.st_gid, invoking_uid=uid)
    )
    if (private and mode != 0o700) or (not private and unsafe_project_write):
        raise _context_error(f"Docker build {label} permissions are unsafe")
    return resolved


def _group_write_is_private(*, group_id: int, invoking_uid: int) -> bool:
    """Prove that a group-writable path is writable by only the invoking identity."""
    try:
        owner = pwd.getpwuid(invoking_uid)
        group = grp.getgrgid(group_id)
        primary_group_users = {
            account.pw_uid for account in pwd.getpwall() if account.pw_gid == group_id
        }
    except (KeyError, OSError):
        return False
    if owner.pw_gid != group_id or primary_group_users != {invoking_uid}:
        return False
    return all(member == owner.pw_name for member in group.gr_mem)


def _hash_verified_entry(path: Path, identity: _FileIdentity) -> str:
    descriptor = _open_verified_regular(path, identity)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        if _identity(os.fstat(descriptor)) != identity:
            raise _context_error("Docker build context file changed while it was hashed")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _append_archive_entry(archive: tarfile.TarFile, entry: _PrivateContextEntry) -> None:
    info = tarfile.TarInfo(entry.relative_path)
    info.mode = entry.mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if entry.entry_type == "directory":
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
        return
    if entry.entry_type == "symlink":
        if _identity(entry.absolute_path.lstat()) != entry.identity:
            raise _context_error("Docker build context symlink changed before archiving")
        target = os.readlink(entry.absolute_path)
        if target != entry.symlink_target:
            raise _context_error("Docker build context symlink target changed before archiving")
        info.type = tarfile.SYMTYPE
        info.linkname = target
        archive.addfile(info)
        return
    descriptor = _open_verified_regular(entry.absolute_path, entry.identity)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            reader = _HashingReader(stream)
            info.size = entry.size
            archive.addfile(info, reader)
            if reader.bytes_read != entry.size or reader.hexdigest != entry.content_sha256:
                raise _context_error("Docker build context file changed while it was archived")
            if _identity(os.fstat(stream.fileno())) != entry.identity:
                raise _context_error("Docker build context file identity changed while archiving")
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        raise


def _open_verified_regular(path: Path, identity: _FileIdentity) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _context_error("Docker build context file cannot be opened safely") from exc
    if _identity(os.fstat(descriptor)) != identity:
        os.close(descriptor)
        raise _context_error("Docker build context file identity changed before use")
    return descriptor


def _verify_symlink_targets(root: Path, captured: dict[str, _PrivateContextEntry]) -> None:
    for entry in captured.values():
        if entry.entry_type != "symlink" or entry.symlink_target is None:
            continue
        lexical = PurePosixPath(entry.relative_path).parent / entry.symlink_target
        normalized_parts: list[str] = []
        for part in lexical.parts:
            if part in {"", "."}:
                continue
            if part == "..":
                if not normalized_parts:
                    raise _context_error("Docker build context symlink escapes the project")
                normalized_parts.pop()
            else:
                normalized_parts.append(part)
        target_relative = PurePosixPath(*normalized_parts).as_posix()
        try:
            resolved_target = entry.absolute_path.resolve(strict=True)
        except OSError as exc:
            raise _context_error("Docker build context symlink target is unavailable") from exc
        if not resolved_target.is_relative_to(root):
            raise _context_error("Docker build context symlink target was not captured")
        resolved_relative = resolved_target.relative_to(root).as_posix()
        if target_relative not in captured or resolved_relative not in captured:
            raise _context_error("Docker build context symlink target was not captured")


def _public_entry(entry: _PrivateContextEntry) -> DockerBuildContextEntry:
    return DockerBuildContextEntry(
        path_sha256=_path_contract_sha256(entry.relative_path),
        entry_type=entry.entry_type,
        mode=entry.mode,
        size=entry.size,
        content_sha256=entry.content_sha256,
        symlink_target_sha256=(
            _canonical_sha256(entry.symlink_target) if entry.symlink_target is not None else None
        ),
        mutable=entry.mutable,
    )


def _hash_regular_file(path: Path) -> tuple[str, int]:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise _context_error("Docker build context archive identity is unsafe")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    if size != metadata.st_size:
        raise _context_error("Docker build context archive changed while hashing")
    return digest.hexdigest(), size


def _identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        owner_uid=metadata.st_uid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _is_forbidden(relative_path: str) -> bool:
    return any(part.lower() in _FORBIDDEN_COMPONENTS for part in PurePosixPath(relative_path).parts)


def _path_contract_sha256(path: str) -> str:
    return hashlib.sha256(f"perflens-build-context-path-v1\0{path}".encode()).hexdigest()


def _path_is_within(candidate: str, parent: str) -> bool:
    candidate_path = PurePosixPath(candidate)
    parent_path = PurePosixPath(parent)
    return candidate_path == parent_path or candidate_path.is_relative_to(parent_path)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _context_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_build_context",
        message,
        recoverable=True,
    )


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "docker_build_context",
        message,
        recoverable=True,
    )
