"""Bounded project-file identities for managed-container A/B treatments."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_TREATMENT_FILES = 32
_MAX_TREATMENT_FILE_BYTES = 256 << 20
_MAX_TREATMENT_TOTAL_BYTES = 512 << 20


@dataclass(frozen=True, slots=True)
class TreatmentFileIdentity:
    path: Path
    relative_path_sha256: str
    device: int
    inode: int
    owner_uid: int
    size: int
    modified_ns: int
    changed_ns: int
    content_sha256: str
    treatment_sha256: str


@dataclass(frozen=True, slots=True)
class TreatmentSnapshot:
    project_root: Path
    files: tuple[TreatmentFileIdentity, ...]

    @property
    def treatment_sha256(self) -> tuple[str, ...]:
        return tuple(sorted(item.treatment_sha256 for item in self.files))


def capture_treatment_snapshot(
    project_root: Path,
    paths: tuple[Path, ...],
    *,
    invoking_uid: int | None = None,
) -> TreatmentSnapshot:
    """Hash explicit, user-owned project files without publishing their paths."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    try:
        root = project_root.resolve(strict=True)
    except OSError as exc:
        raise _treatment_error("Docker treatment project root is unavailable") from exc
    if root != project_root or not root.is_dir() or project_root.is_symlink():
        raise _treatment_error("Docker treatment project root must be a canonical directory")
    if len(paths) > _MAX_TREATMENT_FILES:
        raise _treatment_error("Docker treatment file count exceeds its fixed limit")
    canonical_paths: list[Path] = []
    for path in paths:
        if not path.is_absolute() or path.is_symlink():
            raise _treatment_error("Docker treatment files must be absolute and non-symlinked")
        try:
            canonical = path.resolve(strict=True)
        except OSError as exc:
            raise _treatment_error("Docker treatment file is unavailable") from exc
        if canonical != path or not canonical.is_relative_to(root):
            raise _treatment_error("Docker treatment file is outside the authorized project")
        canonical_paths.append(canonical)
    if len(set(canonical_paths)) != len(canonical_paths):
        raise _treatment_error("Docker treatment files must be unique")
    identities: list[TreatmentFileIdentity] = []
    total_bytes = 0
    for path in sorted(canonical_paths):
        identity = _capture_file(root, path, invoking_uid=uid)
        total_bytes += identity.size
        if total_bytes > _MAX_TREATMENT_TOTAL_BYTES:
            raise _treatment_error("Docker treatment files exceed their total byte limit")
        identities.append(identity)
    return TreatmentSnapshot(project_root=root, files=tuple(identities))


def assert_treatment_snapshot_current(snapshot: TreatmentSnapshot) -> None:
    current = capture_treatment_snapshot(
        snapshot.project_root,
        tuple(item.path for item in snapshot.files),
        invoking_uid=(snapshot.files[0].owner_uid if snapshot.files else os.geteuid()),
    )
    if current != snapshot:
        raise _treatment_error(
            "Docker treatment files changed during the managed workload",
            recoverable=True,
        )


def _capture_file(
    root: Path,
    path: Path,
    *,
    invoking_uid: int,
) -> TreatmentFileIdentity:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != invoking_uid
            or before.st_size > _MAX_TREATMENT_FILE_BYTES
        ):
            raise _treatment_error(
                "Docker treatment file owner, type, link count, or size is unsafe"
            )
        digest = hashlib.sha256()
        remaining = _MAX_TREATMENT_FILE_BYTES + 1
        while remaining and (chunk := os.read(descriptor, min(1 << 20, remaining))):
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            raise _treatment_error("Docker treatment file exceeds its byte limit")
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise _treatment_error("Docker treatment file changed while it was hashed")
    except PerfLensError:
        raise
    except OSError as exc:
        raise _treatment_error("Docker treatment file cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    relative = path.relative_to(root).as_posix()
    relative_sha256 = hashlib.sha256(
        f"perflens-container-treatment-path-v1\0{relative}".encode()
    ).hexdigest()
    content_sha256 = digest.hexdigest()
    treatment_sha256 = hashlib.sha256(
        f"perflens-container-treatment-file-v1\0{relative_sha256}\0{content_sha256}".encode()
    ).hexdigest()
    return TreatmentFileIdentity(
        path=path,
        relative_path_sha256=relative_sha256,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
        content_sha256=content_sha256,
        treatment_sha256=treatment_sha256,
    )


def _treatment_error(message: str, *, recoverable: bool = False) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_comparison",
        message,
        recoverable=recoverable,
    )
