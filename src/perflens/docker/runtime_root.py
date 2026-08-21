"""Create one private per-project runtime root under the invoking user's /run tree."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import Path

from perflens.docker.workload import ManagedProjectIdentity
from perflens.domain.errors import ErrorCode, PerfLensError


def prepare_default_managed_runtime_root(
    project: ManagedProjectIdentity,
    *,
    runtime_parent: Path | None = None,
) -> Path:
    """Create/reuse one 0700 runtime directory without trusting XDG environment input."""
    uid = os.geteuid()
    if project.owner_uid != uid:
        raise _runtime_error("Managed Docker project owner differs from the invoking user")
    parent = runtime_parent or Path("/run/user") / str(uid)
    parent = _private_directory(parent, expected_uid=uid, label="user runtime parent")
    name = f"perflens-docker-{project.identity_sha256[:20]}"
    descriptor = -1
    try:
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != uid
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            raise _runtime_error("Managed Docker user runtime parent changed during validation")
        with suppress(FileExistsError):
            os.mkdir(name, mode=0o700, dir_fd=descriptor)
        child_descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            child = os.fstat(child_descriptor)
        finally:
            os.close(child_descriptor)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise _runtime_error("Managed Docker runtime root cannot be created safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_uid, before.st_mode)
        != (after.st_dev, after.st_ino, after.st_uid, after.st_mode)
        or not stat.S_ISDIR(child.st_mode)
        or child.st_uid != uid
        or stat.S_IMODE(child.st_mode) != 0o700
    ):
        raise _runtime_error("Managed Docker runtime root identity or mode is unsafe")
    root = parent / name
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise _runtime_error("Managed Docker runtime root was replaced after creation")
    return root


def _private_directory(path: Path, *, expected_uid: int, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _runtime_error(f"Managed Docker {label} must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _runtime_error(f"Managed Docker {label} is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _runtime_error(f"Managed Docker {label} owner or mode is unsafe")
    return resolved


def _runtime_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_workload",
        message,
        recoverable=True,
    )
