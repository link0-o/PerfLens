"""Deterministic, bounded, atomic JSON artifact persistence."""

from __future__ import annotations

import json
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from pydantic import BaseModel

from perflens.domain.errors import ErrorCode, PerfLensError


def serialize_json(model: BaseModel) -> bytes:
    payload = model.model_dump(mode="json", exclude_none=True)
    # ASCII JSON keeps byte-offset pagination lossless: a page boundary can no longer split a
    # multibyte UTF-8 code point and introduce replacement characters in Agent-visible text.
    return (json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def write_json_atomic(model: BaseModel, output: Path, *, max_output_bytes: int) -> int:
    data = serialize_json(model)
    return _write_bytes_atomic(data, output, max_output_bytes=max_output_bytes)


def write_json_new_atomic(model: BaseModel, output: Path, *, max_output_bytes: int) -> int:
    """Publish a JSON artifact atomically while refusing to replace any existing path."""
    data = serialize_json(model)
    return _write_bytes_new_atomic(
        data,
        output,
        max_output_bytes=max_output_bytes,
        failure_message="Unable to write new output artifact",
    )


def write_text_atomic(text: str, output: Path, *, max_output_bytes: int) -> int:
    return _write_bytes_atomic(text.encode("utf-8"), output, max_output_bytes=max_output_bytes)


def write_text_new_atomic(text: str, output: Path, *, max_output_bytes: int) -> int:
    """Publish UTF-8 text atomically while refusing to replace an existing path."""
    data = text.encode("utf-8")
    return _write_bytes_new_atomic(
        data,
        output,
        max_output_bytes=max_output_bytes,
        failure_message="Unable to write new text output",
    )


def _write_bytes_new_atomic(
    data: bytes,
    output: Path,
    *,
    max_output_bytes: int,
    failure_message: str,
) -> int:
    if len(data) > max_output_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "artifact",
            "Serialized artifact exceeds max_output_bytes",
            recoverable=True,
            details={"actual_bytes": len(data), "max_output_bytes": max_output_bytes},
        )
    return _publish_bytes(
        data,
        output,
        replace=False,
        create_parent=False,
        failure_message=failure_message,
    )


def _write_bytes_atomic(data: bytes, output: Path, *, max_output_bytes: int) -> int:
    if len(data) > max_output_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "artifact",
            "Serialized artifact exceeds max_output_bytes",
            recoverable=True,
            details={"actual_bytes": len(data), "max_output_bytes": max_output_bytes},
        )
    return _publish_bytes(
        data,
        output,
        replace=True,
        create_parent=True,
        failure_message="Unable to write output artifact",
    )


def _publish_bytes(
    data: bytes,
    output: Path,
    *,
    replace: bool,
    create_parent: bool,
    failure_message: str,
) -> int:
    directory_descriptor = -1
    temporary_name: str | None = None
    published = False
    try:
        if create_parent:
            _ensure_parent_directory(output.parent)
        directory_descriptor = os.open(
            output.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        directory_identity = _directory_identity(os.fstat(directory_descriptor))
        descriptor, temporary_name = _reserve_temporary_file(directory_descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(
                temporary_name,
                output.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            published = True
        else:
            os.link(
                temporary_name,
                output.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            published = True
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_name = None
        os.fsync(directory_descriptor)
        _assert_directory_identity(output.parent, directory_identity)
    except FileExistsError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "artifact",
            "Output appeared during execution and was not overwritten",
            details={"output": str(output), "published": False},
        ) from exc
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "artifact",
            failure_message,
            details={"output": str(output), "published": published},
            suggested_actions=(
                "Check output directory permissions, free space, and storage health.",
                "If published is true, verify the complete output before retrying.",
            ),
        ) from exc
    finally:
        if directory_descriptor >= 0:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                with suppress(OSError):
                    os.fsync(directory_descriptor)
            with suppress(OSError):
                os.close(directory_descriptor)
    return len(data)


def _reserve_temporary_file(directory_descriptor: int) -> tuple[int, str]:
    for _attempt in range(16):
        name = f".perflens-{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            continue
        return descriptor, name
    raise OSError("Unable to reserve a unique temporary artifact file")


def _ensure_parent_directory(parent: Path) -> None:
    missing: list[Path] = []
    candidate = parent
    while not candidate.exists():
        missing.append(candidate)
        if candidate == candidate.parent:
            break
        candidate = candidate.parent
    if not candidate.is_dir():
        raise OSError("Artifact parent ancestor is not a directory")
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            if not directory.is_dir():
                raise
        _fsync_directory(directory.parent)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError("Artifact parent is not a directory")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _assert_directory_identity(parent: Path, expected: tuple[int, int, int, int, int]) -> None:
    if _directory_identity(parent.stat()) != expected:
        raise OSError("Artifact parent directory identity changed during publication")
