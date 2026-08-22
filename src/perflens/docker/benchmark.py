"""Identity-pinned benchmark output captured from one managed Docker run."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from perflens.benchmarks.adapters import BenchmarkFormat, load_benchmark_bytes
from perflens.contracts.artifacts import BenchmarkArtifact
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_BENCHMARK_BYTES = 64 << 20


def workload_command_contract_sha256(entrypoint: str, arguments: tuple[str, ...]) -> str:
    """Bind the exact command whose zero exit status supplies correctness evidence."""
    material = "\0".join(("perflens-managed-correctness-command-v1", entrypoint, *arguments))
    return hashlib.sha256(material.encode()).hexdigest()


def benchmark_output_contract_sha256(
    relative_path: str,
    source_format: BenchmarkFormat,
    benchmark_name: str | None,
) -> str:
    """Hash the fixed private output recipe without publishing its path or name."""
    normalized = _relative_output_path(relative_path)
    return hashlib.sha256(
        (
            "perflens-managed-benchmark-output-v1\0"
            f"{normalized}\0{source_format}\0{benchmark_name or ''}"
        ).encode()
    ).hexdigest()


def load_managed_benchmark(
    scratch_root: Path,
    relative_path: str,
    *,
    source_format: BenchmarkFormat,
    benchmark_name: str | None,
    invoking_uid: int | None = None,
) -> BenchmarkArtifact:
    """Read a stopped workload's private benchmark once and bind it to its raw bytes."""
    uid = os.geteuid() if invoking_uid is None else invoking_uid
    root = _canonical_private_root(scratch_root, uid)
    output = root / _relative_output_path(relative_path)
    if output.is_symlink():
        raise _benchmark_error("Managed Docker benchmark output must not be a symlink")
    try:
        canonical = output.resolve(strict=True)
    except OSError as exc:
        raise _benchmark_error("Managed Docker benchmark output is unavailable") from exc
    if canonical != output or not canonical.is_relative_to(root):
        raise _benchmark_error("Managed Docker benchmark output escapes its private scratch root")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(output, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_mode & 0o022
            or before.st_size > _MAX_BENCHMARK_BYTES
        ):
            raise _benchmark_error(
                "Managed Docker benchmark output owner, mode, type, link count, or size is unsafe"
            )
        remaining = _MAX_BENCHMARK_BYTES + 1
        chunks: list[bytes] = []
        while remaining and (chunk := os.read(descriptor, min(1 << 20, remaining))):
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            raise _benchmark_error("Managed Docker benchmark output exceeds its byte limit")
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise _benchmark_error("Managed Docker benchmark output changed while it was read")
    except PerfLensError:
        raise
    except OSError as exc:
        raise _benchmark_error("Managed Docker benchmark output cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raw = b"".join(chunks)
    benchmark = load_benchmark_bytes(
        raw,
        source_format=source_format,
        benchmark_name=benchmark_name,
        max_input_bytes=_MAX_BENCHMARK_BYTES,
    )
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    return benchmark.model_copy(
        update={
            "benchmark_id": f"benchmark-{raw_sha256[:16]}",
            "environment": benchmark.environment.model_copy(update={"containerized": True}),
            "warnings": tuple(
                dict.fromkeys(
                    (
                        *benchmark.warnings,
                        "Benchmark bytes were captured from this managed container run's "
                        "private scratch output.",
                    )
                )
            ),
        }
    )


def _canonical_private_root(path: Path, invoking_uid: int) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _benchmark_error("Managed Docker scratch root must be absolute and non-symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _benchmark_error("Managed Docker scratch root is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != invoking_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _benchmark_error("Managed Docker scratch root identity or permissions are unsafe")
    return resolved


def _relative_output_path(value: str) -> Path:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or len(value.encode()) > 4096
        or str(path) != value
        or value in {".", ".."}
        or ".." in path.parts
    ):
        raise _benchmark_error(
            "Managed Docker benchmark output must be a normalized scratch-relative path"
        )
    return Path(*path.parts)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _benchmark_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "docker_benchmark",
        message,
        recoverable=True,
    )
