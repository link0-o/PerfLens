"""Stage inspected collector service assets without changing the host."""

from __future__ import annotations

import shutil
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError

_ASSET_NAMES = (
    "collector.example.toml",
    "perflens-collector.service",
    "perflens.sysusers",
)
_MAX_ASSET_BYTES = 256 << 10


def install_collector_assets(output_directory: Path) -> Path:
    """Copy service templates to a new staging directory; never install or elevate."""
    candidate = output_directory.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector asset parent directory does not exist",
            details={"path": str(candidate.parent)},
        ) from exc
    target = parent / candidate.name
    if target.exists() or target.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "collector_assets",
            "Collector asset destination already exists",
            recoverable=True,
            details={"path": str(target)},
        )
    source = _bundled_collector_root()
    try:
        target.mkdir()
        total = 0
        for name in _ASSET_NAMES:
            data = source.joinpath(name).read_bytes()
            total += len(data)
            if total > _MAX_ASSET_BYTES:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "collector_assets",
                    "Bundled collector assets exceed their size limit",
                )
            with (target / name).open("xb") as handle:
                handle.write(data)
    except PerfLensError:
        shutil.rmtree(target, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "collector_assets",
            "Unable to stage collector assets",
            details={"path": str(target)},
        ) from exc
    return target


def _bundled_collector_root() -> Traversable:
    packaged = resources.files("perflens").joinpath("_bundled").joinpath("collector")
    if all(packaged.joinpath(name).is_file() for name in _ASSET_NAMES):
        return packaged
    repository_copy = Path(__file__).resolve().parents[3] / "packaging" / "collector"
    if all((repository_copy / name).is_file() for name in _ASSET_NAMES):
        return repository_copy
    raise PerfLensError(
        ErrorCode.INTERNAL_ERROR,
        "collector_assets",
        "The installed package does not contain collector service assets",
    )
