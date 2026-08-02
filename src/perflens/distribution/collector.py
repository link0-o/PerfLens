"""Stage inspected collector service assets without changing the host."""

from __future__ import annotations

import json
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


def install_collector_assets(
    output_directory: Path,
    *,
    allowed_uids: tuple[int, ...] = (1000,),
    collector_command: Path = Path("/usr/bin/perflens-collector"),
    perf_path: Path = Path("/usr/bin/perf"),
) -> Path:
    """Copy service templates to a new staging directory; never install or elevate."""
    rendered_uids, rendered_collector, rendered_perf = _deployment_values(
        allowed_uids,
        collector_command,
        perf_path,
    )
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
            if name == "collector.example.toml":
                text = data.decode("utf-8")
                text = _replace_exact(
                    text,
                    "allowed_uids = [1000]",
                    f"allowed_uids = {rendered_uids}",
                    name,
                )
                text = _replace_exact(
                    text,
                    'perf_path = "/usr/bin/perf"',
                    f"perf_path = {rendered_perf}",
                    name,
                )
                data = text.encode("utf-8")
            elif name == "perflens-collector.service":
                text = data.decode("utf-8")
                text = _replace_exact(
                    text,
                    "ExecStart=/usr/bin/perflens-collector ",
                    f"ExecStart={rendered_collector} ",
                    name,
                )
                data = text.encode("utf-8")
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


def _deployment_values(
    allowed_uids: tuple[int, ...],
    collector_command: Path,
    perf_path: Path,
) -> tuple[str, str, str]:
    unique_uids = tuple(sorted(set(allowed_uids)))
    if not unique_uids or len(unique_uids) > 64 or any(uid < 0 for uid in unique_uids):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector assets require between 1 and 64 non-negative allowed UIDs",
        )
    collector_text = str(collector_command.expanduser())
    perf_text = str(perf_path.expanduser())
    if not collector_command.expanduser().is_absolute() or any(
        character.isspace() or character in "\0\"'" for character in collector_text
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector command must be an absolute path without whitespace or quotes",
        )
    if not perf_path.expanduser().is_absolute() or "\0" in perf_text:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "perf path must be an absolute path without NUL characters",
        )
    return (
        json.dumps(list(unique_uids), separators=(",", ":")),
        collector_text,
        json.dumps(perf_text),
    )


def _replace_exact(text: str, marker: str, replacement: str, asset_name: str) -> str:
    if text.count(marker) != 1:
        raise PerfLensError(
            ErrorCode.INTERNAL_ERROR,
            "collector_assets",
            "Bundled collector asset contains a missing or ambiguous render marker",
            details={"asset": asset_name},
        )
    return text.replace(marker, replacement)


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
