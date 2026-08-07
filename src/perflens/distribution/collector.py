"""Stage inspected collector service assets without changing the host."""

from __future__ import annotations

import json
import os
import shutil
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Literal

from perflens.domain.errors import ErrorCode, PerfLensError

_ASSET_MAPPINGS = (
    ("collector.example.toml", "collector.toml", 0o600),
    ("perflens-collector.service", "perflens-collector.service", 0o644),
    (
        "perflens-collector-helper.service",
        "perflens-collector-helper.service",
        0o644,
    ),
    (
        "perflens-privileged-helper.service",
        "perflens-privileged-helper.service",
        0o644,
    ),
    ("perflens.sysusers", "perflens.sysusers", 0o644),
)
_MAX_ASSET_BYTES = 256 << 10


def install_collector_assets(
    output_directory: Path,
    *,
    allowed_uids: tuple[int, ...] = (1000,),
    collector_command: Path = Path("/usr/bin/perflens-collector"),
    perf_path: Path = Path("/usr/bin/perf"),
    privilege_mode: Literal["cap_perfmon", "paranoid3_helper"] = "cap_perfmon",
) -> Path:
    """Copy service templates to a new staging directory; never install or elevate."""
    rendered_uids, rendered_collector, rendered_perf, rendered_helper_perf = _deployment_values(
        allowed_uids,
        collector_command,
        perf_path,
    )
    if privilege_mode not in {"cap_perfmon", "paranoid3_helper"}:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector privilege mode is unsupported",
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
        target.mkdir(mode=0o700)
        total = 0
        for source_name, output_name, output_mode in _ASSET_MAPPINGS:
            data = source.joinpath(source_name).read_bytes()
            if source_name == "collector.example.toml":
                text = data.decode("utf-8")
                text = _replace_exact(
                    text,
                    "allowed_uids = [1000]",
                    f"allowed_uids = {rendered_uids}",
                    source_name,
                )
                text = _replace_exact(
                    text,
                    'perf_path = "/usr/bin/perf"',
                    f"perf_path = {rendered_perf}",
                    source_name,
                )
                text = _replace_exact(
                    text,
                    'privilege_mode = "cap_perfmon"',
                    f'privilege_mode = "{privilege_mode}"',
                    source_name,
                )
                data = text.encode("utf-8")
            elif source_name in {
                "perflens-collector.service",
                "perflens-collector-helper.service",
            }:
                text = data.decode("utf-8")
                text = _replace_exact(
                    text,
                    "ExecStart=/usr/bin/perflens-collector ",
                    f"ExecStart={rendered_collector} ",
                    source_name,
                )
                data = text.encode("utf-8")
            elif source_name == "perflens-privileged-helper.service":
                text = data.decode("utf-8")
                text = _replace_exact(
                    text,
                    "@PERFLENS_ALLOWED_UID@",
                    str(allowed_uids[0]),
                    source_name,
                )
                text = _replace_exact(
                    text,
                    "@PERFLENS_PERF_EXECUTABLE@",
                    rendered_helper_perf,
                    source_name,
                )
                text = _replace_exact(
                    text,
                    "@PERFLENS_PERF_READONLY_PATH@",
                    rendered_helper_perf,
                    source_name,
                )
                data = text.encode("utf-8")
            total += len(data)
            if total > _MAX_ASSET_BYTES:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "collector_assets",
                    "Bundled collector assets exceed their size limit",
                )
            with (target / output_name).open("xb") as handle:
                os.fchmod(handle.fileno(), output_mode)
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
) -> tuple[str, str, str, str]:
    unique_uids = tuple(sorted(set(allowed_uids)))
    if len(unique_uids) != 1 or any(uid < 0 for uid in unique_uids):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector assets require exactly one non-negative allowed UID",
        )
    collector_text = str(collector_command.expanduser())
    perf_text = str(perf_path.expanduser())
    if not systemd_safe_absolute_path(collector_text):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "Collector command must use a systemd-safe absolute path",
        )
    if not systemd_safe_absolute_path(perf_text):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "collector_assets",
            "perf executable must use a systemd-safe absolute path",
        )
    return (
        json.dumps(list(unique_uids), separators=(",", ":")),
        collector_text,
        json.dumps(perf_text),
        perf_text,
    )


def systemd_safe_absolute_path(value: str) -> bool:
    """Return whether an absolute path is inert in unquoted systemd unit directives."""
    return Path(value).is_absolute() and all(
        character.isascii() and (character.isalnum() or character in "/._+-") for character in value
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
    if all(packaged.joinpath(name).is_file() for name, _, _ in _ASSET_MAPPINGS):
        return packaged
    repository_copy = Path(__file__).resolve().parents[3] / "packaging" / "collector"
    if all((repository_copy / name).is_file() for name, _, _ in _ASSET_MAPPINGS):
        return repository_copy
    raise PerfLensError(
        ErrorCode.INTERNAL_ERROR,
        "collector_assets",
        "The installed package does not contain collector service assets",
    )
