"""Canonical path validation for immutable inputs and artifact outputs."""

from __future__ import annotations

from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError


def validate_input_file(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "input",
            "Input file does not exist or cannot be resolved",
            details={"path": str(path)},
            suggested_actions=("Provide a readable folded stack file.",),
        ) from exc
    if not resolved.is_file():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "input",
            "Input path is not a regular file",
            details={"path": str(resolved)},
        )
    return resolved


def validate_output_file(path: Path, *, input_path: Path) -> Path:
    expanded = path.expanduser()
    try:
        resolved = expanded.resolve(strict=False)
        input_resolved = input_path.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Output path cannot be resolved safely",
            details={"path": str(path)},
        ) from exc
    if resolved == input_resolved:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Output path must not overwrite the source profile",
            details={"path": str(resolved)},
        )
    if resolved.exists() and resolved.is_dir():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Output path refers to a directory",
            details={"path": str(resolved)},
        )
    return resolved


def validate_new_output_file(path: Path) -> Path:
    """Resolve a new output under an existing directory without allowing overwrite."""
    expanded = path.expanduser()
    try:
        parent = expanded.parent.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Output parent directory does not exist or cannot be resolved safely",
            details={"path": str(path)},
        ) from exc
    if not parent.is_dir():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Output parent path is not a directory",
            details={"path": str(parent)},
        )
    resolved = parent / expanded.name
    if resolved.exists() or resolved.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "output",
            "Active collection refuses to overwrite an existing output",
            details={"path": str(resolved)},
        )
    return resolved
