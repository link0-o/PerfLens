"""Install the bundled PerfLens Skill into a project without overwriting files."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from perflens.domain.errors import ErrorCode, PerfLensError

SKILL_NAME = "perflens-performance-analysis"
_MAX_SKILL_FILES = 64
_MAX_SKILL_BYTES = 2 << 20


@dataclass(slots=True)
class _CopyBudget:
    files: int = 0
    bytes: int = 0


def install_project_skill(project_root: Path) -> Path:
    """Install the bundled Skill beneath PROJECT/.agents/skills and refuse overwrite."""
    root = _existing_directory(project_root, label="Project root")
    agents_root = _safe_child_directory(root, ".agents")
    skills_root = _safe_child_directory(agents_root, "skills")
    target = skills_root / SKILL_NAME
    if target.exists() or target.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "PerfLens Skill destination already exists",
            recoverable=True,
            details={"path": str(target)},
            suggested_actions=(
                "Keep the existing Skill or remove it explicitly before reinstalling.",
            ),
        )

    source = _bundled_skill_root()
    created = False
    try:
        target.mkdir()
        created = True
        _copy_resource_tree(source, target, budget=_CopyBudget())
    except PerfLensError:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise
    except OSError as exc:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "skill_install",
            "Unable to install the PerfLens Skill",
            details={"path": str(target)},
            suggested_actions=("Check project directory permissions and free space.",),
        ) from exc
    return target


def _bundled_skill_root() -> Traversable:
    packaged = (
        resources.files("perflens")
        .joinpath("_bundled")
        .joinpath("skills")
        .joinpath(SKILL_NAME)
    )
    if packaged.joinpath("SKILL.md").is_file():
        return packaged

    repository_copy = (
        Path(__file__).resolve().parents[3] / ".agents" / "skills" / SKILL_NAME
    )
    if (repository_copy / "SKILL.md").is_file():
        return repository_copy
    raise PerfLensError(
        ErrorCode.INTERNAL_ERROR,
        "skill_install",
        "The installed package does not contain the PerfLens Skill",
        suggested_actions=("Reinstall PerfLens from an official wheel or source distribution.",),
    )


def _existing_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "skill_install",
            f"{label} does not exist or cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "skill_install",
            f"{label} must be a directory",
            details={"path": str(resolved)},
        )
    return resolved


def _safe_child_directory(parent: Path, name: str) -> Path:
    candidate = parent / name
    if not candidate.exists() and not candidate.is_symlink():
        try:
            candidate.mkdir()
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "skill_install",
                "Unable to create the Skill parent directory",
                details={"path": str(candidate)},
            ) from exc
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Skill parent directory cannot be resolved safely",
            details={"path": str(candidate)},
        ) from exc
    if not resolved.is_dir() or not resolved.is_relative_to(parent):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "skill_install",
            "Skill parent directory escapes the selected project",
            details={"path": str(resolved), "project_root": str(parent)},
        )
    return resolved


def _copy_resource_tree(source: Traversable, target: Path, *, budget: _CopyBudget) -> None:
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        destination = target / child.name
        if child.is_dir():
            destination.mkdir()
            _copy_resource_tree(child, destination, budget=budget)
            continue
        if not child.is_file():
            raise PerfLensError(
                ErrorCode.INTERNAL_ERROR,
                "skill_install",
                "Bundled Skill contains an unsupported resource",
                details={"name": child.name},
            )
        data = child.read_bytes()
        budget.files += 1
        budget.bytes += len(data)
        if budget.files > _MAX_SKILL_FILES or budget.bytes > _MAX_SKILL_BYTES:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "skill_install",
                "Bundled Skill exceeds the installation resource limits",
                details={
                    "files": budget.files,
                    "bytes": budget.bytes,
                    "max_files": _MAX_SKILL_FILES,
                    "max_bytes": _MAX_SKILL_BYTES,
                },
            )
        with destination.open("xb") as handle:
            handle.write(data)
