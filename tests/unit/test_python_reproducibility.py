from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from perflens import __version__


def _run(primary: Path, reproduced: Path) -> subprocess.CompletedProcess[str]:
    project_root = Path(__file__).resolve().parents[2]
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(project_root / "scripts" / "verify_python_reproducibility.py"),
            "--directory",
            str(primary),
            "--reproducible-directory",
            str(reproduced),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
    )


def _write_packages(directory: Path, *, wheel: bytes = b"wheel", source: bytes = b"source") -> None:
    directory.mkdir()
    (directory / f"perflens-{__version__}-py3-none-any.whl").write_bytes(wheel)
    (directory / f"perflens-{__version__}.tar.gz").write_bytes(source)


def test_reproducibility_check_accepts_identical_packages(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    reproduced = tmp_path / "reproduced"
    _write_packages(primary)
    _write_packages(reproduced)

    completed = _run(primary, reproduced)

    assert completed.returncode == 0
    assert f"perflens-{__version__}-py3-none-any.whl" in completed.stdout
    assert f"perflens-{__version__}.tar.gz" in completed.stdout


def test_reproducibility_check_rejects_different_bytes(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    reproduced = tmp_path / "reproduced"
    _write_packages(primary)
    _write_packages(reproduced, wheel=b"different wheel")

    completed = _run(primary, reproduced)

    assert completed.returncode == 2
    assert "Python package is not reproducible" in completed.stderr


@pytest.mark.parametrize(
    ("unsafe_artifact", "expected"),
    [
        ("missing", "required regular artifact is missing"),
        ("empty", "artifact is empty or oversized"),
        ("symlink", "required regular artifact is missing"),
        ("oversized", "artifact is empty or oversized"),
    ],
)
def test_reproducibility_check_rejects_unsafe_artifacts(
    tmp_path: Path,
    unsafe_artifact: str,
    expected: str,
) -> None:
    primary = tmp_path / "primary"
    reproduced = tmp_path / "reproduced"
    _write_packages(primary)
    _write_packages(reproduced)
    wheel = reproduced / f"perflens-{__version__}-py3-none-any.whl"
    if unsafe_artifact == "missing":
        wheel.unlink()
    elif unsafe_artifact == "empty":
        wheel.write_bytes(b"")
    elif unsafe_artifact == "symlink":
        wheel.unlink()
        wheel.symlink_to(primary / wheel.name)
    else:
        with wheel.open("wb") as handle:
            handle.truncate((512 << 20) + 1)

    completed = _run(primary, reproduced)

    assert completed.returncode == 2
    assert expected in completed.stderr


@pytest.mark.parametrize("unsafe_directory", ["primary", "reproduced"])
def test_reproducibility_check_rejects_symlink_directories(
    tmp_path: Path,
    unsafe_directory: str,
) -> None:
    real_primary = tmp_path / "real-primary"
    real_reproduced = tmp_path / "real-reproduced"
    _write_packages(real_primary)
    _write_packages(real_reproduced)
    if unsafe_directory == "primary":
        primary = tmp_path / "primary"
        primary.symlink_to(real_primary, target_is_directory=True)
        reproduced = real_reproduced
    else:
        primary = real_primary
        reproduced = tmp_path / "reproduced"
        reproduced.symlink_to(real_reproduced, target_is_directory=True)

    completed = _run(primary, reproduced)

    assert completed.returncode == 2
    assert "must not be a symbolic link" in completed.stderr
