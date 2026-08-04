"""Inspect and smoke-test extracted split PerfLens Debian packages without root."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from perflens import __version__


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--reproducible-directory", type=Path)
    parser.add_argument("--main", type=Path)
    parser.add_argument("--collector", type=Path)
    arguments = parser.parse_args()
    directory = arguments.directory.resolve(strict=True)
    if arguments.main is None:
        candidates = tuple(directory.glob(f"perflens_{__version__}-1_*.deb"))
        if len(candidates) != 1:
            parser.error("expected exactly one architecture-specific perflens DEB")
        main_package = candidates[0]
    else:
        main_package = arguments.main.resolve(strict=True)
    collector_package = (
        arguments.collector.resolve(strict=True)
        if arguments.collector is not None
        else directory / f"perflens-collector_{__version__}-1_all.deb"
    )
    collector_package = collector_package.resolve(strict=True)
    if arguments.reproducible_directory is not None:
        reproducible = arguments.reproducible_directory.resolve(strict=True)
        assert _same_file(main_package, reproducible / main_package.name)
        assert _same_file(collector_package, reproducible / collector_package.name)
    dpkg_deb = _command("dpkg-deb")

    assert _field(dpkg_deb, main_package, "Package") == "perflens"
    assert _field(dpkg_deb, collector_package, "Package") == "perflens-collector"
    assert _field(dpkg_deb, main_package, "Version") == f"{__version__}-1"
    assert _field(dpkg_deb, collector_package, "Version") == f"{__version__}-1"
    main_dependencies = _field(dpkg_deb, main_package, "Depends")
    assert any(
        f"python3 (>= {abi})" in main_dependencies
        and f"python3 (<< 3.{int(abi.removeprefix('3.')) + 1})" in main_dependencies
        for abi in ("3.12", "3.13")
    )
    assert f"perflens (= {__version__}-1)" in _field(
        dpkg_deb, collector_package, "Depends"
    )

    with tempfile.TemporaryDirectory(prefix="perflens-deb-smoke-") as directory:
        root = Path(directory) / "root"
        main_control = Path(directory) / "main-control"
        collector_control = Path(directory) / "collector-control"
        for package, control in (
            (main_package, main_control),
            (collector_package, collector_control),
        ):
            _run(dpkg_deb, "--extract", str(package), str(root))
            _run(dpkg_deb, "--control", str(package), str(control))
            assert {path.name for path in control.iterdir()} == {"control", "md5sums"}

        binary_directory = root / "usr/bin"
        expected_commands = {
            "perflens",
            "perflens-mcp",
            "perflens-admin",
            "perflens-collector",
        }
        assert {path.name for path in binary_directory.iterdir()} == expected_commands
        for command in expected_commands:
            link = binary_directory / command
            assert link.is_symlink()
            assert os.readlink(link) == "../lib/perflens/perflens-launcher"

        launcher = root / "usr/lib/perflens/perflens-launcher"
        assert launcher.is_file()
        assert launcher.stat().st_mode & 0o777 == 0o755
        assert not tuple((root / "usr/lib/perflens").glob("*.dist-info/uv_cache.json"))
        _assert_safe_modes(root)
        policy = (
            root / "usr/share/perflens/collector/collector.example.toml"
        ).read_text(encoding="utf-8")
        service = (
            root / "usr/share/perflens/collector/perflens-collector.service"
        ).read_text(encoding="utf-8")
        assert "policy_version = 1" in policy
        assert "策略格式版本" in policy
        assert "max_spool_bytes = 10737418240" in policy
        assert "PerfLens never deletes old evidence automatically" in policy
        assert "exactly one UID is supported" in policy
        assert service.startswith("# Managed by PerfLens.")
        _assert_shared_libraries(root)

        environment = dict(os.environ)
        environment["PATH"] = f"{binary_directory}:{environment.get('PATH', '')}"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        project_root = Path(__file__).resolve().parents[1]
        subprocess.run(  # noqa: S603 - fixed test interpreter and checked-in smoke script
            [sys.executable, str(project_root / "tests/package_smoke.py")],
            cwd=project_root,
            env=environment,
            check=True,
        )


def _assert_safe_modes(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if path.is_dir() or path.name == "perflens-launcher":
            assert mode == 0o755, (path, oct(mode))
        else:
            assert mode == 0o644, (path, oct(mode))


def _assert_shared_libraries(root: Path) -> None:
    ldd = _command("ldd")
    shared_objects = tuple((root / "usr/lib/perflens").rglob("*.so"))
    assert shared_objects
    for shared_object in shared_objects:
        completed = subprocess.run(  # noqa: S603 - ldd is resolved and input is packaged
            [ldd, str(shared_object)],
            check=True,
            capture_output=True,
            text=True,
        )
        assert "not found" not in completed.stdout, shared_object


def _field(dpkg_deb: str, package: Path, field: str) -> str:
    completed = subprocess.run(  # noqa: S603 - dpkg-deb is resolved from PATH
        [dpkg_deb, "--field", str(package), field],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _command(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"required command is unavailable: {name}")
    return resolved


def _run(command: str, *arguments: str) -> None:
    subprocess.run(  # noqa: S603 - dpkg-deb is resolved and arguments are structured
        [command, *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def _same_file(left: Path, right: Path) -> bool:
    with left.open("rb") as left_handle, right.open("rb") as right_handle:
        while True:
            left_chunk = left_handle.read(1 << 20)
            right_chunk = right_handle.read(1 << 20)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


if __name__ == "__main__":
    main()
