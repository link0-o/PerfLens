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
from perflens.distribution.debian import DEBIAN_PACKAGE_REVISION


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--reproducible-directory", type=Path)
    parser.add_argument("--main", type=Path)
    parser.add_argument("--collector", type=Path)
    arguments = parser.parse_args()
    directory = arguments.directory.resolve(strict=True)
    package_version = f"{__version__}-{DEBIAN_PACKAGE_REVISION}"
    if arguments.main is None:
        candidates = tuple(directory.glob(f"perflens_{package_version}_*.deb"))
        if len(candidates) != 1:
            parser.error("expected exactly one architecture-specific perflens DEB")
        main_package = candidates[0]
    else:
        main_package = arguments.main.resolve(strict=True)
    if arguments.collector is None:
        collector_candidates = tuple(
            directory.glob(f"perflens-collector_{package_version}_*.deb")
        )
        if len(collector_candidates) != 1:
            parser.error("expected exactly one architecture-specific Collector DEB")
        collector_package = collector_candidates[0]
    else:
        collector_package = arguments.collector.resolve(strict=True)
    if arguments.reproducible_directory is not None:
        reproducible = arguments.reproducible_directory.resolve(strict=True)
        assert _same_file(main_package, reproducible / main_package.name)
        assert _same_file(collector_package, reproducible / collector_package.name)
    dpkg_deb = _command("dpkg-deb")

    assert _field(dpkg_deb, main_package, "Package") == "perflens"
    assert _field(dpkg_deb, collector_package, "Package") == "perflens-collector"
    assert _field(dpkg_deb, main_package, "Version") == package_version
    assert _field(dpkg_deb, collector_package, "Version") == package_version
    main_dependencies = _field(dpkg_deb, main_package, "Depends")
    assert any(
        f"python3 (>= {abi})" in main_dependencies
        and f"python3 (<< 3.{int(abi.removeprefix('3.')) + 1})" in main_dependencies
        for abi in ("3.12", "3.13")
    )
    assert f"perflens (= {package_version})" in _field(
        dpkg_deb, collector_package, "Depends"
    )
    collector_dependencies = _field(dpkg_deb, collector_package, "Depends")
    for dependency in ("libbpf1", "libelf1", "zlib1g", "libzstd1"):
        assert dependency in collector_dependencies

    with tempfile.TemporaryDirectory(prefix="perflens-deb-smoke-") as directory:
        root = Path(directory) / "root"
        main_control = Path(directory) / "main-control"
        collector_control = Path(directory) / "collector-control"
        for package, control, expected_control_files in (
            (main_package, main_control, {"control", "md5sums", "postinst"}),
            (collector_package, collector_control, {"control", "md5sums"}),
        ):
            _run(dpkg_deb, "--extract", str(package), str(root))
            _run(dpkg_deb, "--control", str(package), str(control))
            assert {path.name for path in control.iterdir()} == expected_control_files

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
        launcher_text = launcher.read_text(encoding="utf-8")
        assert "sys.dont_write_bytecode = True" in launcher_text
        assert "sys.pycache_prefix" in launcher_text
        assert (main_control / "postinst").stat().st_mode & 0o777 == 0o755
        assert not tuple((root / "usr/lib/perflens").glob("*.dist-info/uv_cache.json"))
        helper = root / "usr/lib/perflens/perflens-privileged-helper"
        assert helper.is_file()
        assert helper.stat().st_mode & 0o777 == 0o755
        trace_helper = root / "usr/lib/perflens/perflens-trace-helper"
        assert trace_helper.is_file()
        assert trace_helper.stat().st_mode & 0o777 == 0o755
        container_gate = root / "usr/lib/perflens/perflens-container-gate"
        assert container_gate.is_file()
        assert container_gate.stat().st_mode & 0o777 == 0o755
        _assert_safe_modes(root)
        policy = (root / "usr/share/perflens/collector/collector.example.toml").read_text(
            encoding="utf-8"
        )
        service = (root / "usr/share/perflens/collector/perflens-collector.service").read_text(
            encoding="utf-8"
        )
        helper_service = (
            root / "usr/share/perflens/collector/perflens-privileged-helper.service"
        ).read_text(encoding="utf-8")
        trace_policy = (
            root / "usr/share/perflens/collector/trace.example.toml"
        ).read_text(encoding="utf-8")
        trace_service = (
            root / "usr/share/perflens/collector/perflens-trace-helper.service"
        ).read_text(encoding="utf-8")
        assert "policy_version = 1" in policy
        assert 'privilege_mode = "cap_perfmon"' in policy
        assert "策略格式版本" in policy
        assert "max_spool_bytes = 5368709120" in policy
        assert "PerfLens never deletes old evidence automatically" in policy
        assert "perflens-admin spool-status checks quotas read-only" in policy
        assert "exactly one UID is supported" in policy
        assert service.startswith("# Managed by PerfLens.")
        assert "CapabilityBoundingSet=CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE" in helper_service
        assert "AmbientCapabilities=CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE" in helper_service
        assert "NoNewPrivileges=yes" in helper_service
        assert "SecureBits=" not in helper_service
        assert 'capture_backend = "target_filtered_kernel_v1"' in trace_policy
        assert "target_filter_before_userspace = true" in trace_policy
        assert "@PERFLENS_TRACE_CAPABILITIES@" in trace_service
        assert "ReadWritePaths=/run/perflens-trace-helper" in trace_service
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
        if path.is_dir() or path.name in {
            "perflens-launcher",
            "perflens-container-gate",
            "perflens-privileged-helper",
            "perflens-trace-helper",
        }:
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
    for helper in (
        root / "usr/lib/perflens/perflens-container-gate",
        root / "usr/lib/perflens/perflens-privileged-helper",
        root / "usr/lib/perflens/perflens-trace-helper",
    ):
        completed = subprocess.run(  # noqa: S603 - packaged fixed binary
            [ldd, str(helper)],
            check=True,
            capture_output=True,
            text=True,
        )
        assert "not found" not in completed.stdout


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
