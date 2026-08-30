"""Inspect and smoke-test extracted split PerfLens Debian packages without root."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any, cast

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from perflens import __version__
from perflens.distribution.debian import DEBIAN_PACKAGE_REVISION
from perflens.docker.elf import validate_self_contained_elf
from perflens.runtime_locks.native_pthread_abi import (
    NATIVE_PTHREAD_PROBE_ABI_VERSION,
    NATIVE_PTHREAD_PROBE_EXPORTS,
    NATIVE_PTHREAD_PROBE_NEEDED_LIBRARIES,
    NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION,
    NATIVE_PTHREAD_WRAPPER_LOCK_KINDS,
)


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
        collector_candidates = tuple(directory.glob(f"perflens-collector_{package_version}_*.deb"))
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
    assert "docker" not in main_dependencies.lower()
    assert "libc6 (>= 2.36)" in main_dependencies
    assert any(
        f"python3 (>= {abi})" in main_dependencies
        and f"python3 (<< 3.{int(abi.removeprefix('3.')) + 1})" in main_dependencies
        for abi in ("3.12", "3.13")
    )
    assert f"perflens (= {package_version})" in _field(dpkg_deb, collector_package, "Depends")
    collector_dependencies = _field(dpkg_deb, collector_package, "Depends")
    assert "docker" not in collector_dependencies.lower()
    for dependency in ("libbpf1", "libelf1", "zlib1g", "libzstd1"):
        assert dependency in collector_dependencies

    with tempfile.TemporaryDirectory(prefix="perflens-deb-smoke-") as directory:
        root = Path(directory) / "root"
        main_root = Path(directory) / "main-root"
        collector_root = Path(directory) / "collector-root"
        main_control = Path(directory) / "main-control"
        collector_control = Path(directory) / "collector-control"
        for package, package_root, control, expected_control_files in (
            (main_package, main_root, main_control, {"control", "md5sums", "postinst"}),
            (collector_package, collector_root, collector_control, {"control", "md5sums"}),
        ):
            _run(dpkg_deb, "--extract", str(package), str(package_root))
            _run(dpkg_deb, "--extract", str(package), str(root))
            _run(dpkg_deb, "--control", str(package), str(control))
            assert {path.name for path in control.iterdir()} == expected_control_files
            assert not (package_root / "etc").exists()
            assert not (package_root / "run").exists()
            assert not (package_root / "var").exists()

        packaged_gate = Path("usr/lib/perflens/perflens-container-gate")
        assert (main_root / packaged_gate).is_file()
        assert not (collector_root / packaged_gate).exists()
        packaged_probe = Path("usr/lib/perflens/libperflens-pthread-probe.so")
        probe = main_root / packaged_probe
        assert probe.is_file()
        assert not probe.is_symlink()
        assert stat.S_IMODE(probe.stat().st_mode) == 0o644
        assert not (collector_root / packaged_probe).exists()
        _assert_root_owned_archive_file(
            dpkg_deb,
            main_package,
            packaged_probe,
            expected_mode=0o644,
        )
        _assert_pthread_probe_hardening(probe)
        postinst_text = (main_control / "postinst").read_text(encoding="utf-8")
        for forbidden in (
            "docker",
            "systemctl",
            "usermod",
            "groupadd",
            "setcap",
            "/etc/perflens",
        ):
            assert forbidden not in postinst_text

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
        docker_config = main_root / "usr/share/perflens/docker-empty-config"
        assert docker_config.is_dir()
        assert not tuple(docker_config.iterdir())
        assert docker_config.stat().st_mode & 0o777 == 0o755
        assert not (collector_root / "usr/share/perflens/docker-empty-config").exists()
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
        trace_policy = (root / "usr/share/perflens/collector/trace.example.toml").read_text(
            encoding="utf-8"
        )
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
    gate = root / "usr/lib/perflens/perflens-container-gate"
    with gate.open("rb") as gate_stream:
        validate_self_contained_elf(
            gate_stream.fileno(),
            file_size=gate.stat().st_size,
        )
    for helper in (
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


def _assert_root_owned_archive_file(
    dpkg_deb: str,
    package: Path,
    relative_path: Path,
    *,
    expected_mode: int,
) -> None:
    completed = subprocess.run(  # noqa: S603 - resolved dpkg-deb and fixed package operation
        [dpkg_deb, "--fsys-tarfile", str(package)],
        check=True,
        capture_output=True,
    )
    with tarfile.open(fileobj=BytesIO(completed.stdout), mode="r:") as archive:
        member = archive.getmember(f"./{relative_path.as_posix()}")
        assert member.isfile()
        assert member.uid == 0
        assert member.gid == 0
        assert stat.S_IMODE(member.mode) == expected_mode
        assert not any("capability" in key.lower() for key in member.pax_headers)


def _assert_pthread_probe_hardening(probe: Path) -> None:
    with probe.open("rb") as handle:
        elf = ELFFile(handle)
        assert elf.elfclass == 64
        assert elf.little_endian
        assert elf["e_machine"] == "EM_X86_64"
        assert elf["e_type"] == "ET_DYN"

        has_relro = False
        for segment in elf.iter_segments():
            segment_type = segment["p_type"]
            assert segment_type != "PT_INTERP"
            if segment_type == "PT_GNU_RELRO":
                has_relro = True
            if segment_type == "PT_GNU_STACK":
                assert int(segment["p_flags"]) & 1 == 0
        assert has_relro

        symbols: dict[str, Any] = {}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection) and section.name == ".dynsym":
                symbols.update(
                    (symbol.name, symbol)
                    for symbol in section.iter_symbols()
                    if symbol.name and symbol["st_shndx"] != "SHN_UNDEF"
                )
        assert frozenset(symbols) == NATIVE_PTHREAD_PROBE_EXPORTS
        for name in NATIVE_PTHREAD_WRAPPER_LOCK_KINDS:
            symbol = symbols[name]
            assert symbol["st_info"]["type"] == "STT_FUNC"
            assert symbol["st_info"]["bind"] == "STB_GLOBAL"
            assert symbol["st_other"]["visibility"] == "STV_DEFAULT"
            assert int(symbol["st_value"]) != 0
            assert int(symbol["st_size"]) != 0
            assert _elf_symbol_in_executable_load(elf, symbol)
        abi_symbol = symbols["perflens_pthread_probe_abi_version"]
        protocol_symbol = symbols["perflens_pthread_probe_protocol_version"]
        for symbol in (abi_symbol, protocol_symbol):
            assert symbol["st_info"]["bind"] == "STB_GLOBAL"
            assert symbol["st_other"]["visibility"] == "STV_DEFAULT"
        assert (
            int.from_bytes(_elf_symbol_bytes(elf, abi_symbol, 4), byteorder="little")
            == NATIVE_PTHREAD_PROBE_ABI_VERSION
        )
        assert (
            _elf_symbol_bytes(elf, protocol_symbol, 4)
            == NATIVE_PTHREAD_PROBE_PROTOCOL_VERSION.encode("ascii") + b"\x00"
        )

        dynamic = elf.get_section_by_name(".dynamic")
        assert dynamic is not None
        tags = tuple(cast(Any, dynamic).iter_tags())
        tag_names = {str(tag.entry.d_tag) for tag in tags}
        needed_libraries = frozenset(
            str(tag.needed) for tag in tags if str(tag.entry.d_tag) == "DT_NEEDED"
        )
        assert needed_libraries == NATIVE_PTHREAD_PROBE_NEEDED_LIBRARIES
        assert not {"DT_RPATH", "DT_RUNPATH", "DT_TEXTREL"} & tag_names
        bind_now = (
            "DT_BIND_NOW" in tag_names
            or any(str(tag.entry.d_tag) == "DT_FLAGS" and int(tag.entry.d_val) & 8 for tag in tags)
            or any(
                str(tag.entry.d_tag) == "DT_FLAGS_1" and int(tag.entry.d_val) & 1 for tag in tags
            )
        )
        assert bind_now


def _elf_symbol_in_executable_load(elf: ELFFile, symbol: Any) -> bool:
    symbol_address = int(symbol["st_value"])
    symbol_size = int(symbol["st_size"])
    return any(
        segment["p_type"] == "PT_LOAD"
        and int(segment["p_flags"]) & 1 != 0
        and symbol_address >= int(segment["p_vaddr"])
        and symbol_address + symbol_size <= int(segment["p_vaddr"]) + int(segment["p_filesz"])
        for segment in elf.iter_segments()
    )


def _elf_symbol_bytes(elf: ELFFile, symbol: Any, size: int) -> bytes:
    symbol_address = int(symbol["st_value"])
    assert int(symbol["st_size"]) >= size
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        segment_address = int(segment["p_vaddr"])
        segment_size = int(segment["p_filesz"])
        relative = symbol_address - segment_address
        if relative < 0 or relative + size > segment_size:
            continue
        position = elf.stream.tell()
        try:
            elf.stream.seek(int(segment["p_offset"]) + relative)
            data = elf.stream.read(size)
        finally:
            elf.stream.seek(position)
        assert len(data) == size
        return data
    raise AssertionError("probe ABI marker is not backed by a loadable file segment")


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
