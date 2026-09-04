from __future__ import annotations

import hashlib
import math
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import native_launcher as native
from perflens.runtime_locks.native_launcher import (
    NativeLaunchRequest,
    NativeManagedPthreadTarget,
    NativePthreadLauncher,
    NativePthreadProbePolicy,
    discover_native_pthread_probe_policy,
    inspect_managed_native_pthread_capability,
    inspect_native_pthread_host_target,
    inspect_native_pthread_installation,
    inspect_native_pthread_probe,
)
from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorDiscovery,
    RuntimeSupervisorReceipt,
    RuntimeSupervisorRequest,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PROBE_SOURCE = _PROJECT_ROOT / "native/pthread_probe/perflens_pthread_probe.c"

_TARGET_SOURCE = r"""
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (getenv("LEAK_ME") != NULL) return 13;
    if (getenv("PERFLENS_RUNTIME_LOCK_FD") == NULL) return 14;
    if (getenv("LD_PRELOAD") == NULL) return 15;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_lock(&lock) != 0) return 16;
    if (pthread_mutex_unlock(&lock) != 0) return 17;
    if (argc > 2 && strcmp(argv[2], "fork-child") == 0) {
        pid_t child = fork();
        if (child < 0) return 18;
        if (child == 0) {
            sleep(30);
            _exit(0);
        }
    }
    unsigned long delay_ms = argc > 1 ? strtoul(argv[1], NULL, 10) : 50;
    usleep(delay_ms * 1000);
    return 0;
}
"""


@pytest.fixture(autouse=True)
def use_test_runtime_supervisor(
    monkeypatch: pytest.MonkeyPatch,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    monkeypatch.setattr(
        native,
        "discover_runtime_supervisor_policy",
        lambda: RuntimeSupervisorDiscovery(
            "available",
            runtime_supervisor_client.policy,
            (),
        ),
    )


@pytest.fixture
def native_files(tmp_path: Path) -> tuple[Path, Path, Path, NativePthreadProbePolicy]:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is unavailable")
    project = tmp_path / "project"
    output = tmp_path / "private"
    project.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    target_source = project / "target.c"
    probe = tmp_path / "libperflens-pthread-probe.so"
    target = project / "target"
    target_source.write_text(_TARGET_SOURCE, encoding="utf-8")
    subprocess.run(  # noqa: S603 - fixed compiler argv in a test-only private directory
        (
            compiler,
            "-std=c11",
            "-shared",
            "-fPIC",
            "-O2",
            "-fvisibility=hidden",
            "-fstack-protector-strong",
            "-D_GNU_SOURCE=1",
            "-D_FORTIFY_SOURCE=3",
            str(_PROBE_SOURCE),
            "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack",
            "-ldl",
            "-pthread",
            "-o",
            str(probe),
        ),
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603 - fixed compiler argv in a test-only private directory
        (compiler, "-O2", "-pthread", "-o", str(target), str(target_source)),
        check=True,
        capture_output=True,
    )
    probe.chmod(0o644)
    target.chmod(0o755)
    policy = NativePthreadProbePolicy(
        path=probe,
        sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        owner_uid=os.geteuid(),
    )
    return project, output, target, policy


def _managed_target(**updates: object) -> NativeManagedPthreadTarget:
    values: dict[str, object] = {
        "container_target_id": "container-target-" + "1" * 20,
        "container_run_id": "container-run-" + "2" * 20,
        "target_identity_sha256": "3" * 64,
        "executable_path": "/workspace/build/workload",
        "executable_sha256": "4" * 64,
        "architecture": "amd64",
        "libc_family": "glibc",
        "glibc_version": "2.41",
        "dynamically_linked": True,
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
    }
    values.update(updates)
    return NativeManagedPthreadTarget(**values)  # type: ignore[arg-type]


def test_wheel_only_installation_reports_active_launcher_unavailable() -> None:
    capability = inspect_native_pthread_installation(None)

    assert capability.availability == "unavailable"
    assert capability.supported_semantics == ()
    assert "main DEB" in capability.limitations[0]


def test_launcher_never_falls_back_when_fixed_supervisor_is_unavailable(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, output, _target, policy = native_files
    monkeypatch.setattr(
        native,
        "discover_runtime_supervisor_policy",
        lambda: RuntimeSupervisorDiscovery(
            "unavailable",
            None,
            ("fixed supervisor missing",),
        ),
    )

    with pytest.raises(PerfLensError, match="fixed Runtime Lock supervisor is unavailable"):
        NativePthreadLauncher(
            project_root=project,
            private_output_root=output,
            probe_policy=policy,
            runtime_glibc_version="2.41",
        )


def test_probe_discovery_hashes_the_identity_pinned_fd(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    tmp_path: Path,
) -> None:
    _project, _output, _target_path, expected_policy = native_files
    discovery = discover_native_pthread_probe_policy(
        expected_policy.path,
        expected_owner_uid=os.geteuid(),
    )

    assert discovery.availability == "available"
    assert discovery.policy == expected_policy
    assert discovery.identity is not None
    assert discovery.identity.sha256 == expected_policy.sha256

    missing = discover_native_pthread_probe_policy(
        tmp_path / "missing.so",
        expected_owner_uid=os.geteuid(),
    )
    assert missing.availability == "unavailable"
    assert missing.policy is None
    assert missing.identity is None
    assert missing.limitations


def test_launcher_rejects_uid_override(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, output, _target_path, policy = native_files

    with pytest.raises(PerfLensError, match="UID override"):
        NativePthreadLauncher(
            project_root=project,
            private_output_root=output,
            probe_policy=policy,
            invoking_uid=os.geteuid() + 1,
            runtime_glibc_version="2.41",
        )


def test_probe_and_host_target_are_content_and_abi_bound(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, _output, target_path, policy = native_files

    probe = inspect_native_pthread_probe(policy)
    target = inspect_native_pthread_host_target(
        project,
        target_path,
        runtime_glibc_version="2.41",
    )

    assert probe.sha256 == policy.sha256
    assert probe.mode == 0o644
    assert target.project_relative_path == "target"
    assert target.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert "mutex" in target.visible_lock_surfaces
    assert target.runtime_glibc_version == "2.41"


def test_launcher_uses_pinned_fds_fixed_environment_and_private_stream(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    target = launcher.inspect_target(target_path)
    captured: list[RuntimeSupervisorRequest] = []
    supervisor = launcher._supervisor  # pyright: ignore[reportPrivateUsage]
    real_execute = supervisor.execute

    def recording_execute(request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
        captured.append(request)
        return real_execute(request)

    monkeypatch.setattr(supervisor, "execute", recording_execute)
    monkeypatch.setenv("LEAK_ME", "must-not-reach-target")

    result = launcher.launch(
        target_path,
        NativeLaunchRequest(arguments=("80",), duration_seconds=1),
        expected_target_identity_sha256=target.identity_sha256,
    )

    assert result.exit_code == 0
    assert result.termination_reason == "exited"
    assert result.target_start_ticks is not None
    assert result.target_pid in result.observed_tids
    assert result.footer_observed is True
    assert result.declared_event_count == 0
    assert result.lost_event_count == 0
    assert result.truncated is False
    assert result.stream_path.parent == output
    assert stat.S_IMODE(result.stream_path.stat().st_mode) == 0o600
    assert result.stream_sha256 == hashlib.sha256(result.stream_path.read_bytes()).hexdigest()
    assert len(captured) == 1
    request = captured[0]
    assert request.request.adapter == "native_pthread"
    assert request.arguments == ("80",)
    assert request.expected_parent_pid == os.getpid()
    assert request.expected_supervisor_sha256 == supervisor.policy.sha256
    assert result.accounted_active_seconds == math.ceil(result.duration_seconds)


def test_real_packaged_probe_launcher_stream_converts_end_to_end(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    target = launcher.inspect_target(target_path)

    result = launcher.launch(
        target_path,
        NativeLaunchRequest(
            arguments=("20",),
            semantics="exact",
            threshold_ns=None,
            duration_seconds=1,
            max_events=100,
        ),
        expected_target_identity_sha256=target.identity_sha256,
    )

    assert result.footer_observed is True
    assert result.declared_event_count is not None
    assert result.declared_event_count >= 4
    with result.stream_path.open("rb") as private_stream:
        receipt = convert_native_pthread_probe(
            private_stream,
            created_at=result.started_at,
        )
    assert receipt.raw_source_sha256 == result.stream_sha256
    assert receipt.evidence.target.target_pid == result.target_pid
    assert receipt.evidence.target.target_start_time_ticks == result.target_start_ticks
    assert len(receipt.evidence.events) == result.declared_event_count


def test_duration_limit_terminates_the_workload_group_and_preserves_stream(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    target = launcher.inspect_target(target_path)

    result = launcher.launch(
        target_path,
        NativeLaunchRequest(arguments=("5000",), duration_seconds=0.05),
        expected_target_identity_sha256=target.identity_sha256,
    )

    assert result.termination_reason == "duration_limit"
    # The supervisor reports the kernel termination signal directly.  It must
    # not invent a conventional shell-style exit status for a SIGKILL timeout.
    assert result.exit_code is None
    assert result.stream_path.exists()
    assert result.footer_observed is False


def test_launcher_removes_private_stream_when_receipt_inspection_fails(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    target = launcher.inspect_target(target_path)

    def fail_receipt(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("forced private receipt failure")

    monkeypatch.setattr(native, "_inspect_private_stream", fail_receipt)
    with pytest.raises(RuntimeError, match="forced private receipt failure"):
        launcher.launch(
            target_path,
            NativeLaunchRequest(arguments=("20",), duration_seconds=1),
            expected_target_identity_sha256=target.identity_sha256,
        )

    assert list(output.iterdir()) == []


def test_exact_controls_are_strictly_bounded() -> None:
    assert (
        NativeLaunchRequest(
            semantics="exact", threshold_ns=None, duration_seconds=3, max_events=20_000
        ).semantics
        == "exact"
    )
    with pytest.raises(PerfLensError, match="cannot set a threshold"):
        NativeLaunchRequest(semantics="exact", threshold_ns=1, duration_seconds=1)
    with pytest.raises(PerfLensError, match="three seconds"):
        NativeLaunchRequest(semantics="exact", threshold_ns=None, duration_seconds=3.01)
    with pytest.raises(PerfLensError, match="event limit"):
        NativeLaunchRequest(max_events=20_001)
    with pytest.raises(PerfLensError, match="argument"):
        NativeLaunchRequest(arguments=("bad\x00argument",))
    with pytest.raises(PerfLensError, match="semantics"):
        NativeLaunchRequest(semantics=cast(Any, "sampled"))
    with pytest.raises(PerfLensError, match="duration"):
        NativeLaunchRequest(duration_seconds=float("nan"))
    with pytest.raises(PerfLensError, match="threshold"):
        NativeLaunchRequest(threshold_ns=cast(Any, 1.5))
    with pytest.raises(PerfLensError, match="fixed tuple"):
        NativeLaunchRequest(arguments=cast(Any, ["not", "a", "tuple"]))


def test_authorized_target_replacement_is_rejected_before_exec(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    authorized = launcher.inspect_target(target_path)
    replacement = project / "replacement"
    shutil.copy2(target_path, replacement)
    replacement.write_bytes(replacement.read_bytes() + b"replacement")
    replacement.chmod(0o755)
    os.replace(replacement, target_path)

    with pytest.raises(PerfLensError, match="authorized target"):
        launcher.launch(
            target_path,
            NativeLaunchRequest(duration_seconds=1),
            expected_target_identity_sha256=authorized.identity_sha256,
        )
    assert tuple(output.iterdir()) == ()


def test_in_place_mutation_during_snapshot_is_rejected_before_exec(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    authorized = launcher.inspect_target(target_path)
    real_hash_descriptor = native._hash_descriptor  # pyright: ignore[reportPrivateUsage]
    target_hashes = 0

    def mutate_after_snapshot_pre_hash(
        descriptor: int,
        before: os.stat_result,
    ) -> str:
        nonlocal target_hashes
        digest = real_hash_descriptor(descriptor, before)
        if before.st_ino == authorized.inode:
            target_hashes += 1
            if target_hashes == 2:
                with target_path.open("r+b") as handle:
                    handle.seek(-1, os.SEEK_END)
                    original = handle.read(1)
                    handle.seek(-1, os.SEEK_END)
                    handle.write(bytes([original[0] ^ 0x01]))
                    handle.flush()
                    os.fsync(handle.fileno())
        return digest

    monkeypatch.setattr(native, "_hash_descriptor", mutate_after_snapshot_pre_hash)
    with pytest.raises(PerfLensError, match=r"changed|snapshot"):
        launcher.launch(
            target_path,
            NativeLaunchRequest(duration_seconds=1),
            expected_target_identity_sha256=authorized.identity_sha256,
        )
    assert tuple(output.iterdir()) == ()


def test_rpath_dependency_paths_and_session_escape_are_rejected(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, _output, _target_path, _policy = native_files
    compiler = shutil.which("cc")
    assert compiler is not None
    rpath_target = project / "rpath-target"
    subprocess.run(  # noqa: S603 - fixed compiler argv in a test-only private directory
        (
            compiler,
            "-O2",
            "-pthread",
            "-Wl,-rpath,/tmp/perflens-untrusted",
            "-o",
            str(rpath_target),
            str(project / "target.c"),
        ),
        check=True,
        capture_output=True,
    )
    rpath_target.chmod(0o755)
    with pytest.raises(PerfLensError, match=r"DT_RPATH|DT_RUNPATH"):
        inspect_native_pthread_host_target(
            project,
            rpath_target,
            runtime_glibc_version="2.41",
        )

    common: dict[str, Any] = {
        "elf_type": "ET_DYN",
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "glibc_versions": (),
        "defined_dynamic_symbols": frozenset(),
        "probe_abi_version": None,
        "probe_protocol_version": None,
    }
    slashed = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        needed_libraries=("libc.so.6", "/tmp/libevil.so"),
        imported_dynamic_symbols=frozenset(),
        **common,  # type: ignore[arg-type]
    )
    unreviewed = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        needed_libraries=("libc.so.6", "libapplication.so"),
        imported_dynamic_symbols=frozenset(),
        **common,  # type: ignore[arg-type]
    )
    escaping = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        needed_libraries=("libc.so.6",),
        imported_dynamic_symbols=frozenset({"setsid"}),
        **common,  # type: ignore[arg-type]
    )
    with pytest.raises(PerfLensError, match="dependency paths"):
        native._validate_target_elf(slashed, "2.41")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="non-reviewed"):
        native._validate_target_elf(unreviewed, "2.41")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="escape"):
        native._validate_target_elf(escaping, "2.41")  # pyright: ignore[reportPrivateUsage]


def test_elf_imports_exports_wrapper_types_and_resource_bounds_are_distinct(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, _output, target_path, _policy = native_files
    descriptor = os.open(target_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = native._read_elf_metadata(  # pyright: ignore[reportPrivateUsage]
            descriptor,
            target_path.stat().st_size,
            require_probe=False,
        )
        assert "pthread_mutex_lock" in metadata.imported_dynamic_symbols
        assert "pthread_mutex_lock" not in metadata.defined_dynamic_symbols
        with pytest.raises(PerfLensError, match="size"):
            native._read_elf_metadata(  # pyright: ignore[reportPrivateUsage]
                descriptor,
                native._MAX_ELF_BYTES + 1,  # pyright: ignore[reportPrivateUsage]
                require_probe=False,
            )
    finally:
        os.close(descriptor)

    wrapper_names = (
        native.NATIVE_PTHREAD_PROBE_EXPORTS  # pyright: ignore[reportPrivateUsage]
        - native.NATIVE_PTHREAD_PROBE_MARKER_EXPORTS  # pyright: ignore[reportPrivateUsage]
    )
    valid_wrappers: dict[str, dict[str, object]] = {
        name: {
            "st_info": {"type": "STT_FUNC", "bind": "STB_GLOBAL"},
            "st_other": {"visibility": "STV_DEFAULT"},
            "st_value": 0x1100,
            "st_size": 16,
        }
        for name in wrapper_names
    }
    native._validate_probe_wrapper_symbols(  # pyright: ignore[reportPrivateUsage]
        valid_wrappers,
        executable_load_ranges=((0x1000, 0x2000),),
    )
    invalid_wrappers = {name: dict(symbol) for name, symbol in valid_wrappers.items()}
    first_wrapper = next(iter(wrapper_names))
    invalid_wrappers[first_wrapper] = {
        **invalid_wrappers[first_wrapper],
        "st_info": {"type": "STT_OBJECT", "bind": "STB_GLOBAL"},
    }
    with pytest.raises(PerfLensError, match="wrapper type"):
        native._validate_probe_wrapper_symbols(  # pyright: ignore[reportPrivateUsage]
            invalid_wrappers,
            executable_load_ranges=((0x1000, 0x2000),),
        )
    for bad_address, bad_size in ((0x1100, 0), (0x1FF8, 16), ((1 << 64) - 8, 16)):
        invalid_interval = {name: dict(symbol) for name, symbol in valid_wrappers.items()}
        invalid_interval[first_wrapper] = {
            **invalid_interval[first_wrapper],
            "st_value": bad_address,
            "st_size": bad_size,
        }
        with pytest.raises(PerfLensError, match="wrapper type"):
            native._validate_probe_wrapper_symbols(  # pyright: ignore[reportPrivateUsage]
                invalid_interval,
                executable_load_ranges=((0x1000, 0x2000),),
            )

    class ExcessiveProgramHeaders:
        elfclass = 64
        little_endian = True

        def __getitem__(self, key: str) -> str:
            if key == "e_machine":
                return "EM_X86_64"
            raise KeyError(key)

        def num_segments(self) -> int:
            return native._MAX_ELF_PROGRAM_HEADERS + 1  # pyright: ignore[reportPrivateUsage]

        def num_sections(self) -> int:
            return 1

    def excessive_headers(_handle: object) -> ExcessiveProgramHeaders:
        return ExcessiveProgramHeaders()

    monkeypatch.setattr(native, "ELFFile", excessive_headers)
    descriptor = os.open(target_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(PerfLensError, match="program headers"):
            native._read_elf_metadata(  # pyright: ignore[reportPrivateUsage]
                descriptor,
                target_path.stat().st_size,
                require_probe=False,
            )
    finally:
        os.close(descriptor)

    defined_only = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        elf_type="ET_DYN",
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed_libraries=("libc.so.6",),
        glibc_versions=(),
        imported_dynamic_symbols=frozenset(),
        defined_dynamic_symbols=frozenset({"pthread_mutex_lock"}),
    )
    assert native.native_pthread_visible_lock_kinds(defined_only.imported_dynamic_symbols) == ()
    with pytest.raises(PerfLensError, match="fixed bound"):
        native._bounded_elf_string(  # pyright: ignore[reportPrivateUsage]
            "x" * (native._MAX_ELF_SYMBOL_NAME_BYTES + 1),  # pyright: ignore[reportPrivateUsage]
            label="dynamic symbol",
        )


def test_probe_replacement_is_rejected_after_launcher_creation(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    project, output, target_path, policy = native_files
    launcher = NativePthreadLauncher(
        project_root=project,
        private_output_root=output,
        probe_policy=policy,
        runtime_glibc_version="2.41",
    )
    target = launcher.inspect_target(target_path)
    replacement = policy.path.with_suffix(".replacement.so")
    shutil.copy2(policy.path, replacement)
    replacement.write_bytes(replacement.read_bytes() + b"replacement")
    replacement.chmod(0o644)
    os.replace(replacement, policy.path)

    with pytest.raises(PerfLensError, match="digest"):
        launcher.launch(
            target_path,
            NativeLaunchRequest(duration_seconds=1),
            expected_target_identity_sha256=target.identity_sha256,
        )
    assert tuple(output.iterdir()) == ()


@pytest.mark.parametrize("unsafe_mode", [0o6755, 0o777])
def test_privileged_or_writable_target_is_rejected(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    unsafe_mode: int,
) -> None:
    project, _output, target_path, _policy = native_files
    target_path.chmod(unsafe_mode)

    with pytest.raises(PerfLensError, match=r"privilege bits|mode"):
        inspect_native_pthread_host_target(
            project,
            target_path,
            runtime_glibc_version="2.41",
        )


def test_target_file_capabilities_are_rejected(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, _output, target_path, _policy = native_files

    def fake_getxattr(*_args: object, **_kwargs: object) -> bytes:
        return b"capability"

    monkeypatch.setattr(native.os, "getxattr", fake_getxattr)

    with pytest.raises(PerfLensError, match="file capabilities"):
        inspect_native_pthread_host_target(
            project,
            target_path,
            runtime_glibc_version="2.41",
        )


def test_symlink_and_project_escape_are_rejected(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    tmp_path: Path,
) -> None:
    project, _output, target_path, _policy = native_files
    symlink = project / "linked"
    symlink.symlink_to(target_path)
    with pytest.raises(PerfLensError, match="symlink"):
        inspect_native_pthread_host_target(
            project,
            symlink,
            runtime_glibc_version="2.41",
        )
    outside = tmp_path / "outside"
    shutil.copy2(target_path, outside)
    with pytest.raises(PerfLensError, match="escapes"):
        inspect_native_pthread_host_target(
            project,
            outside,
            runtime_glibc_version="2.41",
        )


def test_unsupported_static_musl_loader_and_glibc_matrix_are_rejected() -> None:
    static = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        elf_type="ET_EXEC",
        interpreter=None,
        needed_libraries=(),
        glibc_versions=(),
        imported_dynamic_symbols=frozenset(),
    )
    musl = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        elf_type="ET_DYN",
        interpreter="/lib/ld-musl-x86_64.so.1",
        needed_libraries=("libc.musl-x86_64.so.1",),
        glibc_versions=(),
        imported_dynamic_symbols=frozenset(),
    )
    too_new = native._ElfMetadata(  # pyright: ignore[reportPrivateUsage]
        elf_type="ET_DYN",
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed_libraries=("libc.so.6",),
        glibc_versions=("2.42",),
        imported_dynamic_symbols=frozenset(),
    )

    with pytest.raises(PerfLensError, match="Static"):
        native._validate_target_elf(static, "2.41")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="musl"):
        native._validate_target_elf(musl, "2.41")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="newer glibc"):
        native._validate_target_elf(too_new, "2.41")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match=r"2\.36/2\.41"):
        native._runtime_glibc_version("2.37")  # pyright: ignore[reportPrivateUsage]


def test_unsupported_glibc_disables_only_active_native_instrumentation(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    _project, _output, _target, policy = native_files

    capability = inspect_native_pthread_installation(
        policy,
        runtime_glibc_version="2.37",
    )

    assert capability.availability == "unavailable"
    assert capability.supported_semantics == ()
    assert any("2.36/2.41" in limitation for limitation in capability.limitations)
    assert any("import and analysis remain available" in item for item in capability.limitations)
    assert any("call stacks or source attribution" in item for item in capability.limitations)
    assert any("self-observed" in item for item in capability.limitations)


def test_managed_docker_capability_exposes_typed_gate_launch(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
) -> None:
    _project, _output, _target, policy = native_files
    capability = inspect_managed_native_pthread_capability(
        _managed_target(),
        probe_policy=policy,
    )

    assert capability.availability == "available"
    assert capability.launch_backend == "managed_docker"
    assert capability.target_identity_sha256 == "3" * 64
    assert capability.supported_semantics == ("exact", "thresholded")
    assert capability.supported_lock_surfaces == (
        "condition",
        "mutex",
        "rwlock_read",
        "rwlock_write",
    )
    assert any("does not authorize" in limitation for limitation in capability.limitations)
    assert any(
        "parent Docker optimization Preview" in limitation
        for limitation in capability.limitations
    )
    assert all("socket" not in field.lower() for field in capability.__dataclass_fields__)


def test_managed_docker_capability_without_probe_keeps_import_available() -> None:
    capability = inspect_managed_native_pthread_capability(
        _managed_target(),
        probe_policy=None,
    )

    assert capability.availability == "unavailable"
    assert capability.probe_sha256 is None
    assert capability.supported_semantics == ()
    assert capability.supported_lock_surfaces == ()
    assert any(
        "import and deterministic analysis remain available" in limitation
        for limitation in capability.limitations
    )


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"dynamically_linked": False}, "Static"),
        ({"libc_family": "musl", "glibc_version": None}, "musl"),
        ({"glibc_version": "2.40"}, "2.36/2.41"),
        ({"interpreter": "/unsupported/loader"}, "loader"),
    ],
)
def test_managed_docker_unsupported_targets_are_unavailable(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    updates: dict[str, object],
    expected: str,
) -> None:
    _project, _output, _target, policy = native_files
    capability = inspect_managed_native_pthread_capability(
        _managed_target(**updates),
        probe_policy=policy,
    )

    assert capability.availability == "unavailable"
    assert capability.supported_semantics == ()
    assert capability.supported_lock_surfaces == ()
    assert any(expected in limitation for limitation in capability.limitations)


def test_managed_target_description_rejects_path_and_identity_injection() -> None:
    with pytest.raises(PerfLensError, match="normalized"):
        _managed_target(executable_path="/workspace/../etc/passwd")
    with pytest.raises(PerfLensError, match="ContainerTarget"):
        _managed_target(container_target_id="container-target-invalid")


def test_probe_policy_rejects_wrong_mode_digest_and_missing_markers(
    native_files: tuple[Path, Path, Path, NativePthreadProbePolicy],
    tmp_path: Path,
) -> None:
    _project, _output, _target, policy = native_files
    with pytest.raises(PerfLensError, match="invalid digest"):
        NativePthreadProbePolicy(path=policy.path, sha256="invalid", owner_uid=os.geteuid())
    with pytest.raises(PerfLensError, match="0644"):
        NativePthreadProbePolicy(
            path=policy.path,
            sha256=policy.sha256,
            owner_uid=os.geteuid(),
            mode=0o755,
        )

    compiler = shutil.which("cc")
    assert compiler is not None
    source = tmp_path / "missing-marker.c"
    source.write_text("int unrelated_symbol = 1;\n", encoding="utf-8")
    missing = tmp_path / "missing-marker.so"
    subprocess.run(  # noqa: S603 - fixed compiler argv in a test-only private directory
        (compiler, "-shared", "-fPIC", "-o", str(missing), str(source)),
        check=True,
        capture_output=True,
    )
    missing.chmod(0o644)
    missing_policy = NativePthreadProbePolicy(
        path=missing,
        sha256=hashlib.sha256(missing.read_bytes()).hexdigest(),
        owner_uid=os.geteuid(),
    )
    with pytest.raises(PerfLensError, match=r"exports|marker|wrapper"):
        inspect_native_pthread_probe(missing_policy)
