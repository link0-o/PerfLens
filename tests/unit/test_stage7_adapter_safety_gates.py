from __future__ import annotations

import errno
import hashlib
import os
import subprocess
import zipfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import cpython_adapter as cpython
from perflens.runtime_locks import go_pprof_launcher as go
from perflens.runtime_locks import java_jfr_capability as java_capability
from perflens.runtime_locks import java_jfr_launcher as java
from perflens.runtime_locks import native_launcher as native
from perflens.runtime_locks.go_pprof_adapter import GoToolIdentity
from perflens.runtime_locks.go_pprof_launcher import (
    GoPprofLaunchRequest,
    GoPprofRawResult,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrDirectoryPolicy,
    JavaJfrFilePolicy,
    JavaJfrLaunchPolicy,
    JavaJfrLaunchRequest,
    JavaJfrNativeLibraryPolicy,
    JavaJfrPayloadFilePolicy,
    JavaJfrRuntimePayloadPolicy,
)
from perflens.runtime_locks.native_launcher import (
    NativeLaunchRequest,
    NativeManagedPthreadTarget,
    NativePthreadProbePolicy,
)


def _sha(character: str = "a") -> str:
    return character * 64


def _java_directory(path: Path) -> JavaJfrDirectoryPolicy:
    return JavaJfrDirectoryPolicy(
        path=path,
        device=1,
        inode=2,
        owner_uid=1000,
        mode=0o755,
        links=2,
        size=4096,
        modified_ns=3,
        changed_ns=4,
    )


def _java_payload_file(path: Path, character: str) -> JavaJfrPayloadFilePolicy:
    return JavaJfrPayloadFilePolicy(
        path=path,
        sha256=_sha(character),
        device=1,
        inode=2,
        owner_uid=1000,
        mode=0o644,
        size=8,
        modified_ns=3,
        changed_ns=4,
    )


def _java_native_library(path: Path, relative: str) -> JavaJfrNativeLibraryPolicy:
    return JavaJfrNativeLibraryPolicy(
        relative_path=relative,
        named_path=path,
        resolved_path=path,
        source_kind="regular",
        link_target_sha256=None,
        link_device=None,
        link_inode=None,
        link_owner_uid=None,
        link_mode=None,
        link_links=None,
        link_size=None,
        link_modified_ns=None,
        link_changed_ns=None,
        sha256=_sha("c"),
        device=1,
        inode=2,
        owner_uid=1000,
        mode=0o644,
        links=1,
        size=8,
        modified_ns=3,
        changed_ns=4,
    )


def _java_runtime_payload(tmp_path: Path) -> JavaJfrRuntimePayloadPolicy:
    root = tmp_path / "jdk"
    directories = (
        _java_directory(root),
        _java_directory(root / "bin"),
        _java_directory(root / "lib"),
    )
    payloads = (
        _java_payload_file(root / "release", "d"),
        _java_payload_file(root / "lib/modules", "e"),
    )
    libraries = (
        _java_native_library(root / "lib/libjli.so", "libjli.so"),
        _java_native_library(root / "lib/server/libjvm.so", "server/libjvm.so"),
    )
    manifest = java._derive_native_library_policy_manifest_identity(  # pyright: ignore[reportPrivateUsage]
        libraries
    )
    native_bytes = sum(item.size for item in libraries)
    provisional = object.__new__(JavaJfrRuntimePayloadPolicy)
    for name, value in (
        ("jdk_root", directories[0]),
        ("bin_directory", directories[1]),
        ("lib_directory", directories[2]),
        ("release_file", payloads[0]),
        ("modules_file", payloads[1]),
        ("native_libraries", libraries),
        ("native_library_bytes", native_bytes),
        ("native_library_manifest_sha256", manifest),
        ("identity_sha256", _sha("0")),
    ):
        object.__setattr__(provisional, name, value)
    identity = java._derive_runtime_payload_policy_identity(  # pyright: ignore[reportPrivateUsage]
        provisional
    )
    return JavaJfrRuntimePayloadPolicy(
        jdk_root=directories[0],
        bin_directory=directories[1],
        lib_directory=directories[2],
        release_file=payloads[0],
        modules_file=payloads[1],
        native_libraries=libraries,
        native_library_bytes=native_bytes,
        native_library_manifest_sha256=manifest,
        identity_sha256=identity,
    )


def _java_launch_policy(tmp_path: Path) -> JavaJfrLaunchPolicy:
    root = tmp_path / "jdk"
    return JavaJfrLaunchPolicy(
        java_tool=JavaJfrFilePolicy(root / "bin/java", _sha("1"), 1000, 0o755),
        jfr_tool=JavaJfrFilePolicy(root / "bin/jfr", _sha("2"), 1000, 0o755),
        jfc_profile=JavaJfrFilePolicy(tmp_path / "balanced.jfc", _sha("3"), 0, 0o644),
        jdk_major=25,
        profile="balanced",
        runtime_payload=_java_runtime_payload(tmp_path),
    )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"path": Path("relative")}, "absolute"),
        ({"sha256": "ABC"}, "digest"),
        ({"owner_uid": True}, "owner UID"),
        ({"owner_uid": -1}, "owner UID"),
        ({"mode": 0o777}, "mode"),
    ],
)
def test_java_file_policy_rejects_untrusted_fields(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "path": tmp_path / "java",
        "sha256": _sha(),
        "owner_uid": 0,
        "mode": 0o755,
    }
    values.update(updates)
    with pytest.raises(PerfLensError, match=message):
        JavaJfrFilePolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"path": Path("relative")}, "absolute"),
        ({"mode": 0o775}, "mode"),
        ({"device": -1}, "identity"),
        ({"changed_ns": -1}, "identity"),
    ],
)
def test_java_directory_policy_rejects_untrusted_fields(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "path": tmp_path / "jdk",
        "device": 1,
        "inode": 2,
        "owner_uid": 0,
        "mode": 0o755,
        "links": 2,
        "size": 4096,
        "modified_ns": 3,
        "changed_ns": 4,
    }
    values.update(updates)
    with pytest.raises(PerfLensError, match=message):
        JavaJfrDirectoryPolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"path": Path("relative")}, "absolute"),
        ({"sha256": "x"}, "digest"),
        ({"mode": 0o666}, "mode"),
        ({"size": -1}, "identity"),
    ],
)
def test_java_payload_policy_rejects_untrusted_fields(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    valid = _java_payload_file(tmp_path / "release", "d")
    with pytest.raises(PerfLensError, match=message):
        replace(valid, **updates)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"relative_path": "../libjli.so"}, "relative path"),
        ({"relative_path": "/libjli.so"}, "relative path"),
        ({"named_path": Path("relative")}, "not absolute"),
        ({"sha256": "x"}, "digest"),
        ({"mode": 0o666}, "identity"),
        ({"size": 0}, "identity"),
        ({"link_inode": 1}, "symlink metadata"),
        ({"resolved_path": Path("/different")}, "symlink metadata"),
        ({"source_kind": "symlink"}, "symlink identity"),
    ],
)
def test_java_native_library_policy_rejects_untrusted_fields(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    valid = _java_native_library(tmp_path / "jdk/lib/libjli.so", "libjli.so")
    with pytest.raises(PerfLensError, match=message):
        replace(valid, **updates)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"identity_sha256": "x"}, "payload identity digest"),
        ({"native_library_manifest_sha256": "x"}, "manifest digest"),
        ({"bin_directory": _java_directory(Path("/wrong/bin"))}, "layout"),
        ({"native_libraries": ()}, "exceeds its bound"),
        ({"native_library_bytes": 1}, "exceeds its bound"),
        (
            {
                "native_libraries": (
                    _java_native_library(Path("/jdk/lib/server/libjvm.so"), "server/libjvm.so"),
                    _java_native_library(Path("/jdk/lib/libjli.so"), "libjli.so"),
                )
            },
            "manifest layout",
        ),
        ({"native_library_manifest_sha256": _sha("f")}, "differs from its files"),
    ],
)
def test_java_runtime_payload_rejects_manifest_grafts(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    valid = _java_runtime_payload(tmp_path)
    with pytest.raises(PerfLensError, match=message):
        replace(valid, **updates)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"jdk_major": 23}, "17/21/25"),
        ({"profile": "unknown"}, "profile"),
        (
            {"java_tool": JavaJfrFilePolicy(Path("/jdk/bin/not-java"), _sha(), 0, 0o755)},
            "fixed java and jfr",
        ),
        (
            {"jfr_tool": JavaJfrFilePolicy(Path("/other/bin/jfr"), _sha(), 0, 0o755)},
            "same JDK bin",
        ),
        (
            {"java_tool": JavaJfrFilePolicy(Path("/other/bin/java"), _sha(), 0, 0o755)},
            "same JDK",
        ),
        (
            {"jfc_profile": JavaJfrFilePolicy(Path("/p.jfc"), _sha(), 0, 0o755)},
            "packaged mode",
        ),
    ],
)
def test_java_launch_policy_rejects_mixed_toolchains(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    valid = _java_launch_policy(tmp_path)
    with pytest.raises(PerfLensError, match=message):
        replace(valid, **updates)


def test_java_launch_policy_requires_executable_tool_modes(tmp_path: Path) -> None:
    valid = _java_launch_policy(tmp_path)
    with pytest.raises(PerfLensError, match="executable modes"):
        replace(valid, java_tool=replace(valid.java_tool, mode=0o644))


def test_java_runtime_payload_rejects_file_escape_and_identity_graft(tmp_path: Path) -> None:
    valid = _java_runtime_payload(tmp_path)
    escaped = replace(
        valid.native_libraries[0],
        named_path=tmp_path / "outside/libjli.so",
        resolved_path=tmp_path / "outside/libjli.so",
    )
    libraries = (escaped, valid.native_libraries[1])
    manifest = java._derive_native_library_policy_manifest_identity(  # pyright: ignore[reportPrivateUsage]
        libraries
    )
    with pytest.raises(PerfLensError, match="escapes the JDK lib tree"):
        replace(
            valid,
            native_libraries=libraries,
            native_library_manifest_sha256=manifest,
        )
    with pytest.raises(PerfLensError, match="payload identity differs"):
        replace(valid, identity_sha256=_sha("9"))


@pytest.mark.parametrize(
    ("arguments", "duration", "message"),
    [
        (("bad\0argument",), 1, "argument is invalid"),
        ((("x" * 4097),), 1, "exceeds its bound"),
        (tuple("x" for _ in range(257)), 1, "bounded tuple"),
        ((), 0, "duration"),
        ((), True, "duration"),
        ((), float("inf"), "duration"),
    ],
)
def test_java_launch_request_rejects_unbounded_inputs(
    arguments: tuple[str, ...], duration: float, message: str
) -> None:
    with pytest.raises(PerfLensError, match=message):
        JavaJfrLaunchRequest(arguments=arguments, duration_seconds=duration)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"x\0y", "safe bound"),
        (b"\xff", "valid UTF-8"),
        (b" continuation", "folding"),
        (b"broken", "malformed"),
        (b"Main-Class: Main\nmain-class: Other\n", "duplicate"),
    ],
)
def test_java_manifest_parser_rejects_ambiguous_content(raw: bytes, message: str) -> None:
    with pytest.raises(PerfLensError, match=message):
        java._manifest_attributes(raw)  # pyright: ignore[reportPrivateUsage]


def _write_jar(path: Path, entries: tuple[tuple[str, bytes, int | None], ...]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, content)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ((("payload", b"x", None),), "one manifest"),
        (
            (
                ("META-INF/MANIFEST.MF", b"Main-Class: Main\n", None),
                ("meta-inf/manifest.mf", b"Main-Class: Main\n", None),
            ),
            "one manifest",
        ),
        (
            (("META-INF/MANIFEST.MF", b"Main-Class: Main\nClass-Path: foreign.jar\n", None),),
            "classpath",
        ),
        ((("META-INF/MANIFEST.MF", b"Main-Class: bad main\n", None),), "Main-Class"),
    ],
)
def test_java_jar_manifest_rejects_unsafe_archive_contract(
    tmp_path: Path,
    entries: tuple[tuple[str, bytes, int | None], ...],
    message: str,
) -> None:
    jar = tmp_path / "workload.jar"
    _write_jar(jar, entries)
    descriptor = os.open(jar, os.O_RDONLY)
    try:
        with pytest.raises(PerfLensError, match=message):
            java._inspect_jar_manifest(  # pyright: ignore[reportPrivateUsage]
                descriptor, jar.stat().st_size
            )
    finally:
        os.close(descriptor)


def test_java_capability_parsers_reject_drift_and_failed_tools() -> None:
    with pytest.raises(ValueError, match="empty"):
        java_capability.parse_java_jfr_metadata("")
    with pytest.raises(ValueError, match="required event"):
        java_capability.parse_java_jfr_metadata('@Name("jdk.DataLoss")\nclass DataLoss {}')
    with pytest.raises(ValueError, match="version output"):
        java_capability._parse_java_version("not-java")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="version output"):
        java_capability._parse_jfr_version("not-jfr")  # pyright: ignore[reportPrivateUsage]

    def failed(
        argv: Sequence[str], _timeout: float, _max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "bad")

    with pytest.raises(ValueError, match="command failed"):
        java_capability._invoke(failed, ("java", "-version"))  # pyright: ignore[reportPrivateUsage]

    def oversized(
        argv: Sequence[str], _timeout: float, _max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "x" * ((1 << 20) + 1), "")
    with pytest.raises(ValueError, match="exceeds"):
        java_capability._invoke(oversized, ("java", "-version"))  # pyright: ignore[reportPrivateUsage]


def test_java_capability_discovery_rejects_missing_and_ambiguous_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing_path(_name: str) -> None:
        return None

    monkeypatch.setattr(java_capability.shutil, "which", missing_path)
    unavailable = java_capability.discover_java_jfr_installation()
    assert unavailable.availability == "unavailable"
    assert "No java" in unavailable.limitations[0]

    odd = tmp_path / "tools/java"
    odd.parent.mkdir()
    odd.write_bytes(b"java")
    def odd_path(_name: str) -> str:
        return str(odd)

    monkeypatch.setattr(java_capability.shutil, "which", odd_path)
    ambiguous = java_capability.discover_java_jfr_installation()
    assert ambiguous.availability == "unavailable"
    assert "fixed JDK root" in ambiguous.limitations[0]

    def unresolved_path(_name: str) -> str:
        return str(tmp_path / "missing")

    monkeypatch.setattr(java_capability.shutil, "which", unresolved_path)
    missing = java_capability.discover_java_jfr_installation()
    assert missing.availability == "unavailable"
    assert "cannot be resolved" in missing.limitations[0]


def test_java_capability_private_openers_reject_unsafe_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "jdk"
    root.mkdir(mode=0o755)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="relative name"):
            java_capability._open_safe_directory(  # pyright: ignore[reportPrivateUsage]
                root / "bad", (os.geteuid(),), label="JDK bin", parent_fd=root_fd
            )
        release = root / "release"
        release.write_bytes(b"")
        release.chmod(0o644)
        with pytest.raises(ValueError, match="payload identity is unsafe"):
            java_capability._open_safe_payload_file(  # pyright: ignore[reportPrivateUsage]
                root_fd,
                "release",
                release,
                (os.geteuid(),),
                max_bytes=1024,
            )
        release.write_bytes(b"release")
        def present_capability(_target: int, _name: str) -> bytes:
            return b"capability"

        monkeypatch.setattr(java_capability.os, "getxattr", present_capability)
        with pytest.raises(ValueError, match="capabilities"):
            java_capability._open_safe_payload_file(  # pyright: ignore[reportPrivateUsage]
                root_fd,
                "release",
                release,
                (os.geteuid(),),
                max_bytes=1024,
            )
        def failed_capability(_target: int, _name: str) -> bytes:
            raise OSError(errno.EIO, "failed")

        monkeypatch.setattr(java_capability.os, "getxattr", failed_capability)
        with pytest.raises(OSError):
            java_capability._open_safe_payload_file(  # pyright: ignore[reportPrivateUsage]
                root_fd,
                "release",
                release,
                (os.geteuid(),),
                max_bytes=1024,
            )
    finally:
        os.close(root_fd)


def test_java_capability_tool_and_native_library_openers_reject_unsafe_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "jdk"
    bin_path = root / "bin"
    lib_path = root / "lib"
    bin_path.mkdir(parents=True, mode=0o755)
    lib_path.mkdir(mode=0o755)
    java_path = bin_path / "java"
    java_path.write_bytes(b"java")
    java_path.chmod(0o644)
    bin_fd = os.open(bin_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="tool identity is unsafe"):
            java_capability._open_safe_tool(  # pyright: ignore[reportPrivateUsage]
                bin_fd, "java", java_path, (os.geteuid(),)
            )
        java_path.chmod(0o755)
        def present_capability(_target: int, _name: str) -> bytes:
            return b"capability"

        monkeypatch.setattr(java_capability.os, "getxattr", present_capability)
        with pytest.raises(ValueError, match="capabilities"):
            java_capability._open_safe_tool(  # pyright: ignore[reportPrivateUsage]
                bin_fd, "java", java_path, (os.geteuid(),)
            )
    finally:
        os.close(bin_fd)

    library = lib_path / "libjli.so"
    library.write_bytes(b"")
    library.chmod(0o644)
    descriptor = os.open(library, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="native library identity is unsafe"):
            java_capability._native_library_identity(  # pyright: ignore[reportPrivateUsage]
                descriptor,
                relative_path="libjli.so",
                named_path=library,
                resolved_path=library,
                source_kind="regular",
                link_target_sha256=None,
                link_metadata=None,
                trusted=(os.geteuid(),),
            )
    finally:
        os.close(descriptor)


def _native_managed_target(**updates: object) -> NativeManagedPthreadTarget:
    values: dict[str, object] = {
        "container_target_id": "container-target-" + "1" * 20,
        "container_run_id": "container-run-" + "2" * 20,
        "target_identity_sha256": _sha("3"),
        "executable_path": "/workspace/workload",
        "executable_sha256": _sha("4"),
        "architecture": "amd64",
        "libc_family": "glibc",
        "glibc_version": "2.41",
        "dynamically_linked": True,
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
    }
    values.update(updates)
    return NativeManagedPthreadTarget(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"container_target_id": "bad"}, "ContainerTarget"),
        ({"container_run_id": "bad"}, "ContainerRun"),
        ({"target_identity_sha256": "bad"}, "digest"),
        ({"executable_path": "relative"}, "normalized"),
        ({"executable_path": "/workspace/../escape"}, "normalized"),
        ({"architecture": "arm64"}, "architecture"),
        ({"libc_family": "uclibc"}, "libc family"),
        ({"dynamically_linked": 1}, "dynamic-link state"),
        ({"glibc_version": "bad"}, "glibc version"),
        ({"glibc_version": None}, "bind its runtime"),
        ({"interpreter": "relative"}, "loader path"),
    ],
)
def test_native_managed_target_rejects_unbound_identity(
    updates: dict[str, object], message: str
) -> None:
    with pytest.raises(PerfLensError, match=message):
        _native_managed_target(**updates)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"path": Path("relative")}, "absolute"),
        ({"sha256": "bad"}, "digest"),
        ({"owner_uid": True}, "owner UID"),
        ({"mode": 0o755}, "0644"),
    ],
)
def test_native_probe_policy_rejects_untrusted_inputs(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "path": tmp_path / "probe.so",
        "sha256": _sha(),
        "owner_uid": 0,
        "mode": 0o644,
    }
    values.update(updates)
    with pytest.raises(PerfLensError, match=message):
        NativePthreadProbePolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"semantics": "sampled"}, "semantics"),
        ({"duration_seconds": 0}, "duration"),
        ({"duration_seconds": True}, "duration"),
        ({"semantics": "exact", "threshold_ns": 1}, "cannot set a threshold"),
        (
            {"semantics": "exact", "threshold_ns": None, "duration_seconds": 4},
            "exceeds three seconds",
        ),
        ({"threshold_ns": 0}, "bounded threshold"),
        ({"threshold_ns": True}, "bounded threshold"),
        ({"max_events": 0}, "event limit"),
        ({"max_events": True}, "event limit"),
        ({"arguments": ("bad\0arg",)}, "argument is invalid"),
        ({"arguments": ("x" * 4097,)}, "exceeds its bound"),
        ({"arguments": tuple("x" for _ in range(257))}, "too many arguments"),
    ],
)
def test_native_launch_request_rejects_unbounded_inputs(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(PerfLensError, match=message):
        NativeLaunchRequest(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("arguments", "duration", "message"),
    [
        ((), 0, "30 second"),
        ((), 31, "30 second"),
        (("bad\0arg",), 1, "safe bound"),
        (tuple("x" for _ in range(129)), 1, "safe bound"),
        (("x" * ((32 << 10) + 1),), 1, "safe bound"),
    ],
)
def test_go_launch_request_rejects_unbounded_inputs(
    arguments: tuple[str, ...], duration: int, message: str
) -> None:
    with pytest.raises(PerfLensError, match=message):
        GoPprofLaunchRequest(arguments=arguments, duration_seconds=duration)


def _go_tool(path: Path) -> GoToolIdentity:
    path.write_bytes(b"go tool")
    path.chmod(0o755)
    value = path.stat()
    return GoToolIdentity(
        path=path,
        version="1.24",
        minor_version="1.24",
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        mode=0o755,
        links=value.st_nlink,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
    )


def test_go_target_inspection_rejects_scope_uid_mode_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    tool = _go_tool(tmp_path / "go")
    target = project / "target"
    target.write_bytes(b"binary")
    target.chmod(0o755)
    def go_124(_tool: GoToolIdentity, _fd: int) -> str:
        return "1.24"

    monkeypatch.setattr(go, "_go_binary_version", go_124)

    with pytest.raises(PerfLensError, match="UID override"):
        go.inspect_go_target(project, target, go_tool=tool, invoking_uid=os.geteuid() + 1)
    alias = project / "alias"
    alias.symlink_to(target.name)
    with pytest.raises(PerfLensError, match="symlink"):
        go.inspect_go_target(project, alias, go_tool=tool)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    outside.chmod(0o755)
    with pytest.raises(PerfLensError, match="outside"):
        go.inspect_go_target(project, outside, go_tool=tool)
    target.chmod(0o777)
    with pytest.raises(PerfLensError, match="unsafe"):
        go.inspect_go_target(project, target, go_tool=tool)
    target.chmod(0o755)
    def go_123(_tool: GoToolIdentity, _fd: int) -> str:
        return "1.23"

    monkeypatch.setattr(go, "_go_binary_version", go_123)
    with pytest.raises(PerfLensError, match="reviewed"):
        go.inspect_go_target(project, target, go_tool=tool)


def test_go_pinned_target_rejects_descriptor_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _go_tool(tmp_path / "go")
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(PerfLensError, match="executable regular file"):
            go.inspect_pinned_go_executable_version(tool, read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)

    target = tmp_path / "target"
    target.write_bytes(b"binary")
    target.chmod(0o755)
    descriptor = os.open(target, os.O_RDONLY)
    def go_123(_tool: GoToolIdentity, _fd: int) -> str:
        return "1.23"

    monkeypatch.setattr(go, "_go_binary_version", go_123)
    try:
        with pytest.raises(PerfLensError, match="reviewed"):
            go.inspect_pinned_go_executable_version(tool, descriptor)
    finally:
        os.close(descriptor)


def _raw_result(root: Path, raw: Path) -> GoPprofRawResult:
    value = raw.stat()
    return GoPprofRawResult(
        private_root=root,
        raw_path=raw,
        raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
        raw_size=value.st_size,
        raw_device=value.st_dev,
        raw_inode=value.st_ino,
        profile_kind="mutex",
        accounted_active_seconds=1,
    )


def test_go_private_profile_rejects_cross_root_tamper_and_unsafe_mode(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    raw = root / "raw.txt"
    raw.write_bytes(b"profile")
    raw.chmod(0o600)
    result = _raw_result(root, raw)

    with pytest.raises(PerfLensError, match="different private root"):
        go.open_go_pprof_raw(replace(result, private_root=tmp_path / "foreign"))
    raw.write_bytes(b"changed")
    with pytest.raises(PerfLensError, match="captured identity"):
        go.open_go_pprof_raw(result)
    refreshed = _raw_result(root, raw)
    raw.chmod(0o644)
    with pytest.raises(PerfLensError, match="identity or size"):
        go.open_go_pprof_raw(refreshed)


def test_cpython_installation_and_file_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = tmp_path / "python"
    runtime_home = tmp_path / "runtime-home"
    bootstrap = tmp_path / "bootstrap.py"
    runtime_home.mkdir(mode=0o755)
    interpreter.write_bytes(b"python")
    bootstrap.write_bytes(b"bootstrap")
    interpreter.chmod(0o755)
    bootstrap.chmod(0o644)
    trusted = (os.geteuid(),)
    installation = cpython.inspect_cpython_installation(
        interpreter_path=interpreter,
        runtime_home_path=runtime_home,
        bootstrap_path=bootstrap,
        trusted_owner_uids=trusted,
    )
    assert installation.availability == "available"
    assert installation.interpreter is not None
    assert installation.runtime_home is not None
    assert installation.bootstrap is not None
    policy = cpython.CpythonLaunchPolicy(
        installation.interpreter,
        installation.runtime_home,
        installation.bootstrap,
        installation.runtime_version or "",
        bool(installation.free_threaded),
        installation.metadata_sha256 or "",
    )
    cpython.assert_cpython_launch_policy_current(policy)
    bootstrap.write_bytes(b"replacement")
    with pytest.raises(PerfLensError, match="changed after capability inspection"):
        cpython.assert_cpython_launch_policy_current(policy)

    monkeypatch.setattr(cpython.sys, "version_info", (3, 11, 0))
    unsupported = cpython.inspect_cpython_installation(
        interpreter_path=interpreter,
        runtime_home_path=runtime_home,
        bootstrap_path=bootstrap,
        trusted_owner_uids=trusted,
    )
    assert unsupported.availability == "unavailable"


def test_cpython_private_file_inspection_rejects_paths_modes_and_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(PerfLensError, match="absolute"):
        cpython._inspect_file(  # pyright: ignore[reportPrivateUsage]
            Path("relative"), executable=False, maximum_size=10, trusted_owner_uids=(os.geteuid(),)
        )
    target = tmp_path / "target"
    target.write_bytes(b"content")
    target.chmod(0o644)
    alias = tmp_path / "alias"
    alias.symlink_to(target.name)
    with pytest.raises(PerfLensError, match="absolute non-symlink"):
        cpython._inspect_file(  # pyright: ignore[reportPrivateUsage]
            alias, executable=False, maximum_size=10, trusted_owner_uids=(os.geteuid(),)
        )
    target.chmod(0o666)
    with pytest.raises(PerfLensError, match="unsafe"):
        cpython._inspect_file(  # pyright: ignore[reportPrivateUsage]
            target, executable=False, maximum_size=10, trusted_owner_uids=(os.geteuid(),)
        )
    target.chmod(0o644)
    def present_capability(_target: int, _name: str) -> bytes:
        return b"capability"

    monkeypatch.setattr(cpython.os, "getxattr", present_capability)
    with pytest.raises(PerfLensError, match="file capabilities"):
        cpython._inspect_file(  # pyright: ignore[reportPrivateUsage]
            target, executable=False, maximum_size=10, trusted_owner_uids=(os.geteuid(),)
        )
    def failed_capability(_target: int, _name: str) -> bytes:
        raise OSError(errno.EIO, "failed")

    monkeypatch.setattr(cpython.os, "getxattr", failed_capability)
    with pytest.raises(PerfLensError, match="cannot be checked"):
        cpython._inspect_file(  # pyright: ignore[reportPrivateUsage]
            target, executable=False, maximum_size=10, trusted_owner_uids=(os.geteuid(),)
        )


def test_native_and_go_capability_xattr_failures_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"content")
    descriptor = os.open(target, os.O_RDONLY)
    try:
        def failed_capability(_target: int, _name: str) -> bytes:
            raise OSError(errno.EIO, "failed")

        monkeypatch.setattr(native.os, "getxattr", failed_capability)
        with pytest.raises(PerfLensError, match="cannot be checked"):
            native._reject_file_capabilities(  # pyright: ignore[reportPrivateUsage]
                descriptor, "Native target"
            )
        def present_capability(_target: int, _name: str) -> bytes:
            return b"capability"

        monkeypatch.setattr(native.os, "getxattr", present_capability)
        with pytest.raises(PerfLensError, match="file capabilities"):
            native._reject_file_capabilities(  # pyright: ignore[reportPrivateUsage]
                descriptor, "Native target"
            )
        monkeypatch.setattr(go.os, "getxattr", failed_capability)
        with pytest.raises(PerfLensError, match="could not be inspected"):
            go._reject_file_capabilities(descriptor, "Go target")  # pyright: ignore[reportPrivateUsage]
        monkeypatch.setattr(go.os, "getxattr", present_capability)
        with pytest.raises(PerfLensError, match="file capabilities"):
            go._reject_file_capabilities(descriptor, "Go target")  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)


def test_native_private_directory_and_argument_vector_gates(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError, match="absolute"):
        native._private_directory(  # pyright: ignore[reportPrivateUsage]
            Path("relative"), owner_uid=os.geteuid(), expected_mode=None, label="root"
        )
    missing = tmp_path / "missing"
    with pytest.raises(PerfLensError, match="cannot be resolved"):
        native._private_directory(  # pyright: ignore[reportPrivateUsage]
            missing, owner_uid=os.geteuid(), expected_mode=None, label="root"
        )
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    identity = native._inspect_directory_identity(  # pyright: ignore[reportPrivateUsage]
        directory,
        owner_uid=os.geteuid(),
        expected_mode=0o700,
        label="root",
    )
    descriptor = native._open_directory_identity_fd(identity)  # pyright: ignore[reportPrivateUsage]
    os.close(descriptor)
    directory.chmod(0o755)
    with pytest.raises(PerfLensError, match="identity changed"):
        native._open_directory_identity_fd(identity)  # pyright: ignore[reportPrivateUsage]

    arguments = tuple("x" * 4096 for _ in range(17))
    with pytest.raises(PerfLensError, match="vector exceeds"):
        native._validated_arguments(arguments)  # pyright: ignore[reportPrivateUsage]


def test_native_stream_footer_and_private_stream_validation(tmp_path: Path) -> None:
    assert native._strict_footer(b"not terminated", expected_pid=42) is None  # pyright: ignore[reportPrivateUsage]
    assert native._strict_footer(b"\n", expected_pid=42) is None  # pyright: ignore[reportPrivateUsage]
    footer = (
        b'{"schema_version":"1.0","record_type":"probe_footer",'
        b'"protocol":"native_pthread_probe","pid":42,"sequence":1,'
        b'"declared_event_count":3,"lost_event_count":1,"truncated":true}\n'
    )
    stream = tmp_path / "stream.ndjson"
    stream.write_bytes(footer)
    stream.chmod(0o600)
    digest, size, parsed = native._inspect_private_stream(  # pyright: ignore[reportPrivateUsage]
        stream,
        owner_uid=os.geteuid(),
        expected_pid=42,
    )
    assert digest == hashlib.sha256(footer).hexdigest()
    assert size == len(footer)
    assert parsed == (3, 1, True)
    stream.chmod(0o644)
    with pytest.raises(PerfLensError, match="identity or size"):
        native._inspect_private_stream(  # pyright: ignore[reportPrivateUsage]
            stream,
            owner_uid=os.geteuid(),
            expected_pid=42,
        )


def test_native_missing_probe_discovery_and_glibc_validation(tmp_path: Path) -> None:
    discovery = native.discover_native_pthread_probe_policy(
        tmp_path / "missing-probe.so",
        expected_owner_uid=os.geteuid(),
    )
    assert discovery.availability == "unavailable"
    assert discovery.policy is None
    with pytest.raises(PerfLensError, match="malformed"):
        native._version_tuple("not-a-version")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="malformed"):
        native._version_tuple("2")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="supported"):
        native._runtime_glibc_version("2.40")  # pyright: ignore[reportPrivateUsage]


def test_go_private_directory_open_and_cleanup_gates(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    identity = go._directory(root, os.geteuid(), 0o700)  # pyright: ignore[reportPrivateUsage]
    descriptor = go._open_directory(identity)  # pyright: ignore[reportPrivateUsage]
    os.close(descriptor)
    root.chmod(0o777)
    with pytest.raises(PerfLensError, match="identity changed"):
        go._open_directory(identity)  # pyright: ignore[reportPrivateUsage]
    root.chmod(0o700)
    identity = go._directory(root, os.geteuid(), 0o700)  # pyright: ignore[reportPrivateUsage]
    observed = identity[1]
    forged = SimpleNamespace(
        st_dev=observed.st_dev + 1,
        st_ino=observed.st_ino,
        st_uid=observed.st_uid,
        st_mode=observed.st_mode,
    )
    with pytest.raises(PerfLensError, match="identity changed"):
        go._open_directory((root, forged))  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    with pytest.raises(PerfLensError, match="identity count"):
        go._unlink_private(identity, ("one",), ())  # pyright: ignore[reportPrivateUsage]
    go._unlink_private(identity, ("missing",), ((1, 2),))  # pyright: ignore[reportPrivateUsage]
    owned = root / "owned"
    owned.write_bytes(b"profile")
    value = owned.stat()
    with pytest.raises(PerfLensError, match="identity mismatch"):
        go._unlink_private(identity, ("owned",), ((value.st_dev, value.st_ino + 1),))  # pyright: ignore[reportPrivateUsage]
    go._unlink_private(identity, ("owned",), ((value.st_dev, value.st_ino),))  # pyright: ignore[reportPrivateUsage]
    assert not owned.exists()


def test_go_verified_private_cleanup_is_append_only_and_identity_bound(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    identity = go._directory(root, os.geteuid(), 0o700)  # pyright: ignore[reportPrivateUsage]
    missing = root / "missing"
    go._unlink_verified_private(identity, missing, (1, 2, _sha(), 3))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PerfLensError, match="outside"):
        go._unlink_verified_private(  # pyright: ignore[reportPrivateUsage]
            identity,
            tmp_path / "foreign",
            (1, 2, _sha(), 3),
        )
    profile = root / "profile"
    profile.write_bytes(b"profile")
    profile.chmod(0o600)
    value = profile.stat()
    expected = (
        value.st_dev,
        value.st_ino,
        hashlib.sha256(profile.read_bytes()).hexdigest(),
        value.st_size,
    )
    with pytest.raises(PerfLensError, match="identity mismatch"):
        go._unlink_verified_private(  # pyright: ignore[reportPrivateUsage]
            identity,
            profile,
            (value.st_dev, value.st_ino, _sha("f"), value.st_size),
        )
    assert profile.exists()
    go._unlink_verified_private(identity, profile, expected)  # pyright: ignore[reportPrivateUsage]
    assert not profile.exists()
