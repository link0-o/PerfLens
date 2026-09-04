from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from perflens.runtime_locks import java_jfr_capability as capability_module
from perflens.runtime_locks.java_jfr_capability import (
    JavaJfrRunner,
    inspect_java_jfr_installation,
    parse_java_jfr_metadata,
)

PROFILE_ROOT = Path(__file__).parents[2] / "src/perflens/runtime_locks/jfr"
METADATA = """
@Name("jdk.DataLoss")
class DataLoss extends jdk.jfr.Event {
  long startTime;
  long amount;
  long total;
}
@Name("jdk.JVMInformation")
class JVMInformation extends jdk.jfr.Event {
  long startTime;
  String jvmName;
  String jvmVersion;
  String jvmArguments;
  String jvmFlags;
  String javaArguments;
  long jvmStartTime;
  long pid;
}
@Name("jdk.JavaMonitorEnter")
class JavaMonitorEnter extends jdk.jfr.Event {
  long startTime;
  long duration;
  Thread eventThread;
  StackTrace stackTrace;
  Class monitorClass;
  Thread previousOwner;
  long address;
}
@Name("jdk.JavaMonitorWait")
class JavaMonitorWait extends jdk.jfr.Event {
  long startTime;
  long duration;
  Thread eventThread;
  StackTrace stackTrace;
  Class monitorClass;
  Thread notifier;
  long timeout;
  boolean timedOut;
  long address;
}
@Name("jdk.ThreadPark")
class ThreadPark extends jdk.jfr.Event {
  long startTime;
  long duration;
  Thread eventThread;
  StackTrace stackTrace;
  Class parkedClass;
  long timeout;
  long until;
  long address;
}
"""


def _fake_jdk(tmp_path: Path) -> Path:
    root = tmp_path / "jdk"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    for name in ("java", "jfr"):
        tool = root / "bin" / name
        tool.write_bytes(b"fake trusted executable")
        tool.chmod(0o755)
    (root / "release").write_text('JAVA_VERSION="25.0.1"\n', encoding="utf-8")
    (root / "lib/modules").write_bytes(b"fake-jdk-modules")
    (root / "lib/server").mkdir()
    (root / "lib/libjli.so").write_bytes(b"fake-jli")
    (root / "lib/libjava.so").write_bytes(b"fake-java-native")
    (root / "lib/server/libjvm.so").write_bytes(b"fake-jvm")
    (root / "release").chmod(0o644)
    (root / "lib/modules").chmod(0o644)
    for native in (root / "lib/libjli.so", root / "lib/libjava.so", root / "lib/server/libjvm.so"):
        native.chmod(0o644)
    (root / "lib/server").chmod(0o755)
    (root / "bin").chmod(0o755)
    (root / "lib").chmod(0o755)
    root.chmod(0o755)
    return root


def _executable_jdk(tmp_path: Path, *, oversized_jfr: bool = False) -> Path:
    root = tmp_path / "jdk-executable"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    java = root / "bin/java"
    java.write_text(
        "#!/usr/bin/python3\n"
        "print('openjdk version \\\"25.0.4.1\\\"')\n"
        "print('OpenJDK Runtime Environment (build 25.0.4.1+1)')\n",
        encoding="utf-8",
    )
    metadata_expression = repr(METADATA)
    jfr = root / "bin/jfr"
    jfr.write_text(
        "#!/usr/bin/python3\n"
        "import sys\n"
        "if sys.argv[1] == 'version':\n"
        + (
            "    sys.stdout.write('x' * ((1 << 20) + 1))\n"
            if oversized_jfr
            else "    print('25.0.4.1')\n"
        )
        + "else:\n"
        f"    sys.stdout.write({metadata_expression})\n",
        encoding="utf-8",
    )
    java.chmod(0o755)
    jfr.chmod(0o755)
    (root / "release").write_text('JAVA_VERSION="25.0.4.1"\n', encoding="utf-8")
    (root / "lib/modules").write_bytes(b"fake-jdk-modules")
    (root / "lib/server").mkdir()
    (root / "lib/libjli.so").write_bytes(b"fake-jli")
    (root / "lib/libjava.so").write_bytes(b"fake-java-native")
    (root / "lib/server/libjvm.so").write_bytes(b"fake-jvm")
    (root / "release").chmod(0o644)
    (root / "lib/modules").chmod(0o644)
    for native in (root / "lib/libjli.so", root / "lib/libjava.so", root / "lib/server/libjvm.so"):
        native.chmod(0o644)
    (root / "lib/server").chmod(0o755)
    (root / "bin").chmod(0o755)
    (root / "lib").chmod(0o755)
    root.chmod(0o755)
    return root


def _runner(version: str = "25.0.4.1") -> JavaJfrRunner:
    def run(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        del timeout, max_bytes
        if argv[-1] == "-version":
            return subprocess.CompletedProcess(
                argv,
                0,
                "",
                f'openjdk version "{version}"\nOpenJDK Runtime Environment (build {version}+1)\n',
            )
        if argv[-1] == "version":
            return subprocess.CompletedProcess(argv, 0, f"{version}\n", "")
        return subprocess.CompletedProcess(argv, 0, METADATA, "")

    return run


@pytest.mark.parametrize("major", [17, 21, 25])
def test_java_jfr_capability_supports_reviewed_jdks(tmp_path: Path, major: int) -> None:
    root = _fake_jdk(tmp_path)
    version = f"{major}.0.1"

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=_runner(version),
    )

    assert result.availability == "available"
    assert result.jdk_major == major
    assert result.measurement_semantics == ("thresholded",)
    assert {p.profile_id for p in result.profiles} == {"balanced", "deep"}
    assert result.event_surface is not None and result.event_surface.data_loss_disclosed
    assert result.runtime_payload is not None
    assert len(result.runtime_payload.identity_sha256) == 64
    assert tuple(item.relative_path for item in result.runtime_payload.native_libraries) == (
        "libjava.so",
        "libjli.so",
        "server/libjvm.so",
    )
    assert result.runtime_payload.native_library_bytes == sum(
        item.size for item in result.runtime_payload.native_libraries
    )
    assert len(result.runtime_payload.native_library_manifest_sha256) == 64
    assert result.active_launch_supported is True
    assert result.live_attach_supported is False


def test_java_jfr_capability_is_unavailable_for_wheel_only() -> None:
    result = inspect_java_jfr_installation(None)

    assert result.availability == "unavailable"
    assert result.active_launch_supported is False
    assert "import remains available" in result.limitations[0]


def test_java_jfr_capability_rejects_version_mismatch(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)

    def mismatch(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        if argv[-1] == "version":
            return subprocess.CompletedProcess(argv, 0, "21.0.1\n", "")
        return _runner("25.0.1")(argv, timeout, max_bytes)

    result = inspect_java_jfr_installation(
        root, profile_root=PROFILE_ROOT, trusted_owner_uids=(os.getuid(),), runner=mismatch
    )
    assert result.availability == "unavailable"
    assert "same JDK build" in result.limitations[0]


def test_java_jfr_capability_rejects_writable_tool(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)
    (root / "bin/jfr").chmod(0o777)

    result = inspect_java_jfr_installation(
        root, profile_root=PROFILE_ROOT, trusted_owner_uids=(os.getuid(),), runner=_runner()
    )
    assert result.availability == "unavailable"
    assert "identity is unsafe" in result.limitations[0]


def test_java_jfr_capability_rejects_writable_bin_directory(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)
    (root / "bin").chmod(0o775)

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=_runner(),
    )

    assert result.availability == "unavailable"
    assert "JDK bin directory identity is unsafe" in result.limitations[0]


def test_java_jfr_capability_rejects_symlinked_tool(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)
    (root / "bin/jfr").unlink()
    (root / "bin/jfr").symlink_to("java")

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=_runner(),
    )

    assert result.availability == "unavailable"
    assert "capability check failed" in result.limitations[0]


def test_java_jfr_default_discovery_executes_open_verified_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _executable_jdk(tmp_path)
    real_popen = subprocess.Popen
    executables: list[str] = []

    def observe_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        executables.append(str(kwargs.get("executable", "")))
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", observe_popen)
    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
    )

    assert result.availability == "available"
    assert len(executables) == 3
    assert all(value.startswith("/proc/self/fd/") for value in executables)


def test_java_jfr_default_discovery_kills_oversized_output(tmp_path: Path) -> None:
    root = _executable_jdk(tmp_path, oversized_jfr=True)

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
    )

    assert result.availability == "unavailable"
    assert "output exceeds its bound" in result.limitations[0]


def test_java_jfr_capability_rejects_tool_path_replacement(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)
    delegate = _runner()
    replaced = False

    def replace_after_java(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal replaced
        result = delegate(argv, timeout, max_bytes)
        if argv[-1] == "-version" and not replaced:
            replaced = True
            replacement = root / "bin/java.new"
            replacement.write_bytes(b"different trusted executable")
            replacement.chmod(0o755)
            replacement.replace(root / "bin/java")
        return result

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=replace_after_java,
    )

    assert result.availability == "unavailable"
    assert "changed during discovery" in result.limitations[0]


def test_java_jfr_capability_rejects_bin_directory_replacement(tmp_path: Path) -> None:
    root = _fake_jdk(tmp_path)
    delegate = _runner()
    replaced = False

    def replace_bin_after_java(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal replaced
        result = delegate(argv, timeout, max_bytes)
        if argv[-1] == "-version" and not replaced:
            replaced = True
            (root / "bin").rename(root / "bin.old")
            (root / "bin").mkdir()
            (root / "bin").chmod(0o755)
        return result

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=replace_bin_after_java,
    )

    assert result.availability == "unavailable"
    assert "changed during discovery" in result.limitations[0]


@pytest.mark.parametrize("relative_path", ["release", "lib/modules"])
def test_java_jfr_capability_rejects_runtime_payload_replacement(
    tmp_path: Path,
    relative_path: str,
) -> None:
    root = _fake_jdk(tmp_path)
    delegate = _runner()
    replaced = False

    def replace_payload_after_java(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal replaced
        result = delegate(argv, timeout, max_bytes)
        if argv[-1] == "-version" and not replaced:
            replaced = True
            target = root / relative_path
            replacement = target.with_name(target.name + ".new")
            replacement.write_bytes(b"replacement-runtime-payload")
            replacement.chmod(0o644)
            replacement.replace(target)
        return result

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=replace_payload_after_java,
    )

    assert result.availability == "unavailable"
    assert "changed during discovery" in result.limitations[0]


@pytest.mark.parametrize(
    "relative_path",
    ["lib/libjli.so", "lib/server/libjvm.so"],
)
def test_java_jfr_capability_rejects_native_payload_replacement(
    tmp_path: Path,
    relative_path: str,
) -> None:
    root = _fake_jdk(tmp_path)
    delegate = _runner()
    replaced = False

    def replace_native_after_java(
        argv: Sequence[str], timeout: float, max_bytes: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal replaced
        result = delegate(argv, timeout, max_bytes)
        if argv[-1] == "-version" and not replaced:
            replaced = True
            target = root / relative_path
            replacement = target.with_suffix(target.suffix + ".new")
            replacement.write_bytes(b"replacement-native-library")
            replacement.chmod(0o644)
            replacement.replace(target)
        return result

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=replace_native_after_java,
    )

    assert result.availability == "unavailable"
    assert "changed during discovery" in result.limitations[0]
    assert "changed during discovery" in result.limitations[0]


def test_java_jfr_capability_bounds_native_payload_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fake_jdk(tmp_path)
    monkeypatch.setattr(capability_module, "_MAX_NATIVE_LIBRARY_FILES", 2)

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=_runner(),
    )

    assert result.availability == "unavailable"
    assert "file-count bound" in result.limitations[0]


def test_java_jfr_capability_binds_safe_native_library_symlink(
    tmp_path: Path,
) -> None:
    root = _fake_jdk(tmp_path)
    target = root / "lib/libjava.so"
    alias = root / "lib/libjava-alias.so"
    alias.symlink_to(target.name)

    result = inspect_java_jfr_installation(
        root,
        profile_root=PROFILE_ROOT,
        trusted_owner_uids=(os.getuid(),),
        runner=_runner(),
    )

    assert result.availability == "available"
    assert result.runtime_payload is not None
    symbolic = next(
        item
        for item in result.runtime_payload.native_libraries
        if item.relative_path == "libjava-alias.so"
    )
    assert symbolic.source_kind == "symlink"
    assert symbolic.link_target_sha256 is not None
    assert symbolic.sha256 == next(
        item.sha256
        for item in result.runtime_payload.native_libraries
        if item.relative_path == "libjava.so"
    )


def test_java_jfr_metadata_rejects_missing_data_loss() -> None:
    start = METADATA.index('@Name("jdk.DataLoss")')
    end = METADATA.index('@Name("jdk.JavaMonitorEnter")')
    with pytest.raises(ValueError, match="missing a required event"):
        parse_java_jfr_metadata(METADATA[:start] + METADATA[end:])


@pytest.mark.skipif(
    not Path("/usr/lib/jvm/java-25-openjdk-amd64/bin/jfr").exists(),
    reason="local JDK 25 is not installed",
)
def test_local_jdk25_metadata_has_reviewed_surface() -> None:
    jfr = "/usr/lib/jvm/java-25-openjdk-amd64/bin/jfr"
    result = subprocess.run(  # noqa: S603
        [
            jfr,
            "metadata",
            "--events",
            "jdk.DataLoss,jdk.JVMInformation,jdk.JavaMonitorEnter,jdk.JavaMonitorWait,jdk.ThreadPark",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    surface = parse_java_jfr_metadata(result.stdout)
    assert surface.data_loss_disclosed is True
    assert len(surface.events) == 5


@pytest.mark.skipif(
    not Path("/usr/lib/jvm/java-21-openjdk-amd64/bin/jfr").exists(),
    reason="local JDK 21 is not installed",
)
def test_local_jdk21_metadata_has_reviewed_surface() -> None:
    jfr = "/usr/lib/jvm/java-21-openjdk-amd64/bin/jfr"
    result = subprocess.run(  # noqa: S603
        [
            jfr,
            "metadata",
            "--events",
            "jdk.DataLoss,jdk.JVMInformation,jdk.JavaMonitorEnter,jdk.JavaMonitorWait,jdk.ThreadPark",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    surface = parse_java_jfr_metadata(result.stdout)
    assert surface.data_loss_disclosed is True
    assert len(surface.events) == 5
