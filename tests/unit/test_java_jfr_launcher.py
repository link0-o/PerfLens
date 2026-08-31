from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import time
import zipfile
from pathlib import Path
from typing import cast

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import java_jfr_launcher as launcher_module
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrDirectoryPolicy,
    JavaJfrFileIdentity,
    JavaJfrFilePolicy,
    JavaJfrJsonRunnerReceipt,
    JavaJfrLauncher,
    JavaJfrLaunchFailure,
    JavaJfrLaunchPolicy,
    JavaJfrLaunchRequest,
    JavaJfrNativeLibraryPolicy,
    JavaJfrPayloadFilePolicy,
    JavaJfrRuntimePayloadPolicy,
    SubprocessJavaJfrJsonRunner,
    acquire_java_jfr_artifact_root_lease,
    cleanup_java_jfr_empty_private_roots,
    cleanup_java_jfr_launch_result,
    inspect_executable_jar,
    inventory_java_jfr_retained_evidence,
    java_jfr_arguments_sha256,
    open_java_jfr_private_file,
    release_java_jfr_artifact_root_lease,
)
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorDiscovery,
    RuntimeSupervisorReceipt,
    RuntimeSupervisorRequest,
)


@pytest.fixture(autouse=True)
def use_test_runtime_supervisor(
    monkeypatch: pytest.MonkeyPatch,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    monkeypatch.setattr(
        launcher_module,
        "discover_runtime_supervisor_policy",
        lambda: RuntimeSupervisorDiscovery(
            "available",
            runtime_supervisor_client.policy,
            (),
        ),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy(path: Path) -> JavaJfrFilePolicy:
    metadata = path.stat()
    return JavaJfrFilePolicy(
        path=path,
        sha256=_sha256(path),
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _directory_policy(path: Path) -> JavaJfrDirectoryPolicy:
    metadata = path.stat()
    return JavaJfrDirectoryPolicy(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _payload_file_policy(path: Path) -> JavaJfrPayloadFilePolicy:
    metadata = path.stat()
    return JavaJfrPayloadFilePolicy(
        path=path,
        sha256=_sha256(path),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _runtime_payload_policy(jdk_root: Path) -> JavaJfrRuntimePayloadPolicy:
    root = _directory_policy(jdk_root)
    bin_directory = _directory_policy(jdk_root / "bin")
    lib_directory = _directory_policy(jdk_root / "lib")
    release_file = _payload_file_policy(jdk_root / "release")
    modules_file = _payload_file_policy(jdk_root / "lib/modules")
    native_libraries = tuple(
        _native_library_policy(path, path.relative_to(jdk_root / "lib").as_posix())
        for path in sorted((jdk_root / "lib").rglob("*.so"))
    )
    native_material = ["perflens-java-jfr-native-library-manifest-v1"]
    for native in native_libraries:
        native_material.extend(
            (
                native.relative_path,
                native.source_kind,
                native.link_target_sha256 or "",
                native.sha256,
                str(native.size),
                str(native.owner_uid),
                str(native.mode),
            )
        )
    native_manifest_sha256 = hashlib.sha256("\0".join(native_material).encode()).hexdigest()
    native_library_bytes = sum(item.size for item in native_libraries)
    material = ["perflens-java-jfr-runtime-payload-v2"]
    for directory in (root, bin_directory, lib_directory):
        material.extend(
            (
                directory.path.name,
                str(directory.device),
                str(directory.inode),
                str(directory.owner_uid),
                str(directory.mode),
            )
        )
    for payload in (release_file, modules_file):
        material.extend(
            (
                payload.path.name,
                payload.sha256,
                str(payload.size),
                str(payload.owner_uid),
                str(payload.mode),
            )
        )
    material.extend(
        (
            native_manifest_sha256,
            str(len(native_libraries)),
            str(native_library_bytes),
        )
    )
    return JavaJfrRuntimePayloadPolicy(
        jdk_root=root,
        bin_directory=bin_directory,
        lib_directory=lib_directory,
        release_file=release_file,
        modules_file=modules_file,
        native_libraries=native_libraries,
        native_library_bytes=native_library_bytes,
        native_library_manifest_sha256=native_manifest_sha256,
        identity_sha256=hashlib.sha256("\0".join(material).encode()).hexdigest(),
    )


def _native_library_policy(path: Path, relative_path: str) -> JavaJfrNativeLibraryPolicy:
    link = path.lstat()
    source_kind = "symlink" if path.is_symlink() else "regular"
    resolved = path.resolve(strict=True)
    metadata = resolved.stat(follow_symlinks=False)
    link_target = os.readlink(path) if source_kind == "symlink" else None
    return JavaJfrNativeLibraryPolicy(
        relative_path=relative_path,
        named_path=path,
        resolved_path=resolved,
        source_kind=source_kind,
        link_target_sha256=(
            hashlib.sha256(os.fsencode(link_target)).hexdigest()
            if link_target is not None
            else None
        ),
        link_device=link.st_dev if source_kind == "symlink" else None,
        link_inode=link.st_ino if source_kind == "symlink" else None,
        link_owner_uid=link.st_uid if source_kind == "symlink" else None,
        link_mode=stat.S_IMODE(link.st_mode) if source_kind == "symlink" else None,
        link_links=link.st_nlink if source_kind == "symlink" else None,
        link_size=link.st_size if source_kind == "symlink" else None,
        link_modified_ns=link.st_mtime_ns if source_kind == "symlink" else None,
        link_changed_ns=link.st_ctime_ns if source_kind == "symlink" else None,
        sha256=_sha256(resolved),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _fake_launch_policy(tmp_path: Path) -> JavaJfrLaunchPolicy:
    tools = tmp_path / "jdk" / "bin"
    tools.mkdir(parents=True)
    java = tools / "java"
    jfr = tools / "jfr"
    shutil.copyfile("/bin/true", java)
    shutil.copyfile("/bin/true", jfr)
    java.chmod(0o755)
    jfr.chmod(0o755)
    jfc = tmp_path / "fixed.jfc"
    jfc.write_text("fixed")
    jfc.chmod(0o644)
    jdk_root = tools.parent
    lib = jdk_root / "lib"
    lib.mkdir()
    (jdk_root / "release").write_bytes(b"fixed-release")
    (lib / "modules").write_bytes(b"fixed-modules")
    (lib / "server").mkdir()
    (lib / "libjli.so").write_bytes(b"fixed-jli")
    (lib / "server/libjvm.so").write_bytes(b"fixed-jvm")
    (jdk_root / "release").chmod(0o644)
    (lib / "modules").chmod(0o644)
    (lib / "libjli.so").chmod(0o644)
    (lib / "server/libjvm.so").chmod(0o644)
    (lib / "server").chmod(0o755)
    jdk_root.chmod(0o755)
    tools.chmod(0o755)
    lib.chmod(0o755)
    return JavaJfrLaunchPolicy(
        _policy(java),
        _policy(jfr),
        _policy(jfc),
        25,
        "balanced",
        _runtime_payload_policy(jdk_root),
    )


def test_json_runner_never_falls_back_when_fixed_supervisor_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        launcher_module,
        "discover_runtime_supervisor_policy",
        lambda: RuntimeSupervisorDiscovery(
            "unavailable",
            None,
            ("fixed supervisor missing",),
        ),
    )

    with pytest.raises(PerfLensError, match="fixed Runtime Lock supervisor is unavailable"):
        SubprocessJavaJfrJsonRunner()


class _JsonRunner:
    def __init__(self) -> None:
        self.recording_magic = b""

    def render_json(
        self,
        *,
        recording_directory_fd: int,
        recording_name: str,
        recording_fd: int,
        output_fd: int,
        jfr_tool: JavaJfrFileIdentity,
        jdk_major: int,
        max_output_bytes: int,
    ) -> JavaJfrJsonRunnerReceipt:
        assert max_output_bytes == 64 << 20
        assert recording_name.startswith("java-jfr-") and recording_name.endswith(".jfr")
        assert os.fstat(recording_directory_fd).st_ino > 0
        self.recording_magic = os.pread(recording_fd, 4, 0)
        os.write(output_fd, b'{"recording":{"events":[]}}')
        return JavaJfrJsonRunnerReceipt(jfr_tool.sha256, jdk_major)


class _FailingJsonRunner:
    def render_json(
        self,
        *,
        recording_directory_fd: int,
        recording_name: str,
        recording_fd: int,
        output_fd: int,
        jfr_tool: JavaJfrFileIdentity,
        jdk_major: int,
        max_output_bytes: int,
    ) -> JavaJfrJsonRunnerReceipt:
        del (
            recording_directory_fd,
            recording_name,
            recording_fd,
            output_fd,
            jfr_tool,
            jdk_major,
            max_output_bytes,
        )
        raise RuntimeError("converter failed")


class _SlowJsonRunner(_JsonRunner):
    def render_json(
        self,
        *,
        recording_directory_fd: int,
        recording_name: str,
        recording_fd: int,
        output_fd: int,
        jfr_tool: JavaJfrFileIdentity,
        jdk_major: int,
        max_output_bytes: int,
    ) -> JavaJfrJsonRunnerReceipt:
        time.sleep(0.3)
        return super().render_json(
            recording_directory_fd=recording_directory_fd,
            recording_name=recording_name,
            recording_fd=recording_fd,
            output_fd=output_fd,
            jfr_tool=jfr_tool,
            jdk_major=jdk_major,
            max_output_bytes=max_output_bytes,
        )


@pytest.fixture(scope="module")
def jdk_tools() -> tuple[Path, Path, Path, Path, Path]:
    java_name = shutil.which("java")
    javac_name = shutil.which("javac")
    jar_name = shutil.which("jar")
    jfr_name = shutil.which("jfr")
    if not all((java_name, javac_name, jar_name, jfr_name)):
        pytest.skip("A complete local JDK is required for the startup-JFR launcher test")
    assert java_name is not None
    assert javac_name is not None
    assert jar_name is not None
    assert jfr_name is not None
    java = Path(java_name).resolve()
    jdk_root = java.parent.parent
    jfc = jdk_root / "lib" / "jfr" / "default.jfc"
    if not jfc.is_file():
        pytest.skip("The local JDK has no default JFR profile")
    return java, Path(jfr_name).resolve(), Path(javac_name).resolve(), Path(jar_name).resolve(), jfc


@pytest.fixture()
def java_project(
    tmp_path: Path,
    jdk_tools: tuple[Path, Path, Path, Path, Path],
) -> dict[str, object]:
    java, jfr, javac, jar_tool, source_jfc = jdk_tools
    project = tmp_path / "project"
    output = tmp_path / "private"
    classes = project / "classes"
    project.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    classes.mkdir()
    source = project / "Workload.java"
    source.write_text(
        """
import java.nio.file.Files;
import java.nio.file.Path;
public final class Workload {
  public static void main(String[] args) throws Exception {
    if (args.length > 1 && args[1].equals("child")) {
      Process child = new ProcessBuilder("/bin/sleep", "30").start();
      Files.writeString(Path.of(args[2]), Long.toString(child.pid()));
    }
    Thread.sleep(Long.parseLong(args[0]));
  }
}
""".strip()
        + "\n"
    )
    subprocess.run(  # noqa: S603 - fixed local JDK fixture tool
        [str(javac), "-d", str(classes), str(source)],
        check=True,
    )
    target = project / "workload.jar"
    subprocess.run(  # noqa: S603 - fixed local JDK fixture tool
        [
            str(jar_tool),
            "--create",
            "--file",
            str(target),
            "--main-class",
            "Workload",
            "-C",
            str(classes),
            ".",
        ],
        check=True,
    )
    target.chmod(0o600)
    jfc = tmp_path / "profile.jfc"
    shutil.copyfile(source_jfc, jfc)
    jfc.chmod(0o644)
    runner = _JsonRunner()
    version_output = subprocess.check_output(  # noqa: S603 - fixed local JDK fixture tool
        [str(java), "-version"],
        stderr=subprocess.STDOUT,
    )
    major = int(version_output.split(b'"')[1].split(b".")[0])
    policy = JavaJfrLaunchPolicy(
        java_tool=_policy(java),
        jfr_tool=_policy(jfr),
        jfc_profile=_policy(jfc),
        jdk_major=major,
        profile="balanced",
        runtime_payload=_runtime_payload_policy(java.parent.parent),
    )
    return {
        "project": project,
        "output": output,
        "target": target,
        "runner": runner,
        "policy": policy,
    }


def test_launcher_runs_sealed_jar_with_fixed_jfr_and_private_outputs(
    java_project: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    project = java_project["project"]
    output = java_project["output"]
    target = java_project["target"]
    runner = java_project["runner"]
    policy = java_project["policy"]
    assert isinstance(project, Path)
    assert isinstance(output, Path)
    assert isinstance(target, Path)
    assert isinstance(runner, _JsonRunner)
    assert isinstance(policy, JavaJfrLaunchPolicy)
    captured: list[RuntimeSupervisorRequest] = []
    real_execute = runtime_supervisor_client.execute

    def recording_execute(request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
        captured.append(request)
        return real_execute(request)

    monkeypatch.setattr(runtime_supervisor_client, "execute", recording_execute)
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=runner,
        supervisor_client=runtime_supervisor_client,
    )
    identity = java_launcher.inspect_target(target)
    result = java_launcher.launch(
        target,
        JavaJfrLaunchRequest(arguments=("100",), duration_seconds=5),
        expected_target_identity_sha256=identity.identity_sha256,
        expected_arguments_sha256=java_jfr_arguments_sha256(("100",)),
    )

    assert len(captured) == 1
    supervisor_request = captured[0]
    assert supervisor_request.request.adapter == "java_jfr_workload"
    assert supervisor_request.arguments == ("100",)
    assert supervisor_request.expected_parent_pid == os.getpid()
    assert supervisor_request.expected_supervisor_sha256 == runtime_supervisor_client.policy.sha256
    assert runner.recording_magic == b"FLR\x00"
    assert result.exit_code == 0
    assert result.target_identity_sha256 == identity.identity_sha256
    assert result.runtime_payload_identity_sha256 == policy.runtime_payload.identity_sha256
    assert result.recording_path.stat().st_mode & 0o777 == 0o600
    assert result.json_path.stat().st_mode & 0o777 == 0o600
    assert result.quality_status == "partial"
    assert any("live attach" in limitation for limitation in result.limitations)
    assert any("same-UID ABA" in limitation for limitation in result.limitations)
    recording_fd = open_java_jfr_private_file(result, "recording")
    try:
        assert os.read(recording_fd, 4) == b"FLR\x00"
    finally:
        os.close(recording_fd)
    cleanup_java_jfr_launch_result(result)
    assert not result.private_directory_path.exists()


def test_launcher_times_out_and_cleans_same_session_child(java_project: dict[str, object]) -> None:
    project = java_project["project"]
    output = java_project["output"]
    target = java_project["target"]
    runner = java_project["runner"]
    policy = java_project["policy"]
    assert isinstance(project, Path)
    assert isinstance(output, Path)
    assert isinstance(target, Path)
    assert isinstance(runner, _JsonRunner)
    assert isinstance(policy, JavaJfrLaunchPolicy)
    pid_file = project / "child.pid"
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=runner,
    )
    identity = java_launcher.inspect_target(target)
    result = java_launcher.launch(
        target,
        JavaJfrLaunchRequest(
            arguments=("30000", "child", str(pid_file)),
            duration_seconds=1.5,
        ),
        expected_target_identity_sha256=identity.identity_sha256,
        expected_arguments_sha256=java_jfr_arguments_sha256(("30000", "child", str(pid_file))),
    )
    assert result.termination_reason == "duration_limit"
    child_pid = int(pid_file.read_text())
    for _ in range(100):
        if not Path(f"/proc/{child_pid}").exists():
            break
        time.sleep(0.01)
    assert not Path(f"/proc/{child_pid}").exists()


def test_fixed_same_jdk_json_runner_produces_bounded_json(
    java_project: dict[str, object],
) -> None:
    project = java_project["project"]
    output = java_project["output"]
    target = java_project["target"]
    policy = java_project["policy"]
    assert isinstance(project, Path)
    assert isinstance(output, Path)
    assert isinstance(target, Path)
    assert isinstance(policy, JavaJfrLaunchPolicy)
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=SubprocessJavaJfrJsonRunner(),
    )
    identity = java_launcher.inspect_target(target)
    result = java_launcher.launch(
        target,
        JavaJfrLaunchRequest(arguments=("100",), duration_seconds=5),
        expected_target_identity_sha256=identity.identity_sha256,
        expected_arguments_sha256=java_jfr_arguments_sha256(("100",)),
    )
    assert result.json_size <= 64 << 20
    assert result.json_path.read_bytes().lstrip().startswith(b"{")

    result.json_path.write_text("{}")
    with pytest.raises(PerfLensError, match="identity or digest changed"):
        cleanup_java_jfr_launch_result(result)
    assert result.private_directory_path.exists()


def test_fixed_runner_rejects_recording_mutation_during_conversion(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    recording = private / "java-jfr-0123456789abcdefabcd.jfr"
    output = private / "output.json"
    recording.write_bytes(b"FLR\x00fixed-recording")
    output.write_bytes(b"")
    recording.chmod(0o600)
    output.chmod(0o600)
    tool = tmp_path / "jfr"
    shutil.copyfile("/bin/true", tool)
    tool.chmod(0o755)
    identity = launcher_module._inspect_policy_file(  # pyright: ignore[reportPrivateUsage]
        _policy(tool),
        executable=True,
        max_bytes=1 << 20,
    )
    recording_fd = os.open(recording, os.O_RDONLY)
    output_fd = os.open(output, os.O_RDWR)
    directory_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY)

    class MutatingSupervisor:
        policy = runtime_supervisor_client.policy

        @staticmethod
        def execute(request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
            recording.write_bytes(b"FLR\x00changed-record")
            recording.chmod(0o600)
            adapter = request.request
            assert adapter.adapter == "java_jfr_print"
            os.write(adapter.output.descriptor, b'{"recording":{"events":[]}}')
            return RuntimeSupervisorReceipt(
                request_id=request.request_id,
                supervisor_version="0.4.0",
                supervisor_sha256=runtime_supervisor_client.policy.sha256,
                workload_pid=os.getpid(),
                workload_start_ticks=1,
                elapsed_monotonic_ns=1,
                accounted_active_seconds=1,
                exit_code=0,
                terminating_signal=None,
                termination_reason="exited",
                term_sent=False,
                kill_sent=False,
                observed_group_descendants=0,
                residual_group_descendants=0,
                cleanup_complete=True,
            )

    try:
        with pytest.raises(PerfLensError, match="identity changed during JSON conversion"):
            SubprocessJavaJfrJsonRunner(
                cast(RuntimeSupervisorClient, MutatingSupervisor())
            ).render_json(
                recording_directory_fd=directory_fd,
                recording_name=recording.name,
                recording_fd=recording_fd,
                output_fd=output_fd,
                jfr_tool=identity,
                jdk_major=25,
                max_output_bytes=64 << 20,
            )
    finally:
        os.close(directory_fd)
        os.close(recording_fd)
        os.close(output_fd)


def test_json_conversion_failure_retains_only_bounded_private_outputs(
    java_project: dict[str, object],
) -> None:
    project = java_project["project"]
    output = java_project["output"]
    target = java_project["target"]
    policy = java_project["policy"]
    assert isinstance(project, Path)
    assert isinstance(output, Path)
    assert isinstance(target, Path)
    assert isinstance(policy, JavaJfrLaunchPolicy)
    before = tuple(output.iterdir())
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_FailingJsonRunner(),
    )
    identity = java_launcher.inspect_target(target)
    with pytest.raises(JavaJfrLaunchFailure, match="diagnostics were retained") as raised:
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("50",), duration_seconds=5),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("50",)),
        )
    retained_result = raised.value.retained_evidence
    assert retained_result is not None
    retained = tuple(path for path in output.iterdir() if path not in before)
    assert len(retained) == 1
    assert retained[0].is_dir()
    files = tuple(retained[0].iterdir())
    assert {path.suffix for path in files} == {".jfr", ".json"}
    assert all(path.stat().st_size <= 64 << 20 for path in files)
    cleanup_java_jfr_launch_result(retained_result)
    assert tuple(output.iterdir()) == before


def test_workload_duration_excludes_slow_jfr_conversion(
    java_project: dict[str, object],
) -> None:
    project = cast(Path, java_project["project"])
    output = cast(Path, java_project["output"])
    target = cast(Path, java_project["target"])
    policy = cast(JavaJfrLaunchPolicy, java_project["policy"])
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_SlowJsonRunner(),
    )
    identity = java_launcher.inspect_target(target)

    started = time.monotonic()
    result = java_launcher.launch(
        target,
        JavaJfrLaunchRequest(arguments=("50",), duration_seconds=2),
        expected_target_identity_sha256=identity.identity_sha256,
        expected_arguments_sha256=java_jfr_arguments_sha256(("50",)),
    )

    elapsed = time.monotonic() - started
    assert elapsed - result.duration_seconds >= 0.25
    cleanup_java_jfr_launch_result(result)


def test_manifest_rejects_class_path_and_agent_directives(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    target = project / "unsafe.jar"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: Workload\nClass-Path: /tmp/evil.jar\n\n",
        )
        archive.writestr("Workload.class", b"not-used")
    target.chmod(0o600)
    with pytest.raises(PerfLensError, match="classpath, agents"):
        inspect_executable_jar(project, target)


def test_target_identity_and_argument_safety(java_project: dict[str, object]) -> None:
    project = java_project["project"]
    target = java_project["target"]
    assert isinstance(project, Path)
    assert isinstance(target, Path)
    identity = inspect_executable_jar(project, target)
    target.touch()
    changed = inspect_executable_jar(project, target)
    assert changed != identity
    assert changed.identity_sha256 == identity.identity_sha256
    with pytest.raises(PerfLensError, match="argument"):
        JavaJfrLaunchRequest(arguments=("bad\x00argument",))


def test_authorized_argument_binding_is_checked_before_launch(
    java_project: dict[str, object],
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    project = java_project["project"]
    output = java_project["output"]
    target = java_project["target"]
    runner = java_project["runner"]
    policy = java_project["policy"]
    assert isinstance(project, Path)
    assert isinstance(output, Path)
    assert isinstance(target, Path)
    assert isinstance(runner, _JsonRunner)
    assert isinstance(policy, JavaJfrLaunchPolicy)

    class ForbiddenSupervisor:
        policy = runtime_supervisor_client.policy

        @staticmethod
        def execute(_request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
            raise AssertionError("supervisor must not run for an argument-binding mismatch")

    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=runner,
        supervisor_client=cast(RuntimeSupervisorClient, ForbiddenSupervisor()),
    )
    identity = java_launcher.inspect_target(target)

    with pytest.raises(PerfLensError, match="arguments differ"):
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("100",)),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("200",)),
        )


def test_policy_tool_replacement_is_rejected_before_launch(
    tmp_path: Path,
    java_project: dict[str, object],
) -> None:
    project = java_project["project"]
    target = java_project["target"]
    assert isinstance(project, Path)
    assert isinstance(target, Path)
    output = tmp_path / "replacement-private"
    output.mkdir(mode=0o700)
    policy = _fake_launch_policy(tmp_path)
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_JsonRunner(),
    )
    identity = java_launcher.inspect_target(target)
    policy.java_tool.path.write_bytes(Path("/bin/false").read_bytes())
    policy.java_tool.path.chmod(0o755)
    with pytest.raises(PerfLensError, match="digest"):
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("10",)),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("10",)),
        )


def test_runtime_payload_replacement_is_rejected_before_launch(
    tmp_path: Path,
    java_project: dict[str, object],
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    project = cast(Path, java_project["project"])
    target = cast(Path, java_project["target"])
    output = tmp_path / "payload-replacement-private"
    output.mkdir(mode=0o700)
    policy = _fake_launch_policy(tmp_path)

    class ForbiddenSupervisor:
        policy = runtime_supervisor_client.policy

        @staticmethod
        def execute(_request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
            raise AssertionError("supervisor must not run after JDK payload replacement")

    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_JsonRunner(),
        supervisor_client=cast(RuntimeSupervisorClient, ForbiddenSupervisor()),
    )
    identity = java_launcher.inspect_target(target)
    policy.runtime_payload.modules_file.path.write_bytes(b"replacement-modules")
    policy.runtime_payload.modules_file.path.chmod(0o644)

    with pytest.raises(PerfLensError, match="runtime payload"):
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("10",)),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("10",)),
        )


def test_native_runtime_payload_replacement_is_rejected_before_launch(
    tmp_path: Path,
    java_project: dict[str, object],
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    project = cast(Path, java_project["project"])
    target = cast(Path, java_project["target"])
    output = tmp_path / "native-payload-replacement-private"
    output.mkdir(mode=0o700)
    policy = _fake_launch_policy(tmp_path)

    class ForbiddenSupervisor:
        policy = runtime_supervisor_client.policy

        @staticmethod
        def execute(_request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
            raise AssertionError("supervisor must not run after native payload replacement")

    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_JsonRunner(),
        supervisor_client=cast(RuntimeSupervisorClient, ForbiddenSupervisor()),
    )
    identity = java_launcher.inspect_target(target)
    native = policy.runtime_payload.native_libraries[0]
    native.named_path.write_bytes(b"replacement-native-library")
    native.named_path.chmod(0o644)

    with pytest.raises(PerfLensError, match="native runtime library"):
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("10",)),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("10",)),
        )


def test_runtime_payload_is_revalidated_after_json_conversion(
    java_project: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = cast(Path, java_project["project"])
    output = cast(Path, java_project["output"])
    target = cast(Path, java_project["target"])
    policy = cast(JavaJfrLaunchPolicy, java_project["policy"])
    java_launcher = JavaJfrLauncher(
        project_root=project,
        private_output_root=output,
        policy=policy,
        json_runner=_JsonRunner(),
    )
    identity = java_launcher.inspect_target(target)
    real_assert = launcher_module._assert_runtime_payload_current  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def fail_after_conversion(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise launcher_module._java_error(  # pyright: ignore[reportPrivateUsage]
                "Java JFR runtime payload identity changed after conversion"
            )
        real_assert(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        launcher_module,
        "_assert_runtime_payload_current",
        fail_after_conversion,
    )
    with pytest.raises(JavaJfrLaunchFailure, match="runtime payload") as raised:
        java_launcher.launch(
            target,
            JavaJfrLaunchRequest(arguments=("50",), duration_seconds=2),
            expected_target_identity_sha256=identity.identity_sha256,
            expected_arguments_sha256=java_jfr_arguments_sha256(("50",)),
        )
    assert calls == 2
    assert raised.value.retained_evidence is not None
    cleanup_java_jfr_launch_result(raised.value.retained_evidence)


def test_json_output_limit_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(descriptor, (64 << 20) + 1)
        with pytest.raises(PerfLensError, match="exceeds 64 MiB"):
            launcher_module._inspect_json_fd(descriptor)  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)


def test_java_jfr_artifact_root_lease_serializes_mcp_process_ownership(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    first = acquire_java_jfr_artifact_root_lease(artifact_root)
    try:
        with pytest.raises(PerfLensError, match="Another PerfLens Java JFR MCP process"):
            acquire_java_jfr_artifact_root_lease(artifact_root)
    finally:
        release_java_jfr_artifact_root_lease(first)

    replacement = acquire_java_jfr_artifact_root_lease(artifact_root)
    release_java_jfr_artifact_root_lease(replacement)
    release_java_jfr_artifact_root_lease(replacement)


def _retained_tree(
    artifact_root: Path,
    *,
    root_suffix: str = "aaaaaaaa",
    run_nonce: str = "0123456789abcdefabcd",
    json_payload: bytes = b'{"recording":{"events":[]}}',
) -> tuple[Path, int]:
    private_root = artifact_root / f".runtime-lock-java-{root_suffix}"
    run = private_root / f"java-jfr-{run_nonce}"
    private_root.mkdir(mode=0o700)
    run.mkdir(mode=0o700)
    recording = run / f"java-jfr-{run_nonce}.jfr"
    rendered = run / f"java-jfr-{run_nonce}.json"
    recording.write_bytes(b"FLR\x00retained-recording")
    rendered.write_bytes(json_payload)
    recording.chmod(0o600)
    rendered.chmod(0o600)
    return run, recording.stat().st_size + rendered.stat().st_size


def test_retained_inventory_recovers_restart_state_and_cleans_empty_roots(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    run, retained_bytes = _retained_tree(artifact_root)

    inventory = inventory_java_jfr_retained_evidence(
        artifact_root,
        max_retained_bytes=1 << 20,
    )

    assert inventory.retained_bytes == retained_bytes
    assert inventory.private_root_count == 1
    assert len(inventory.retained_evidence) == 1
    retained = inventory.retained_evidence[0]
    assert retained.private_directory_path == run
    assert (
        retained.recording_sha256
        == hashlib.sha256(retained.recording_path.read_bytes()).hexdigest()
    )
    assert retained.json_sha256 == hashlib.sha256(retained.json_path.read_bytes()).hexdigest()

    cleanup_java_jfr_launch_result(retained)
    cleanup_java_jfr_empty_private_roots(artifact_root)
    assert tuple(artifact_root.iterdir()) == ()


def test_retained_inventory_enforces_quota_and_rejects_unknown_entries(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    run, retained_bytes = _retained_tree(artifact_root)

    with pytest.raises(PerfLensError, match="exceed the private Session quota"):
        inventory_java_jfr_retained_evidence(
            artifact_root,
            max_retained_bytes=retained_bytes - 1,
        )

    unexpected = run / "unexpected.secret"
    unexpected.write_text("do not inspect or remove", encoding="utf-8")
    unexpected.chmod(0o600)
    with pytest.raises(PerfLensError, match="unexpected file set"):
        inventory_java_jfr_retained_evidence(
            artifact_root,
            max_retained_bytes=1 << 20,
        )
    assert unexpected.read_text(encoding="utf-8") == "do not inspect or remove"


def test_private_directory_open_failure_rolls_back_only_empty_created_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    identity = launcher_module._inspect_directory(  # pyright: ignore[reportPrivateUsage]
        output,
        os.geteuid(),
        0o700,
        "test output",
    )
    root_fd = launcher_module._open_directory_fd(identity)  # pyright: ignore[reportPrivateUsage]
    real_open = os.open

    def fail_created_directory_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "java-jfr-rollback" and dir_fd == root_fd:
            raise PermissionError("injected open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(launcher_module.os, "open", fail_created_directory_open)
    try:
        with pytest.raises(PerfLensError, match="cannot be created safely"):
            launcher_module._create_private_directory(  # pyright: ignore[reportPrivateUsage]
                root_fd,
                identity,
                "java-jfr-rollback",
                os.geteuid(),
            )
    finally:
        os.close(root_fd)
    assert not (output / "java-jfr-rollback").exists()


def test_private_directory_rollback_preserves_changed_nonempty_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    identity = launcher_module._inspect_directory(  # pyright: ignore[reportPrivateUsage]
        output,
        os.geteuid(),
        0o700,
        "test output",
    )
    root_fd = launcher_module._open_directory_fd(identity)  # pyright: ignore[reportPrivateUsage]
    real_open = os.open
    child_name = "java-jfr-review"

    def populate_then_fail(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == child_name and dir_fd == root_fd:
            created_dir_fd = real_open(
                child_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
                dir_fd=root_fd,
            )
            try:
                child_fd = real_open(
                    "review-required",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=created_dir_fd,
                )
                os.close(child_fd)
            finally:
                os.close(created_dir_fd)
            raise PermissionError("injected open failure after identity change")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(launcher_module.os, "open", populate_then_fail)
    try:
        with pytest.raises(PerfLensError, match="cannot be created safely"):
            launcher_module._create_private_directory(  # pyright: ignore[reportPrivateUsage]
                root_fd,
                identity,
                child_name,
                os.geteuid(),
            )
    finally:
        os.close(root_fd)
    review = output / child_name / "review-required"
    assert review.is_file()
    review.unlink()
    review.parent.rmdir()
