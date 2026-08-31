# pyright: reportPrivateUsage=false
from __future__ import annotations

import asyncio
import hashlib
import io
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from mcp.client import Client

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockRunArtifact,
    RuntimeLockRunFinalizationArtifact,
    RuntimeLockSessionArtifact,
    derive_runtime_lock_run_finalization_id,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.java_jfr_adapter import (
    JavaJfrAdapterBridge,
    build_java_jfr_adapter_bridge,
)
from perflens.runtime_locks.java_jfr_capability import (
    JavaJfrCapability,
    JavaJfrDirectoryIdentity,
    JavaJfrEventSurface,
    JavaJfrNativeLibraryIdentity,
    JavaJfrPayloadFileIdentity,
    JavaJfrRuntimePayloadIdentity,
    JavaJfrToolIdentity,
    _derive_native_library_manifest_identity,
    _derive_runtime_payload_identity,
)
from perflens.runtime_locks.java_jfr_converter import (
    JAVA_JFR_CONVERTER_VERSION,
    convert_java_jfr_json,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaExecutableJarIdentity,
    JavaJfrLauncher,
    JavaJfrLaunchPolicy,
    JavaJfrLaunchRequest,
    JavaJfrLaunchResult,
    acquire_java_jfr_artifact_root_lease,
    java_jfr_arguments_sha256,
    release_java_jfr_artifact_root_lease,
)
from perflens.runtime_locks.java_jfr_profiles import load_java_jfr_profiles
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)

_JFR_FIXTURE = Path(__file__).parents[1] / "fixtures/runtime_locks/jfr/jdk25-locks.json"
_PROFILE_ROOT = Path(__file__).parents[2] / "src/perflens/runtime_locks/jfr"
_NOW = datetime(2026, 8, 30, tzinfo=UTC).isoformat()
type _Behavior = Literal["success", "zero_events", "malformed", "cleanup_identity_mismatch"]


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


def _only_finalization_path(artifacts: Path) -> Path:
    paths = list(artifacts.glob("*.runtime-lock-run-finalization.json"))
    assert len(paths) == 1
    return paths[0]


def _read_finalization(artifacts: Path) -> RuntimeLockRunFinalizationArtifact:
    return RuntimeLockRunFinalizationArtifact.model_validate_json(
        _only_finalization_path(artifacts).read_bytes()
    )


def _assert_failed_settlement(
    artifacts: Path,
    project: Path,
    launch_result: JavaJfrLaunchResult,
) -> None:
    finalization = _read_finalization(artifacts)
    assert finalization.outcome == "failed"
    assert finalization.failure_reason == "adapter_output_invalid"
    assert finalization.run_id is None
    assert finalization.run_content_sha256 is None
    assert finalization.reserved_active_seconds == 3
    assert 0 <= finalization.accounted_active_seconds <= 3
    assert finalization.accounted_evidence_bytes == (
        launch_result.recording_size + launch_result.json_size
    )
    assert finalization.reserved_evidence_bytes >= finalization.accounted_evidence_bytes
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    persisted = store.load_runtime_lock_run_finalization(finalization.finalization_id)
    assert persisted == finalization
    settled_session = store.load_runtime_lock_session(finalization.final_session_artifact_id)
    assert settled_session.workload_runs_used == 1
    assert settled_session.state == "failed"
    assert settled_session.invalidation_reason == "adapter_output_invalid"
    assert settled_session.active_seconds_used == finalization.accounted_active_seconds
    assert settled_session.evidence_bytes_used == finalization.accounted_evidence_bytes


def _tool_identity(path: Path) -> JavaJfrToolIdentity:
    metadata = path.stat(follow_symlinks=False)
    return JavaJfrToolIdentity(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o777,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _directory_identity(path: Path) -> JavaJfrDirectoryIdentity:
    metadata = path.stat(follow_symlinks=False)
    return JavaJfrDirectoryIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o777,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _payload_file_identity(path: Path) -> JavaJfrPayloadFileIdentity:
    metadata = path.stat(follow_symlinks=False)
    return JavaJfrPayloadFileIdentity(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o777,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _native_library_identity(path: Path, relative_path: str) -> JavaJfrNativeLibraryIdentity:
    metadata = path.stat(follow_symlinks=False)
    return JavaJfrNativeLibraryIdentity(
        relative_path=relative_path,
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
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o777,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _bridge(project: Path, policy_path: Path) -> JavaJfrAdapterBridge:
    jdk_bin = project / "jdk/bin"
    jdk_bin.mkdir(parents=True)
    jdk_root = jdk_bin.parent
    jdk_lib = jdk_root / "lib"
    jdk_lib.mkdir()
    for directory in (jdk_root, jdk_bin, jdk_lib):
        directory.chmod(0o755)
    java = jdk_bin / "java"
    jfr = jdk_bin / "jfr"
    release = jdk_root / "release"
    modules = jdk_lib / "modules"
    java.write_bytes(b"reviewed java tool\n")
    jfr.write_bytes(b"reviewed jfr tool\n")
    release.write_bytes(b'JAVA_VERSION="25.0.1"\n')
    modules.write_bytes(b"bounded synthetic JDK modules image\n")
    (jdk_lib / "server").mkdir()
    (jdk_lib / "libjli.so").write_bytes(b"bounded synthetic libjli\n")
    (jdk_lib / "server/libjvm.so").write_bytes(b"bounded synthetic libjvm\n")
    java.chmod(0o755)
    jfr.chmod(0o755)
    release.chmod(0o644)
    modules.chmod(0o644)
    (jdk_lib / "libjli.so").chmod(0o644)
    (jdk_lib / "server/libjvm.so").chmod(0o644)
    (jdk_lib / "server").chmod(0o755)
    directories = (
        _directory_identity(jdk_root),
        _directory_identity(jdk_bin),
        _directory_identity(jdk_lib),
    )
    payload_files = (
        _payload_file_identity(release),
        _payload_file_identity(modules),
    )
    native_libraries = (
        _native_library_identity(jdk_lib / "libjli.so", "libjli.so"),
        _native_library_identity(jdk_lib / "server/libjvm.so", "server/libjvm.so"),
    )
    native_manifest_sha256 = _derive_native_library_manifest_identity(native_libraries)
    runtime_payload = JavaJfrRuntimePayloadIdentity(
        jdk_root=directories[0],
        bin_directory=directories[1],
        lib_directory=directories[2],
        release_file=payload_files[0],
        modules_file=payload_files[1],
        native_libraries=native_libraries,
        native_library_bytes=sum(item.size for item in native_libraries),
        native_library_manifest_sha256=native_manifest_sha256,
        identity_sha256=_derive_runtime_payload_identity(
            directories,
            payload_files,
            native_libraries,
        ),
    )
    profiles = tuple(
        profile
        for profile in load_java_jfr_profiles(
            _PROFILE_ROOT,
            trusted_owner_uids=(os.geteuid(),),
        )
        if profile.jdk_major == 25
    )
    discovered = JavaJfrCapability(
        availability="available",
        jdk_root=jdk_bin.parent,
        jdk_major=25,
        java_version="25.0.1",
        java_build="25.0.1+1",
        java_tool=_tool_identity(java),
        jfr_tool=_tool_identity(jfr),
        profiles=profiles,
        event_surface=JavaJfrEventSurface(
            events=(
                "jdk.DataLoss",
                "jdk.JavaMonitorEnter",
                "jdk.JavaMonitorWait",
                "jdk.ThreadPark",
            ),
            fields=(),
            raw_metadata_sha256="3" * 64,
            canonical_metadata_sha256="4" * 64,
            data_loss_disclosed=True,
        ),
        measurement_semantics=("thresholded",),
        active_launch_supported=True,
        live_attach_supported=False,
        limitations=("JFR evidence is thresholded and does not expose exact hold durations.",),
        runtime_payload=runtime_payload,
    )
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))
    bridge = build_java_jfr_adapter_bridge(policy, discovered, created_at=_NOW)
    assert bridge.execution_binding is not None
    assert bridge.launch_policy is not None
    return bridge


class _FakeJavaJfrLauncher:
    def __init__(
        self,
        project_root: Path,
        private_root: Path,
        policy: JavaJfrLaunchPolicy,
        *,
        behavior: _Behavior,
    ) -> None:
        self.project_root = project_root
        self.private_root = private_root
        self.policy = policy
        self.behavior = behavior
        self.launch_count = 0
        self.requests: list[JavaJfrLaunchRequest] = []
        self.results: list[JavaJfrLaunchResult] = []

    def inspect_target(self, executable_jar: Path) -> JavaExecutableJarIdentity:
        payload = executable_jar.read_bytes()
        metadata = executable_jar.stat(follow_symlinks=False)
        digest = hashlib.sha256(payload).hexdigest()
        relative = executable_jar.relative_to(self.project_root).as_posix()
        identity = hashlib.sha256(
            "\0".join(
                (
                    "test-java-jfr-target-v1",
                    relative,
                    digest,
                    str(metadata.st_dev),
                    str(metadata.st_ino),
                )
            ).encode()
        ).hexdigest()
        return JavaExecutableJarIdentity(
            path=executable_jar,
            project_relative_path=relative,
            binary_sha256=digest,
            identity_sha256=identity,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            mode=metadata.st_mode & 0o7777,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            main_class="example.Main",
        )

    def launch(
        self,
        executable_jar: Path,
        request: JavaJfrLaunchRequest,
        *,
        expected_target_identity_sha256: str,
        expected_arguments_sha256: str,
    ) -> JavaJfrLaunchResult:
        target = self.inspect_target(executable_jar)
        assert target.identity_sha256 == expected_target_identity_sha256
        assert java_jfr_arguments_sha256(request.arguments) == expected_arguments_sha256
        self.launch_count += 1
        self.requests.append(request)
        run_directory = self.private_root / f"java-jfr-{self.launch_count:020x}"
        run_directory.mkdir(mode=0o700)
        recording = run_directory / f"java-jfr-{self.launch_count:020x}.jfr"
        rendered = run_directory / f"java-jfr-{self.launch_count:020x}.json"
        recording_payload = b"bounded synthetic JFR recording\n"
        if self.behavior == "zero_events":
            rendered_payload = b'{"recording":{"events":[]}}'
        elif self.behavior == "malformed":
            rendered_payload = b'{"recording":{"events":[not-json]}}'
        else:
            rendered_payload = _JFR_FIXTURE.read_bytes()
        recording.write_bytes(recording_payload)
        rendered.write_bytes(rendered_payload)
        recording.chmod(0o600)
        rendered.chmod(0o600)
        directory_metadata = run_directory.stat(follow_symlinks=False)
        recording_metadata = recording.stat(follow_symlinks=False)
        rendered_metadata = rendered.stat(follow_symlinks=False)
        started = datetime.now(tz=UTC)
        finished = started + timedelta(milliseconds=200)
        result = JavaJfrLaunchResult(
            private_directory_path=run_directory,
            private_directory_device=directory_metadata.st_dev,
            private_directory_inode=directory_metadata.st_ino,
            recording_path=recording,
            recording_device=recording_metadata.st_dev,
            recording_inode=recording_metadata.st_ino,
            recording_sha256=hashlib.sha256(recording_payload).hexdigest(),
            recording_size=len(recording_payload),
            json_path=rendered,
            json_device=rendered_metadata.st_dev,
            json_inode=rendered_metadata.st_ino,
            json_sha256=hashlib.sha256(rendered_payload).hexdigest(),
            json_size=len(rendered_payload),
            target_identity_sha256=target.identity_sha256,
            jar_sha256=target.binary_sha256,
            arguments_sha256=expected_arguments_sha256,
            java_tool_sha256=self.policy.java_tool.sha256,
            jfr_tool_sha256=self.policy.jfr_tool.sha256,
            jfc_sha256=self.policy.jfc_profile.sha256,
            runtime_payload_identity_sha256=(self.policy.runtime_payload.identity_sha256),
            jdk_major=25,
            profile=self.policy.profile,
            threshold_ns=(1_000_000 if self.policy.profile == "deep" else 10_000_000),
            target_pid=31,
            target_uid=os.geteuid(),
            target_start_ticks=77,
            observed_tids=((31,) if self.behavior == "zero_events" else (31, 56, 57)),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=0.2,
            accounted_active_seconds=1,
            exit_code=0,
            termination_reason="exited",
        )
        self.results.append(result)
        if self.behavior == "cleanup_identity_mismatch":
            recording.write_bytes(recording_payload + b"identity changed\n")
            recording.chmod(0o600)
        return result


def _server(
    tmp_path: Path,
    *,
    behavior: _Behavior = "success",
    profile: Literal["balanced", "deep"] = "balanced",
) -> tuple[object, Path, Path, JavaJfrAdapterBridge, list[_FakeJavaJfrLauncher]]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    jar = project / "app.jar"
    jar.write_bytes(b"reviewed executable jar\n")
    jar.chmod(0o644)
    setup = project / "perflens-setup"
    setup.mkdir()
    policy_path = setup / "runtime-locks.toml"
    policy_text = render_default_runtime_lock_project_policy()
    if profile == "deep":
        policy_text = policy_text.replace(
            'duration_threshold_ns = 10000000\nprofile = "balanced"',
            'duration_threshold_ns = 1000000\nprofile = "deep"',
            1,
        )
    policy_path.write_text(policy_text, encoding="utf-8")
    policy_path.chmod(0o600)
    bridge = _bridge(project, policy_path)
    artifacts = project / "artifacts"
    artifacts.mkdir(mode=0o700)
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))
    project_identity = inspect_managed_project_root(project).identity_sha256
    capability = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=project_identity,
        java_jfr_bridge=bridge,
    )
    launchers: list[_FakeJavaJfrLauncher] = []

    def launcher_factory(
        project_root: Path,
        private_root: Path,
        launch_policy: JavaJfrLaunchPolicy,
    ) -> JavaJfrLauncher:
        launcher = _FakeJavaJfrLauncher(
            project_root,
            private_root,
            launch_policy,
            behavior=behavior,
        )
        launchers.append(launcher)
        return cast(JavaJfrLauncher, launcher)

    server = create_server(
        ServerConfig(
            allowed_roots=(project,),
            artifact_root=artifacts,
            allow_writes=True,
            allow_process_execution=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy_path,
            runtime_lock_capability_factory=lambda: capability,
            runtime_lock_java_bridge_factory=lambda: bridge,
            runtime_lock_java_launcher_factory=launcher_factory,
        )
    )
    return server, project, artifacts, bridge, launchers


async def _authorize_java_session(client: Client) -> tuple[dict[str, Any], dict[str, Any]]:
    previewed = await client.call_tool(
        "preview_runtime_lock_session",
        {
            "target_scope": "host_launched_workload",
            "allowed_adapters": ["java_jfr"],
            "allowed_semantics": ["thresholded"],
            "executable": "app.jar",
            "arguments": ["--reviewed", "42"],
        },
    )
    assert not previewed.is_error, previewed.content
    preview = _structured(previewed)
    authorized = await client.call_tool(
        "authorize_runtime_lock_session",
        {
            "preview_id": preview["preview_id"],
            "preview_content_sha256": preview["content_sha256"],
            "authorization_summary_sha256": preview["authorization_summary_sha256"],
            "authorization": "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION",
        },
    )
    assert not authorized.is_error, authorized.content
    return preview, _structured(authorized)


def test_java_jfr_preview_collects_replays_persists_and_cleans_private_evidence(
    tmp_path: Path,
) -> None:
    server, project, artifacts, bridge, launchers = _server(tmp_path)
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            preview, session = await _authorize_java_session(client)
            assert bridge.execution_binding is not None
            assert preview["workload"]["workload_kind"] == "java_archive"
            assert preview["workload"]["program"] == "app.jar"
            assert preview["allowed_semantics"] == ["thresholded"]
            assert preview["adapter_execution_bindings"] == [
                bridge.execution_binding.model_dump(mode="json")
            ]
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            reference = _structured(collected)
            run_id = cast(str, reference["artifact_id"])
            assert reference["summary"]["adapter_id"] == "java_jfr"
            assert reference["summary"]["private_source_replay_status"] == "passed"
            assert reference["summary"]["event_count"] == 4
            assert reference["summary"]["target_pid"] == 31
            assert launchers[0].requests == [
                JavaJfrLaunchRequest(arguments=("--reviewed", "42"), duration_seconds=3)
            ]
            assert list(launchers[0].private_root.iterdir()) == []

    asyncio.run(exercise())
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    loaded = store.load_runtime_lock_run(run_id)
    assert isinstance(loaded, RuntimeLockRunArtifact)
    started = datetime.fromisoformat(loaded.started_at)
    finished = datetime.fromisoformat(loaded.finished_at)
    assert loaded.created_at == loaded.finished_at
    assert finished - started == timedelta(milliseconds=200)
    assert loaded.adapter_id == "java_jfr"
    assert bridge.execution_binding is not None
    assert loaded.adapter_execution_identity_sha256 == (
        bridge.execution_binding.execution_identity_sha256
    )
    assert loaded.quality_status == "partial"
    assert "unqualified_runtime_lock_conclusion" in loaded.forbidden_conclusions
    analysis, evidence, _replayed = store.load_runtime_lock_analysis(
        loaded.runtime_lock_analysis_id
    )
    assert analysis.runtime_lock_analysis_id == loaded.runtime_lock_analysis_id
    verification = store.load_runtime_lock_verification(loaded.runtime_lock_verification_id)
    assert bridge.execution_binding is not None
    launch_result = launchers[0].results[0]
    expected_conversion = convert_java_jfr_json(
        io.BytesIO(_JFR_FIXTURE.read_bytes()),
        execution_binding=bridge.execution_binding,
        target_pid=launch_result.target_pid,
        target_uid=launch_result.target_uid,
        target_start_time_ticks=launch_result.target_start_ticks,
        created_at=launch_result.started_at,
    )
    replay_receipt = verification.model_dump(mode="json").get("source_replay_receipt")
    assert replay_receipt == {
        "status": "passed",
        "source_format": "jfr_json_v1",
        "raw_source_sha256": expected_conversion.raw_source_sha256,
        "raw_source_bytes": expected_conversion.raw_source_bytes,
        "normalized_source_sha256": expected_conversion.normalized_source_sha256,
        "normalized_source_bytes": expected_conversion.normalized_source_bytes,
        "converter_version": JAVA_JFR_CONVERTER_VERSION,
        "conversion_fingerprint": evidence.source.conversion_fingerprint,
        "adapter_execution_identity_sha256": (bridge.execution_binding.execution_identity_sha256),
        "runtime_lock_evidence_id": evidence.runtime_lock_evidence_id,
        "runtime_lock_evidence_content_sha256": evidence.content_sha256,
    }
    finalization_id = derive_runtime_lock_run_finalization_id(
        loaded.session_id,
        loaded.operation_identity_sha256,
    )
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    assert finalization.outcome == "completed"
    assert finalization.run_id == loaded.run_id
    assert finalization.run_content_sha256 == loaded.content_sha256
    assert finalization.reserved_active_seconds == 3
    assert finalization.accounted_active_seconds == loaded.duration_seconds == 1
    assert finalization.reserved_evidence_bytes > loaded.evidence_bytes
    assert finalization.accounted_evidence_bytes == loaded.evidence_bytes
    assert finalization.reserved_exact_events == 0
    assert finalization.accounted_exact_events == 0
    settled_session = store.load_runtime_lock_session(finalization.final_session_artifact_id)
    assert settled_session.workload_runs_used == 1
    assert settled_session.active_seconds_used == loaded.duration_seconds
    assert settled_session.evidence_bytes_used == loaded.evidence_bytes
    assert settled_session.settlement_finalization_id == finalization.finalization_id
    assert len(list(artifacts.glob("*.runtime-lock-evidence.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-analysis.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-verification.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-run.json"))) == 1
    assert len(list(artifacts.glob("*.runtime-lock-run-finalization.json"))) == 1


def test_java_jfr_persisted_run_is_unreadable_without_finalization_marker(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _bridge, _launchers = _server(tmp_path)
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            run_id = cast(str, _structured(collected)["artifact_id"])

    asyncio.run(exercise())
    _only_finalization_path(artifacts).unlink()
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    with pytest.raises(PerfLensError) as captured:
        store.load_runtime_lock_run(run_id)
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_java_jfr_persisted_run_rejects_extra_promoted_forbidden_conclusion(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _bridge, _launchers = _server(tmp_path)
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            run_id = cast(str, _structured(collected)["artifact_id"])

    asyncio.run(exercise())
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    run = store.load_runtime_lock_run(run_id)
    analysis, _evidence, _verification = store.load_runtime_lock_analysis(
        run.runtime_lock_analysis_id
    )
    assert analysis.quality_status == "complete"
    assert run.quality_status == "partial"
    finalization_id = derive_runtime_lock_run_finalization_id(
        run.session_id,
        run.operation_identity_sha256,
    )
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    provisional = run.model_copy(
        update={
            "forbidden_conclusions": (*run.forbidden_conclusions, "forged"),
            "content_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    run_path = artifacts / f"{run_id}.runtime-lock-run.json"
    run_path.write_text(forged.model_dump_json(), encoding="utf-8")
    run_path.chmod(0o600)
    provisional_marker = finalization.model_copy(
        update={"run_content_sha256": forged.content_sha256, "content_sha256": "0" * 64}
    )
    forged_marker = provisional_marker.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional_marker,
                exclude={"content_sha256"},
            )
        }
    )
    marker_path = artifacts / (f"{finalization_id}.runtime-lock-run-finalization.json")
    marker_path.write_text(forged_marker.model_dump_json(), encoding="utf-8")
    marker_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="Agent-visible content"):
        store.load_runtime_lock_run(run_id)


def test_java_jfr_settlement_marker_failure_destroys_session_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, project, artifacts, _bridge, _launchers = _server(tmp_path)
    run_id = ""

    def fail_after_session_write(
        store: ArtifactStore,
        session: RuntimeLockSessionArtifact,
        _finalization: RuntimeLockRunFinalizationArtifact,
    ) -> tuple[Path, Path]:
        store.save(
            session,
            session.session_artifact_id,
            "runtime-lock-session",
        )
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "artifact",
            "simulated finalization marker failure",
        )

    monkeypatch.setattr(
        ArtifactStore,
        "save_runtime_lock_settlement",
        fail_after_session_write,
    )

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert "simulated finalization marker failure" in str(rejected.content)
            revoked = await client.call_tool(
                "revoke_runtime_lock_session",
                {"session_id": session["session_id"]},
            )
            assert revoked.is_error
            assert "not bound to this connection" in str(revoked.content)
            paths = list(artifacts.glob("*.runtime-lock-run.json"))
            assert len(paths) == 1
            run_id = RuntimeLockRunArtifact.model_validate_json(paths[0].read_bytes()).run_id

    asyncio.run(exercise())
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    with pytest.raises(PerfLensError) as captured:
        store.load_runtime_lock_run(run_id)
    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert not list(artifacts.glob("*.runtime-lock-run-finalization.json"))


def test_java_jfr_zero_event_collection_is_honest_partial(tmp_path: Path) -> None:
    server, project, artifacts, _bridge, launchers = _server(
        tmp_path,
        behavior="zero_events",
    )
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            reference = _structured(collected)
            run_id = cast(str, reference["artifact_id"])
            assert reference["summary"]["event_count"] == 0
            assert reference["summary"]["quality_status"] == "partial"
            assert list(launchers[0].private_root.iterdir()) == []

    asyncio.run(exercise())
    store = ArtifactStore(artifacts, PathPolicy((project,)), allow_writes=False)
    loaded = store.load_runtime_lock_run(run_id)
    assert loaded.event_count == 0
    assert loaded.quality_status == "partial"
    assert any("no accepted events" in warning.lower() for warning in loaded.warnings)


def test_java_jfr_deep_profile_warning_reaches_preview_and_run(tmp_path: Path) -> None:
    server, project, artifacts, _bridge, _launchers = _server(tmp_path, profile="deep")
    run_id = ""

    async def exercise() -> None:
        nonlocal run_id
        async with Client(cast(Any, server)) as client:
            preview, session = await _authorize_java_session(client)
            assert any("material collection overhead" in item for item in preview["warnings"])
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            run_id = cast(str, _structured(collected)["artifact_id"])

    asyncio.run(exercise())
    run = ArtifactStore(
        artifacts,
        PathPolicy((project,)),
        allow_writes=False,
    ).load_runtime_lock_run(run_id)
    assert any("material collection overhead" in item for item in run.warnings)


def test_java_jfr_rejects_exact_semantics_and_jar_replacement_before_launch(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _bridge, launchers = _server(tmp_path)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            exact_preview = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["java_jfr"],
                    "allowed_semantics": ["exact"],
                    "executable": "app.jar",
                },
            )
            assert exact_preview.is_error
            assert "outside project policy" in str(exact_preview.content)
            _preview, session = await _authorize_java_session(client)
            exact_collection = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert exact_collection.is_error
            assert "thresholded" in str(exact_collection.content)
            (project / "app.jar").write_bytes(b"replaced after authorization\n")
            (project / "app.jar").chmod(0o644)
            replaced = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert replaced.is_error
            assert "differs from the authorized Preview" in str(replaced.content)

    asyncio.run(exercise())
    assert launchers[0].launch_count == 0
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_java_jfr_malformed_conversion_is_private_and_retained_only_until_shutdown(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _bridge, launchers = _server(
        tmp_path,
        behavior="malformed",
    )
    retained_directory: Path | None = None

    async def exercise() -> None:
        nonlocal retained_directory
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            retained_directory = launchers[0].results[0].private_directory_path
            assert retained_directory.is_dir()
            assert len(list(retained_directory.iterdir())) == 2
            assert all(
                (item.stat().st_mode & 0o777) == 0o600 for item in retained_directory.iterdir()
            )

    asyncio.run(exercise())
    assert retained_directory is not None
    assert retained_directory.is_dir()
    assert len(list(retained_directory.iterdir())) == 2
    _assert_failed_settlement(artifacts, project, launchers[0].results[0])
    assert not list(artifacts.glob("*.runtime-lock-evidence.json"))
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_java_jfr_cleanup_identity_mismatch_fails_closed_before_publication(
    tmp_path: Path,
) -> None:
    server, project, artifacts, _bridge, launchers = _server(
        tmp_path,
        behavior="cleanup_identity_mismatch",
    )
    retained_directory: Path | None = None

    async def exercise() -> None:
        nonlocal retained_directory
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert "identity or digest changed" in str(rejected.content)
            retained_directory = launchers[0].results[0].private_directory_path
            assert retained_directory.is_dir()
            assert not list(artifacts.glob("*.runtime-lock-evidence.json"))
            assert not list(artifacts.glob("*.runtime-lock-run.json"))

    asyncio.run(exercise())
    assert retained_directory is not None
    _assert_failed_settlement(artifacts, project, launchers[0].results[0])
    owned_directory = cast(Path, retained_directory)
    # Cleanup refuses to delete data whose identity changed. The test owns the
    # synthetic directory and removes it only after asserting the fail-closed path.
    for path in owned_directory.iterdir():
        path.unlink()
    owned_directory.rmdir()


def _write_stale_java_jfr_diagnostics(artifacts: Path) -> Path:
    run_nonce = "0123456789abcdefabcd"
    private_root = artifacts / ".runtime-lock-java-aaaaaaaa"
    run = private_root / f"java-jfr-{run_nonce}"
    private_root.mkdir(mode=0o700)
    run.mkdir(mode=0o700)
    recording = run / f"java-jfr-{run_nonce}.jfr"
    rendered = run / f"java-jfr-{run_nonce}.json"
    recording.write_bytes(b"FLR\x00prior-process-recording")
    rendered.write_bytes(_JFR_FIXTURE.read_bytes())
    recording.chmod(0o600)
    rendered.chmod(0o600)
    return private_root


def test_java_jfr_restart_inventories_without_deleting_prior_private_diagnostics(
    tmp_path: Path,
) -> None:
    server, _project, artifacts, _bridge, launchers = _server(tmp_path)
    stale_root = _write_stale_java_jfr_diagnostics(artifacts)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            _preview, session = await _authorize_java_session(client)
            collected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "thresholded",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert not collected.is_error, collected.content
            assert stale_root.is_dir()

    asyncio.run(exercise())
    assert len(launchers) == 1
    assert stale_root.is_dir()
    assert len(tuple(stale_root.rglob("*"))) == 3


def test_java_jfr_restart_rejects_malformed_private_inventory_before_launch(
    tmp_path: Path,
) -> None:
    server, _project, artifacts, _bridge, launchers = _server(tmp_path)
    private_root = artifacts / ".runtime-lock-java-aaaaaaaa"
    private_root.mkdir(mode=0o700)
    unexpected = private_root / "unknown-entry"
    unexpected.write_text("preserve for review", encoding="utf-8")
    unexpected.chmod(0o600)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            rejected = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["java_jfr"],
                    "allowed_semantics": ["thresholded"],
                    "executable": "app.jar",
                    "arguments": ["--reviewed", "42"],
                },
            )
            assert rejected.is_error
            assert "unexpected diagnostic entry" in str(rejected.content)

    asyncio.run(exercise())
    assert launchers == []
    assert unexpected.read_text(encoding="utf-8") == "preserve for review"


def test_java_jfr_second_mcp_cannot_inventory_or_clean_active_private_root(
    tmp_path: Path,
) -> None:
    server, _project, artifacts, _bridge, launchers = _server(tmp_path)
    active_root = artifacts / ".runtime-lock-java-aaaaaaaa"
    active_root.mkdir(mode=0o700)
    in_progress = active_root / "java-jfr-0123456789abcdefabcd"
    in_progress.mkdir(mode=0o700)
    partial = in_progress / "java-jfr-0123456789abcdefabcd.jfr"
    partial.write_bytes(b"FLR\x00active-other-process")
    partial.chmod(0o600)
    owner_lease = acquire_java_jfr_artifact_root_lease(artifacts)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            rejected = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["java_jfr"],
                    "allowed_semantics": ["thresholded"],
                    "executable": "app.jar",
                    "arguments": ["--reviewed", "42"],
                },
            )
            assert rejected.is_error
            assert "owns the private evidence lease" in str(rejected.content)

    try:
        asyncio.run(exercise())
    finally:
        release_java_jfr_artifact_root_lease(owner_lease)
    assert launchers == []
    assert partial.read_bytes() == b"FLR\x00active-other-process"
