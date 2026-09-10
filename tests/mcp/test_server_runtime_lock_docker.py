# pyright: reportPrivateUsage=false
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import pytest
from mcp.client import Client
from tests.mcp.test_server_java_jfr import _bridge as _java_bridge
from tests.mcp.test_server_native_pthread import _native_capability
from tests.mcp.test_storage import _runtime_lock_store_with_two_runs
from tests.support.docker import make_container_resource_context
from tests.unit.test_docker_comparison import (
    _benchmark,
    _collection,
    _optimization_build,
    _run,
    _workload,
)
from tests.unit.test_docker_optimization_runtime import make_optimization_runtime
from tests.unit.test_runtime_lock_docker_binding import (
    _evidence,
    _execution_binding,
)

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.verify_runtime_locks import (
    build_runtime_lock_source_replay_receipt,
    verify_runtime_lock_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.collection.planning import AutomaticCollectionPolicy
from perflens.contracts.artifacts import BenchmarkArtifact, CollectionArtifact
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerMeasurementArtifact,
    ContainerNamespaceIdentity,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerRuntimeLockAuthorizationScope,
    docker_runtime_lock_scope_sha256,
    docker_runtime_lock_version_constraints,
)
from perflens.contracts.runtime_lock_sessions import RuntimeLockSessionBudget
from perflens.contracts.runtime_locks import RuntimeLockEvidenceArtifact
from perflens.docker import adapter as docker_adapter
from perflens.docker.adapter import NativePthreadDockerLaunch
from perflens.docker.comparison import build_container_measurement
from perflens.docker.optimization_session import (
    EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
)
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import PerfLensError
from perflens.mcp import server as server_module
from perflens.mcp.server import (
    ServerConfig,
    _docker_runtime_lock_accounted_bytes,
    _DockerRuntimeLockCollected,
    _DockerRuntimeLockRequest,
    _finalize_docker_runtime_lock_run,
    create_server,
)
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.cpython_adapter import (
    build_cpython_adapter_bridge,
    inspect_cpython_installation,
)
from perflens.runtime_locks.docker_binding import bind_runtime_lock_evidence_to_container
from perflens.runtime_locks.docker_capture import bind_observed_runtime_execution
from perflens.runtime_locks.go_pprof_adapter import (
    GoPprofInstallation,
    GoToolIdentity,
    build_go_pprof_adapter_bridge,
)
from perflens.runtime_locks.native_launcher import (
    NativePthreadProbeDiscovery,
    NativePthreadProbePolicy,
)
from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


def _container_graph(
    tmp_path: Path,
    build: DockerBuildArtifact,
) -> tuple[
    ContainerTargetArtifact,
    ContainerRunArtifact,
    ContainerMeasurementArtifact,
    CollectionArtifact,
    ContainerResourceContextArtifact,
    ContainerWorkloadSpecArtifact,
    BenchmarkArtifact,
]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    profile = tmp_path / "profile.folded"
    profile.write_text("main;work 100\n", encoding="utf-8")
    initial_collection = _collection(profile, marker="b", host_pid=1200)
    initial_binding = initial_collection.container_target
    assert initial_binding is not None
    target_provisional = ContainerTargetArtifact(
        schema_version="1.1",
        perflens_version="0.4.0",
        target_id=initial_binding.target_id,
        created_at="2026-08-22T00:00:00+00:00",
        target_kind=initial_binding.target_kind,
        container_identity_sha256=initial_binding.container_identity_sha256,
        image_identity_sha256=build.final_image_digest.removeprefix("sha256:"),
        container_pid=initial_binding.container_pid,
        host_pid=initial_binding.host_pid,
        host_uid=initial_binding.host_uid,
        container_uid=1000,
        uid_map_sha256="6" * 64,
        host_start_time_ticks=initial_binding.host_start_time_ticks,
        executable_name=initial_binding.executable_name,
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=initial_binding.namespace.pid_namespace_inode,
            user_namespace_inode=initial_binding.namespace.user_namespace_inode,
            mount_namespace_inode=initial_binding.namespace.mount_namespace_inode,
            cgroup_namespace_inode=initial_binding.namespace.cgroup_namespace_inode,
        ),
        cgroup=ContainerCgroupIdentity(
            inode=initial_binding.cgroup.inode,
            identity_sha256=initial_binding.cgroup.identity_sha256,
        ),
        uid_mapping=initial_binding.uid_mapping,
        adapter_recipe_id=initial_binding.adapter_recipe_id,
        adapter_sha256=initial_binding.adapter_sha256,
        identity_fingerprint=initial_binding.identity_fingerprint,
        content_sha256="0" * 64,
    )
    target = target_provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                target_provisional,
                exclude={"content_sha256"},
            )
        }
    )
    collection_binding = initial_binding.model_copy(
        update={
            "target_content_sha256": target.content_sha256,
            "image_identity_sha256": target.image_identity_sha256,
        }
    )
    collection = initial_collection.model_copy(update={"container_target": collection_binding})
    resource = make_container_resource_context(
        container_identity_sha256=target.container_identity_sha256,
        source_collection_id=collection.collection_id,
        source_output_sha256=collection.output_sha256,
    )
    workload = _workload()
    benchmark = _benchmark("benchmark-runtime-lock", (100, 101, 99), commit="baseline")
    container_run = _run(
        collection,
        resource,
        workload,
        marker="b",
        treatment="1" * 64,
        benchmark=benchmark,
    )
    measurement = build_container_measurement(
        collection,
        resource,
        run=container_run,
        workload=workload,
    )
    return target, container_run, measurement, collection, resource, workload, benchmark


def _native_evidence_for_target(
    fixture_root: Path,
    target: ContainerTargetArtifact,
) -> RuntimeLockEvidenceArtifact:
    source = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    records = [json.loads(line) for line in source.splitlines()]
    for record in records:
        record_type = record["record_type"]
        if record_type == "probe_header":
            record["pid"] = target.container_pid
            record["uid"] = target.container_uid
            record["target_start_time_ticks"] = target.host_start_time_ticks
            record["observed_target_tids"] = [target.container_pid, target.container_pid + 1]
        elif record_type == "probe_event":
            record["pid"] = target.container_pid
            record["tid"] = target.container_pid + 1
        elif record_type == "probe_footer":
            record["pid"] = target.container_pid
    normalized = b"".join(
        json.dumps(record, separators=(",", ":")).encode() + b"\n" for record in records
    )
    return convert_native_pthread_probe(BytesIO(normalized)).evidence


def _runtime_lock_scope(fixture_root: Path) -> DockerRuntimeLockAuthorizationScope:
    binding = _execution_binding(_evidence(fixture_root))
    provisional = DockerRuntimeLockAuthorizationScope.model_construct(
        schema_version="1.1",
        runtime_lock_config_sha256="d" * 64,
        capability_id="runtime-lock-capability-" + "e" * 20,
        capability_content_sha256="f" * 64,
        allowed_adapters=("native_pthread",),
        allowed_semantics=("exact",),
        adapter_execution_bindings=(binding,),
        runtime_version_constraints=docker_runtime_lock_version_constraints((binding,)),
        budget=RuntimeLockSessionBudget(),
        content_sha256="0" * 64,
    )
    return DockerRuntimeLockAuthorizationScope.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": docker_runtime_lock_scope_sha256(provisional),
        }
    )


def _go_installation(project: Path) -> GoPprofInstallation:
    tool_path = project / "go"
    tool_path.write_bytes(b"reviewed fixed Go tool\n")
    tool_path.chmod(0o755)
    metadata = tool_path.stat(follow_symlinks=False)
    identity = GoToolIdentity(
        path=tool_path,
        version="1.26.1",
        minor_version="1.26",
        sha256=hashlib.sha256(tool_path.read_bytes()).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=metadata.st_mode & 0o777,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
    )
    return GoPprofInstallation(
        availability="available",
        tool=identity,
        pprof_tool=identity,
        runtime_version=identity.version,
        metadata_sha256=hashlib.sha256(b"go-1.26-reviewed-metadata").hexdigest(),
        limitations=("Synthetic fixed tool identity for the MCP authorization test.",),
    )


def _four_adapter_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    runtime_lock_evidence_budget: int | None = None,
) -> tuple[object, Any, Any, Path]:
    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy_path = project / "runtime-locks.toml"
    policy_text = render_default_runtime_lock_project_policy(docker_enabled=True).replace(
        "launch_instrumentation_allowed = false\n"
        "controlled_import_allowed = false\n"
        "mutex_profile_fraction = 0\n"
        "block_profile_rate_ns = 0\n"
        "file_backend_enabled = false\n"
        "loopback_backend_enabled = false",
        "launch_instrumentation_allowed = true\n"
        "controlled_import_allowed = false\n"
        "mutex_profile_fraction = 1\n"
        "block_profile_rate_ns = 1\n"
        "file_backend_enabled = true\n"
        "loopback_backend_enabled = false",
        1,
    )
    if runtime_lock_evidence_budget is not None:
        policy_text = policy_text.replace(
            "max_evidence_bytes = 536870912",
            f"max_evidence_bytes = {runtime_lock_evidence_budget}",
            1,
        )
    policy_path.write_text(policy_text, encoding="utf-8")
    policy_path.chmod(0o600)
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(project,))

    java_bridge = _java_bridge(project, policy_path)
    interpreter = project / "python3"
    runtime_home = project / "cpython-home"
    bootstrap = project / "cpython-bootstrap.py"
    interpreter.write_bytes(b"reviewed CPython interpreter identity\n")
    runtime_home.mkdir()
    bootstrap.write_bytes(b"reviewed CPython bootstrap identity\n")
    interpreter.chmod(0o755)
    runtime_home.chmod(0o755)
    bootstrap.chmod(0o644)
    cpython_installation = inspect_cpython_installation(
        interpreter_path=interpreter,
        runtime_home_path=runtime_home,
        bootstrap_path=bootstrap,
        trusted_owner_uids=(os.geteuid(),),
    )
    cpython_bridge = build_cpython_adapter_bridge(
        policy,
        cpython_installation,
        created_at="2026-08-31T00:00:00+00:00",
    )
    go_bridge = build_go_pprof_adapter_bridge(
        policy,
        _go_installation(project),
        created_at="2026-08-31T00:00:00+00:00",
    )
    probe = project / "libperflens-pthread-probe.so"
    probe.write_bytes(b"reviewed packaged pthread probe\n")
    probe.chmod(0o644)
    probe_policy = NativePthreadProbePolicy(
        path=probe,
        sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        owner_uid=os.geteuid(),
    )
    monkeypatch.setattr(
        server_module,
        "discover_native_pthread_probe_policy",
        lambda: NativePthreadProbeDiscovery(
            availability="available",
            policy=probe_policy,
            identity=None,
            limitations=(),
        ),
    )
    capability = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=inspect_managed_project_root(project).identity_sha256,
        native_pthread_capability=_native_capability(),
        java_jfr_bridge=java_bridge,
        cpython_bridge=cpython_bridge,
        go_pprof_bridge=go_bridge,
        created_at=datetime.fromisoformat("2026-08-31T00:00:00+00:00"),
    )
    server = create_server(
        ServerConfig(
            allowed_roots=(tmp_path,),
            artifact_root=artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            allow_runtime_locks=True,
            docker_project_config=project / "container-workload.toml",
            runtime_lock_project_config=policy_path,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
            runtime_lock_capability_factory=lambda: capability,
            runtime_lock_java_bridge_factory=lambda: java_bridge,
            runtime_lock_cpython_bridge_factory=lambda: cpython_bridge,
            runtime_lock_go_bridge_factory=lambda: go_bridge,
        )
    )
    return server, runtime, adapter, project


@pytest.mark.parametrize(
    ("adapter_id", "launch_name", "profile_kind"),
    (
        ("native_pthread", "NativePthreadDockerLaunch", None),
        ("cpython_threading", "CpythonDockerLaunch", None),
        ("java_jfr", "JavaJfrDockerLaunch", None),
        ("go_pprof", "GoPprofDockerLaunch", "mutex"),
    ),
)
def test_one_docker_confirmation_builds_each_typed_runtime_lock_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_id: str,
    launch_name: str,
    profile_kind: str | None,
) -> None:
    server, runtime, adapter, _project = _four_adapter_server(tmp_path, monkeypatch)
    recorded_launches: list[object] = []
    launch_type = getattr(docker_adapter, launch_name)

    def record_launch(**values: object) -> object:
        launch = launch_type(**values)
        recorded_launches.append(launch)
        return launch

    monkeypatch.setattr(server_module, launch_name, record_launch)

    def stop_after_launch(*_args: object, **_kwargs: object) -> None:
        raise PerfLensError(
            server_module.ErrorCode.EXTERNAL_TOOL_FAILED,
            "runtime_lock_typed_launch_test",
            "Synthetic stop after typed Docker launch construction",
            recoverable=False,
        )

    monkeypatch.setattr(
        server_module.ExistingDockerRuntime,
        "authorize_optimization_build",
        stop_after_launch,
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_result = await client.call_tool(
                "preview_docker_optimization_session",
                {
                    "allowed_modes": ["stat", "record"],
                    "runtime_lock_adapters": [
                        "cpython_threading",
                        "go_pprof",
                        "java_jfr",
                        "native_pthread",
                    ],
                },
            )
            assert not preview_result.is_error, preview_result.content
            preview = _structured(preview_result)
            assert preview["runtime_lock_scope"]["allowed_adapters"] == [
                "cpython_threading",
                "go_pprof",
                "java_jfr",
                "native_pthread",
            ]
            authorization = await client.call_tool(
                "authorize_docker_optimization_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview[
                        "authorization_summary_sha256"
                    ],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                    ),
                },
            )
            assert not authorization.is_error, authorization.content
            session = _structured(authorization)
            baseline_result = await client.call_tool(
                "build_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "build_kind": "baseline",
                    "candidate_round": 0,
                },
            )
            assert not baseline_result.is_error, baseline_result.content
            baseline = _structured(baseline_result)
            request: dict[str, object] = {
                "session_id": session["session_id"],
                "build_id": baseline["artifact_id"],
                "mode": "stat",
                "duration_seconds": 1,
                "workload_timeout_seconds": 3,
                "max_output_bytes": 1 << 20,
                "runtime_lock_adapter": adapter_id,
                "runtime_lock_max_events": 100,
            }
            if profile_kind is not None:
                request["runtime_lock_go_profile_kind"] = profile_kind
            stopped = await client.call_tool(
                "collect_docker_optimization_workload",
                request,
            )
            assert stopped.is_error
            assert "Synthetic stop after typed Docker launch construction" in str(
                stopped.content
            )
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 1
            assert current.runtime_lock_runs_used == 0
            assert current.runtime_lock_status == "unavailable"

    asyncio.run(exercise())
    assert len(recorded_launches) == 1
    assert type(recorded_launches[0]).__name__ == launch_name
    assert len(adapter.cleaned) == 1


def test_runtime_lock_combined_evidence_budget_is_rejected_before_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, runtime, adapter, _project = _four_adapter_server(
        tmp_path,
        monkeypatch,
        runtime_lock_evidence_budget=128 << 20,
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {
                        "allowed_modes": ["stat"],
                        "runtime_lock_adapters": ["native_pthread"],
                    },
                )
            )
            session = _structured(
                await client.call_tool(
                    "authorize_docker_optimization_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview[
                            "authorization_summary_sha256"
                        ],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            baseline = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session["session_id"],
                        "build_kind": "baseline",
                        "candidate_round": 0,
                    },
                )
            )
            rejected = await client.call_tool(
                "collect_docker_optimization_workload",
                {
                    "session_id": session["session_id"],
                    "build_id": baseline["artifact_id"],
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 3,
                    "max_output_bytes": 1 << 20,
                    "runtime_lock_adapter": "native_pthread",
                    "runtime_lock_max_events": 100,
                },
            )
            assert rejected.is_error
            assert "reservation exceeds the remaining Session budget" in str(
                rejected.content
            )
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 0
            assert current.runtime_lock_runs_used == 0

    asyncio.run(exercise())
    assert len(adapter.cleaned) == 1  # The baseline Build is cleaned when the server closes.


@pytest.mark.parametrize(
    "adapter_scope",
    (
        ("native_pthread", "native_pthread"),
        ("native_pthread", "java_jfr"),
        ("generic_ndjson_import",),
    ),
)
def test_docker_runtime_lock_preview_rejects_ambiguous_or_import_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_scope: tuple[str, ...],
) -> None:
    server, _runtime, _adapter, _project = _four_adapter_server(tmp_path, monkeypatch)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            rejected = await client.call_tool(
                "preview_docker_optimization_session",
                {
                    "allowed_modes": ["stat"],
                    "runtime_lock_adapters": list(adapter_scope),
                },
            )
            assert rejected.is_error
            assert "unique policy-enabled active Adapter scope" in str(rejected.content)

    asyncio.run(exercise())


def test_docker_runtime_lock_collection_rejects_untyped_mode_and_go_profile_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, runtime, _adapter, _project = _four_adapter_server(tmp_path, monkeypatch)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {
                        "allowed_modes": ["stat", "sched"],
                        "runtime_lock_adapters": ["go_pprof", "native_pthread"],
                    },
                )
            )
            session = _structured(
                await client.call_tool(
                    "authorize_docker_optimization_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview[
                            "authorization_summary_sha256"
                        ],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            baseline = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session["session_id"],
                        "build_kind": "baseline",
                        "candidate_round": 0,
                    },
                )
            )
            common = {
                "session_id": session["session_id"],
                "build_id": baseline["artifact_id"],
                "duration_seconds": 1,
                "workload_timeout_seconds": 3,
                "max_output_bytes": 1 << 20,
                "runtime_lock_max_events": 100,
            }
            cases = (
                (
                    {
                        **common,
                        "mode": "sched",
                        "runtime_lock_adapter": "native_pthread",
                    },
                    "must accompany stat or record",
                ),
                (
                    {
                        **common,
                        "mode": "stat",
                        "runtime_lock_adapter": "native_pthread",
                        "runtime_lock_go_profile_kind": "mutex",
                    },
                    "requires exactly one authorized profile kind",
                ),
                (
                    {
                        **common,
                        "mode": "stat",
                        "runtime_lock_adapter": "go_pprof",
                    },
                    "requires exactly one authorized profile kind",
                ),
                (
                    {
                        **common,
                        "mode": "stat",
                        "runtime_lock_go_profile_kind": "mutex",
                    },
                    "cannot be selected without the Go Runtime Lock Adapter",
                ),
            )
            for request, expected_error in cases:
                rejected = await client.call_tool(
                    "collect_docker_optimization_workload",
                    request,
                )
                assert rejected.is_error
                assert expected_error in str(rejected.content)
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 0
            assert current.runtime_lock_runs_used == 0

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("adapter_id", "replacement_kind", "profile_kind", "expected_error"),
    (
        (
            "cpython_threading",
            "cpython_bootstrap",
            None,
            "CPython runtime payload changed after capability inspection",
        ),
        (
            "cpython_threading",
            "cpython_interpreter",
            None,
            "CPython runtime payload changed after capability inspection",
        ),
        ("java_jfr", "java_tool", None, "policy file digest differs from its binding"),
        (
            "java_jfr",
            "java_runtime_payload",
            None,
            "runtime payload file identity changed",
        ),
        ("go_pprof", "go_tool", "mutex", "Go tool identity changed"),
        (
            "go_pprof",
            "go_configuration",
            "mutex",
            "Runtime Lock policy changed after MCP startup",
        ),
    ),
)
def test_docker_runtime_lock_rejects_adapter_replacement_after_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_id: str,
    replacement_kind: str,
    profile_kind: str | None,
    expected_error: str,
) -> None:
    server, runtime, _adapter, project = _four_adapter_server(tmp_path, monkeypatch)

    def stop_if_replacement_is_missed(*_args: object, **_kwargs: object) -> None:
        raise PerfLensError(
            server_module.ErrorCode.EXTERNAL_TOOL_FAILED,
            "runtime_lock_replacement_test",
            "Synthetic stop: replacement safety gate was missed",
            recoverable=False,
        )

    monkeypatch.setattr(
        server_module.ExistingDockerRuntime,
        "authorize_optimization_build",
        stop_if_replacement_is_missed,
    )

    def replace_authorized_input() -> None:
        paths = {
            "cpython_bootstrap": project / "cpython-bootstrap.py",
            "cpython_interpreter": project / "python3",
            "java_tool": project / "jdk/bin/java",
            "java_runtime_payload": project / "jdk/lib/modules",
            "go_tool": project / "go",
            "go_configuration": project / "runtime-locks.toml",
        }
        path = paths[replacement_kind]
        if replacement_kind == "go_configuration":
            payload = path.read_text(encoding="utf-8").replace(
                "mutex_profile_fraction = 1",
                "mutex_profile_fraction = 2",
                1,
            )
            path.write_text(payload, encoding="utf-8")
        else:
            path.write_bytes(path.read_bytes() + b"replacement-after-preview\n")
        path.chmod(0o600 if replacement_kind == "go_configuration" else path.stat().st_mode & 0o777)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {
                        "allowed_modes": ["stat"],
                        "runtime_lock_adapters": [adapter_id],
                    },
                )
            )
            session = _structured(
                await client.call_tool(
                    "authorize_docker_optimization_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview[
                            "authorization_summary_sha256"
                        ],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            baseline = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session["session_id"],
                        "build_kind": "baseline",
                        "candidate_round": 0,
                    },
                )
            )
            replace_authorized_input()
            request: dict[str, object] = {
                "session_id": session["session_id"],
                "build_id": baseline["artifact_id"],
                "mode": "stat",
                "duration_seconds": 1,
                "workload_timeout_seconds": 3,
                "max_output_bytes": 1 << 20,
                "runtime_lock_adapter": adapter_id,
                "runtime_lock_max_events": 100,
            }
            if profile_kind is not None:
                request["runtime_lock_go_profile_kind"] = profile_kind
            rejected = await client.call_tool(
                "collect_docker_optimization_workload",
                request,
            )
            assert rejected.is_error
            assert expected_error in str(rejected.content)
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 0
            assert current.runtime_lock_runs_used == 0

    asyncio.run(exercise())


@pytest.mark.parametrize("fail_run_persistence", (False, True))
def test_docker_runtime_lock_finalization_is_single_charge_and_fail_closed(
    tmp_path: Path,
    fixture_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_run_persistence: bool,
) -> None:
    runtime, _, _ = make_optimization_runtime(tmp_path)
    scope = _runtime_lock_scope(fixture_root)
    preview = runtime.preview(allowed_modes=("stat",), runtime_lock_scope=scope)
    session = runtime.authorize(
        preview_id=preview.preview.preview_id,
        preview_content_sha256=preview.preview.content_sha256,
        authorization_summary_sha256=preview.preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_DOCKER_OPTIMIZATION_AUTHORIZATION,
    )
    build = runtime.build(session.session_id, build_kind="baseline", candidate_round=0).build
    lease = runtime.begin_workload(
        session.session_id,
        build_id=build.build_id,
        mode="stat",
        reserve_active_seconds=3,
        reserve_evidence_bytes=4 << 20,
    )
    runtime.finish_workload(
        session.session_id,
        lease,
        actual_active_seconds=1,
        actual_evidence_bytes=64 << 10,
    )

    (
        target,
        container_run,
        measurement,
        collection,
        resource,
        workload,
        benchmark,
    ) = _container_graph(tmp_path / "graph", build)
    host_evidence = _native_evidence_for_target(fixture_root, target)
    authorized_binding = scope.adapter_execution_bindings[0]
    runtime_version = host_evidence.source.runtime_version
    assert runtime_version is not None
    execution_binding = bind_observed_runtime_execution(
        authorized_binding,
        runtime_version=runtime_version,
        runtime_characteristics="glibc-2.41",
    )
    evidence = bind_runtime_lock_evidence_to_container(
        host_evidence,
        execution_binding=execution_binding,
        target=target,
        run=container_run,
    )
    analysis = build_runtime_lock_analysis(evidence)
    replay = build_runtime_lock_source_replay_receipt(
        evidence,
        origin_source_sha256=evidence.source.source_sha256,
        origin_source_bytes=evidence.source.source_bytes,
    )
    verification = verify_runtime_lock_analysis_artifact(
        analysis,
        evidence,
        source_replay_receipt=replay,
    )
    collected = _DockerRuntimeLockCollected(
        request=_DockerRuntimeLockRequest(
            docker_optimization_session_id=session.session_id,
            build_id=build.build_id,
            adapter_id="native_pthread",
            execution_binding=execution_binding,
            authorized_execution_identity_sha256=(
                authorized_binding.execution_identity_sha256
            ),
            launch=NativePthreadDockerLaunch(
                probe_path=tmp_path / "probe.so",
                probe_sha256=execution_binding.configuration_sha256,
                semantics="exact",
                duration_threshold_ns=None,
                max_events=20_000,
            ),
            observation_limit_seconds=3,
            runtime_characteristics="glibc-2.41",
        ),
        evidence=evidence,
        analysis=analysis,
        verification=verification,
        target=target,
        container_run=container_run,
        measurement=measurement,
        started_at="2026-08-22T00:00:00.100000+00:00",
        finished_at="2026-08-22T00:00:01.100000+00:00",
        replay_verified=True,
    )
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    for artifact, artifact_id, artifact_type in (
        (build, build.build_id, "docker-build"),
        (target, target.target_id, "container-target"),
        (collection, collection.collection_id, "collection"),
        (resource, resource.resource_context_id, "container-resource-context"),
        (workload, workload.workload_spec_id, "container-workload-spec"),
        (benchmark, benchmark.benchmark_id, "benchmark"),
        (container_run, container_run.run_id, "container-run"),
        (measurement, measurement.measurement_id, "container-measurement"),
    ):
        store.save(artifact, artifact_id, artifact_type)

    accounted = _docker_runtime_lock_accounted_bytes(collected)
    if fail_run_persistence:
        original_save = store.save

        def fail_runtime_lock_run_save(
            artifact: Any,
            artifact_id: str,
            artifact_type: str,
        ) -> Path:
            if artifact_type == "runtime-lock-run":
                raise PerfLensError(
                    server_module.ErrorCode.PATH_SAFETY_VIOLATION,
                    "artifact_write",
                    "Synthetic Runtime Lock Run persistence failure",
                    recoverable=False,
                )
            return original_save(artifact, artifact_id, artifact_type)

        monkeypatch.setattr(store, "save", fail_runtime_lock_run_save)
        with pytest.raises(PerfLensError, match="persistence failure"):
            _finalize_docker_runtime_lock_run(
                store,
                runtime,
                session.session_id,
                lease,
                build,
                collected,
            )
        failed = runtime.fail_completed_runtime_lock_use(
            session.session_id,
            lease,
            reason="Synthetic Runtime Lock Run persistence failure",
        )
        assert failed.runtime_lock_status == "unavailable"
        assert failed.runtime_lock_runs_used == 1
        assert failed.runtime_lock_exact_events_used == len(evidence.events)
        assert failed.runtime_lock_evidence_bytes_used == accounted
        assert not tuple(store.root.glob("*.runtime-lock-run.json"))
        return

    charged_session, runtime_run = _finalize_docker_runtime_lock_run(
        store,
        runtime,
        session.session_id,
        lease,
        build,
        collected,
    )

    assert charged_session.runtime_lock_runs_used == 1
    assert charged_session.runtime_lock_exact_events_used == len(evidence.events)
    assert charged_session.runtime_lock_evidence_bytes_used == accounted
    assert runtime_run.authorization_kind == "docker_optimization"
    assert runtime_run.correctness_status == "passed"
    assert runtime_run.duration_seconds == 1
    assert runtime_run.evidence_bytes == len(serialize_json(evidence))
    assert runtime_run.docker_optimization_binding is not None
    assert runtime_run.docker_optimization_binding.accounted_evidence_bytes == accounted
    assert (
        store.root / f"{runtime_run.run_id}.runtime-lock-run.json"
    ).is_file()
    assert (
        store.root
        / f"{charged_session.session_artifact_id}.docker-optimization-session.json"
    ).is_file()
    assert runtime.snapshot(session.session_id) == charged_session
    assert store.load_runtime_lock_run(runtime_run.run_id) == runtime_run


def test_docker_runtime_lock_accounting_requires_complete_replay_chain(
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
    build = _optimization_build(
        kind="baseline",
        round_number=0,
        image_marker="a",
        treatment_marker="1",
    )
    target, container_run, measurement, *_ = _container_graph(
        tmp_path / "generated-measurement",
        build,
    )
    binding = _execution_binding(evidence)
    collected = _DockerRuntimeLockCollected(
        request=_DockerRuntimeLockRequest(
            docker_optimization_session_id="docker-optimization-session-" + "1" * 20,
            build_id="docker-build-" + "2" * 20,
            adapter_id="native_pthread",
            execution_binding=binding,
            authorized_execution_identity_sha256=binding.execution_identity_sha256,
            launch=NativePthreadDockerLaunch(
                probe_path=Path("/probe.so"),
                probe_sha256="3" * 64,
                semantics="exact",
                duration_threshold_ns=None,
                max_events=20,
            ),
            observation_limit_seconds=1,
            runtime_characteristics="glibc-2.41",
        ),
        evidence=evidence,
        analysis=analysis,
        verification=verification,
        target=target,
        container_run=container_run,
        measurement=measurement,
        started_at="2026-08-31T00:00:00+00:00",
        finished_at="2026-08-31T00:00:01+00:00",
        replay_verified=False,
    )

    with pytest.raises(PerfLensError, match="complete source chain"):
        _docker_runtime_lock_accounted_bytes(collected)


def test_runtime_lock_comparison_mcp_persists_verified_standalone_result(
    tmp_path: Path,
) -> None:
    store, baseline, candidate = _runtime_lock_store_with_two_runs(tmp_path)
    server = create_server(
        ServerConfig(
            allowed_roots=(tmp_path,),
            artifact_root=store.root,
            allow_writes=True,
        )
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            compared = await client.call_tool(
                "compare_runtime_lock_analyses",
                {
                    "baseline_run_id": baseline.run_id,
                    "candidate_run_id": candidate.run_id,
                },
            )
            assert not compared.is_error, compared.content
            comparison = _structured(compared)
            assert comparison["comparison_kind"] == "runtime_lock_session"
            assert comparison["baseline_run_id"] == baseline.run_id
            assert comparison["candidate_run_id"] == candidate.run_id
            assert comparison["resource_transfer_status"] == "incomplete"
            assert comparison["conclusion"] == "no_material_change"
            loaded = store.load_runtime_lock_comparison(comparison["comparison_id"])
            assert loaded.content_sha256 == comparison["content_sha256"]

            forged_resource_claim = await client.call_tool(
                "compare_runtime_lock_analyses",
                {
                    "baseline_run_id": baseline.run_id,
                    "candidate_run_id": candidate.run_id,
                    "container_comparison_id": "container-comparison-" + "f" * 20,
                },
            )
            assert forged_resource_claim.is_error
            assert "cannot claim Docker resource evidence" in str(
                forged_resource_claim.content
            )

    asyncio.run(exercise())
