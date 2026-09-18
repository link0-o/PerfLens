# pyright: reportPrivateUsage=false
"""Cross-adapter MCP gates that exercise host Runtime Lock failure semantics."""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest
from mcp.client import Client
from tests.mcp.test_server_cpython import _server as cpython_server
from tests.mcp.test_server_go_pprof import _server as go_server
from tests.mcp.test_server_java_jfr import (
    _authorize_java_session,
    _FakeJavaJfrLauncher,
)
from tests.mcp.test_server_java_jfr import (
    _server as java_server,
)
from tests.mcp.test_server_native_pthread import (
    _FakeNativeLauncher,
)
from tests.mcp.test_server_native_pthread import (
    _server as native_server,
)
from tests.mcp.test_server_runtime_lock_docker import _four_adapter_server
from tests.unit.test_docker_comparison import (
    _benchmark,
    _bind_measurement_image,
    _measurement_pair,
)

import perflens.mcp.server as server_module
from perflens.contracts.artifacts import AnalysisArtifact, BenchmarkArtifact
from perflens.contracts.docker import ContainerMeasurementArtifact
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks import import_runtime_lock_ndjson
from perflens.runtime_locks.cpython_launcher import (
    CpythonLaunchRequest,
    CpythonLaunchResult,
    CpythonThreadingLauncher,
)
from perflens.runtime_locks.go_pprof_converter import GoProfileKind
from perflens.runtime_locks.go_pprof_launcher import (
    GoPprofLauncher,
    GoPprofLaunchRequest,
    GoPprofLaunchResult,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrLaunchFailure,
    JavaJfrLaunchRequest,
    JavaJfrLaunchResult,
    JavaJfrRetainedEvidence,
)
from perflens.runtime_locks.native_launcher import NativeLaunchRequest, NativeLaunchResult
from perflens.runtime_locks.supervisor import RuntimeSupervisorClient

_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
_FIXTURE = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"


def _structured(result: object) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    return cast(dict[str, Any], structured)


async def _authorize_host_session(
    client: Client,
    *,
    adapter: str,
    semantics: str,
    executable: str,
    profile_kind: GoProfileKind = "mutex",
) -> dict[str, Any]:
    request: dict[str, object] = {
        "target_scope": "host_launched_workload",
        "allowed_adapters": [adapter],
        "allowed_semantics": [semantics],
        "executable": executable,
        "arguments": [],
    }
    if adapter == "go_pprof":
        request["profile_kind"] = profile_kind
    previewed = await client.call_tool(
        "preview_runtime_lock_session",
        request,
    )
    assert not previewed.is_error, previewed.content
    preview = _structured(previewed)
    authorized = await client.call_tool(
        "authorize_runtime_lock_session",
        {
            "preview_id": preview["preview_id"],
            "preview_content_sha256": preview["content_sha256"],
            "authorization_summary_sha256": preview["authorization_summary_sha256"],
            "authorization": _AUTHORIZATION,
        },
    )
    assert not authorized.is_error, authorized.content
    return _structured(authorized)


def test_preview_rejects_ambiguous_host_and_import_scopes(tmp_path: Path) -> None:
    server, _project, artifacts, launchers = native_server(tmp_path)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            invalid_requests = (
                (
                    {
                        "target_scope": "host_launched_workload",
                        "allowed_adapters": ["native_pthread"],
                        "allowed_semantics": ["exact"],
                        "executable": "workload",
                        "target_pid": 42,
                    },
                    "cannot also attach",
                ),
                (
                    {
                        "target_scope": "controlled_import",
                        "allowed_adapters": ["generic_ndjson_import"],
                        "allowed_semantics": ["exact"],
                        "executable": "workload",
                    },
                    "cannot bind an executable",
                ),
            )
            for request, message in invalid_requests:
                rejected = await client.call_tool("preview_runtime_lock_session", request)
                assert rejected.is_error
                assert message in str(rejected.content)

    asyncio.run(exercise())
    assert launchers == []
    assert not list(artifacts.glob("*.runtime-lock-preview.json"))


@pytest.mark.parametrize(
    ("value", "message"),
    (
        ("", "Runtime Lock workload executable path is invalid"),
        (
            "/tmp/workload",
            "Runtime Lock workload executable must be one normalized project-relative path",
        ),
    ),
)
@pytest.mark.parametrize(
    "stage",
    ("runtime_lock_authorization", "runtime_lock_collection"),
)
def test_runtime_lock_executable_path_errors_are_adapter_neutral_and_stage_specific(
    tmp_path: Path,
    value: str,
    message: str,
    stage: Literal["runtime_lock_authorization", "runtime_lock_collection"],
) -> None:
    with pytest.raises(PerfLensError) as captured:
        server_module._runtime_lock_project_executable(tmp_path, value, stage=stage)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert captured.value.stage == stage
    assert captured.value.message == message
    assert captured.value.recoverable is True
    assert "Native pthread" not in captured.value.message


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("duration_limit", "authorized duration"),
        ("missing_exit", "exit status is unavailable"),
        ("nonzero_exit", "exited unsuccessfully"),
        ("replay_mismatch", "replay differs"),
    ),
)
def test_cpython_collection_failures_are_terminal_and_leave_no_public_run(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    server, _project, artifacts, _launchers = cpython_server(
        tmp_path,
        runtime_supervisor_client,
    )
    original_launch = CpythonThreadingLauncher.launch
    original_replay = server_module.verify_cpython_threading_replay

    def launch(
        self: CpythonThreadingLauncher,
        script: Path,
        request: CpythonLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> CpythonLaunchResult:
        result = original_launch(
            self,
            script,
            request,
            expected_target_identity_sha256=expected_target_identity_sha256,
        )
        if failure == "duration_limit":
            return replace(result, termination_reason="duration_limit")
        if failure == "missing_exit":
            return replace(result, exit_code=None)
        if failure == "nonzero_exit":
            return replace(result, exit_code=7)
        return result

    def verify_replay(*args: object, **kwargs: object) -> object:
        if failure == "replay_mismatch":
            return None
        return cast(Any, original_replay)(*args, **kwargs)

    monkeypatch.setattr(CpythonThreadingLauncher, "launch", launch)
    monkeypatch.setattr(server_module, "verify_cpython_threading_replay", verify_replay)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            session = await _authorize_host_session(
                client,
                adapter="cpython_threading",
                semantics="exact",
                executable="workload.py",
            )
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 500,
                },
            )
            assert rejected.is_error
            assert message in str(rejected.content)

    asyncio.run(exercise())
    assert not list(artifacts.glob("*.runtime-lock-run.json"))
    states = [_structured_session(path) for path in artifacts.glob("*.runtime-lock-session.json")]
    assert any(item["state"] in {"failed", "exhausted"} for item in states)


def test_cpython_target_replacement_revokes_without_launching(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    server, project, artifacts, launchers = cpython_server(
        tmp_path,
        runtime_supervisor_client,
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            session = await _authorize_host_session(
                client,
                adapter="cpython_threading",
                semantics="exact",
                executable="workload.py",
            )
            script = project / "workload.py"
            script.write_text("raise SystemExit(7)\n", encoding="utf-8")
            script.chmod(0o600)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 500,
                },
            )
            assert rejected.is_error
            assert "differs from the authorized Preview" in str(rejected.content)

    asyncio.run(exercise())
    assert len(launchers) == 1
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def _structured_session(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("launch_failure", "synthetic retained JFR failure"),
        ("duration_limit", "authorized duration"),
        ("nonzero_exit", "exited unsuccessfully"),
        ("source_mismatch", "identity or digest changed"),
        ("replay_mismatch", "replay differs"),
        ("timing_mismatch", "timing receipt is inconsistent"),
        ("active_overrun", "active-time reservation"),
    ),
)
def test_java_collection_failures_are_charged_and_never_publish_a_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    server, _project, artifacts, _bridge, _launchers = java_server(tmp_path)
    original_launch = _FakeJavaJfrLauncher.launch
    original_replay = server_module.verify_java_jfr_replay

    def launch(
        self: _FakeJavaJfrLauncher,
        executable_jar: Path,
        request: JavaJfrLaunchRequest,
        *,
        expected_target_identity_sha256: str,
        expected_arguments_sha256: str,
    ) -> JavaJfrLaunchResult:
        result = original_launch(
            self,
            executable_jar,
            request,
            expected_target_identity_sha256=expected_target_identity_sha256,
            expected_arguments_sha256=expected_arguments_sha256,
        )
        if failure == "launch_failure":
            retained = JavaJfrRetainedEvidence(
                private_directory_path=result.private_directory_path,
                private_directory_device=result.private_directory_device,
                private_directory_inode=result.private_directory_inode,
                recording_path=result.recording_path,
                recording_device=result.recording_device,
                recording_inode=result.recording_inode,
                recording_sha256=result.recording_sha256,
                recording_size=result.recording_size,
                json_path=result.json_path,
                json_device=result.json_device,
                json_inode=result.json_inode,
                json_sha256=result.json_sha256,
                json_size=result.json_size,
            )
            raise JavaJfrLaunchFailure(
                code=server_module.ErrorCode.EXTERNAL_TOOL_FAILED,
                stage="java_jfr_launcher",
                message="synthetic retained JFR failure",
                recoverable=True,
                retained_evidence=retained,
                accounted_active_seconds=1,
            )
        if failure == "duration_limit":
            return replace(result, termination_reason="duration_limit")
        if failure == "nonzero_exit":
            return replace(result, exit_code=9)
        if failure == "source_mismatch":
            return replace(result, json_sha256="0" * 64)
        if failure == "timing_mismatch":
            return replace(result, accounted_active_seconds=2)
        if failure == "active_overrun":
            started = datetime.fromisoformat(result.started_at)
            return replace(
                result,
                finished_at=(started + timedelta(seconds=4)).isoformat(),
                accounted_active_seconds=4,
            )
        return result

    def verify_replay(*args: object, **kwargs: object) -> object:
        if failure == "replay_mismatch":
            return None
        return cast(Any, original_replay)(*args, **kwargs)

    monkeypatch.setattr(_FakeJavaJfrLauncher, "launch", launch)
    monkeypatch.setattr(server_module, "verify_java_jfr_replay", verify_replay)

    async def exercise() -> None:
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
            assert message in str(rejected.content)

    asyncio.run(exercise())
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("missing_exit", "identity became unavailable"),
        ("nonzero_exit", "exited unsuccessfully"),
        ("timing_mismatch", "timing receipt is inconsistent"),
        ("active_overrun", "active-time reservation"),
    ),
)
def test_native_collection_receipt_failures_close_the_single_use_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    server, _project, artifacts, _launchers = native_server(tmp_path)
    original_launch = _FakeNativeLauncher.launch

    def launch(
        self: _FakeNativeLauncher,
        executable: Path,
        request: NativeLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> NativeLaunchResult:
        result = original_launch(
            self,
            executable,
            request,
            expected_target_identity_sha256=expected_target_identity_sha256,
        )
        if failure == "missing_exit":
            return replace(result, exit_code=None)
        if failure == "nonzero_exit":
            return replace(result, exit_code=5)
        if failure == "timing_mismatch":
            return replace(result, accounted_active_seconds=2)
        started = datetime.fromisoformat(result.started_at)
        return replace(
            result,
            finished_at=(started + timedelta(seconds=4)).isoformat(),
            accounted_active_seconds=4,
        )

    monkeypatch.setattr(_FakeNativeLauncher, "launch", launch)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            session = await _authorize_host_session(
                client,
                adapter="native_pthread",
                semantics="exact",
                executable="workload",
            )
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "exact",
                    "duration_seconds": 3,
                    "max_events": 20,
                },
            )
            assert rejected.is_error
            assert message in str(rejected.content)

    asyncio.run(exercise())
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_native_dispatch_rejects_go_only_parameters_before_launch(tmp_path: Path) -> None:
    server, _project, artifacts, launchers = native_server(tmp_path)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            for request, message in (
                (
                    {
                        "measurement_semantics": "cumulative",
                        "profile_kind": "mutex",
                    },
                    "supported only by the Go pprof Adapter",
                ),
                (
                    {
                        "measurement_semantics": "exact",
                        "profile_kind": "block",
                    },
                    "profile_kind is valid only",
                ),
            ):
                session = await _authorize_host_session(
                    client,
                    adapter="native_pthread",
                    semantics="exact",
                    executable="workload",
                )
                rejected = await client.call_tool(
                    "collect_runtime_lock_evidence",
                    {
                        "session_id": session["session_id"],
                        "duration_seconds": 3,
                        "max_events": 20,
                        **request,
                    },
                )
                assert rejected.is_error
                assert message in str(rejected.content)

    asyncio.run(exercise())
    assert len(launchers) == 1
    assert launchers[0].launch_count == 0
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


@pytest.mark.timeout(90)
@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("target_replaced", "not a readable Go executable"),
        ("duration_limit", "authorized duration"),
        ("missing_exit", "exit status is unavailable"),
        ("nonzero_exit", "exited unsuccessfully"),
        ("replay_mismatch", "replay differs"),
    ),
)
def test_go_collection_failures_are_terminal_and_private_profiles_stay_bounded(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    server, project, artifacts = go_server(tmp_path, runtime_supervisor_client)
    original_launch = GoPprofLauncher.launch
    original_replay = server_module.verify_go_pprof_replay

    def launch(
        self: GoPprofLauncher,
        executable: Path,
        request: GoPprofLaunchRequest,
        *,
        expected_target_identity_sha256: str,
    ) -> GoPprofLaunchResult:
        result = original_launch(
            self,
            executable,
            request,
            expected_target_identity_sha256=expected_target_identity_sha256,
        )
        if failure == "duration_limit":
            return replace(result, termination_reason="duration_limit")
        if failure == "missing_exit":
            return replace(result, exit_code=None)
        if failure == "nonzero_exit":
            return replace(result, exit_code=4)
        return result

    def verify_replay(*args: object, **kwargs: object) -> object:
        if failure == "replay_mismatch":
            return None
        return cast(Any, original_replay)(*args, **kwargs)

    monkeypatch.setattr(GoPprofLauncher, "launch", launch)
    monkeypatch.setattr(server_module, "verify_go_pprof_replay", verify_replay)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            session = await _authorize_host_session(
                client,
                adapter="go_pprof",
                semantics="cumulative",
                executable="workload",
            )
            if failure == "target_replaced":
                workload = project / "workload"
                workload.write_bytes(b"replaced after authorization\n")
                workload.chmod(0o700)
            rejected = await client.call_tool(
                "collect_runtime_lock_evidence",
                {
                    "session_id": session["session_id"],
                    "measurement_semantics": "cumulative",
                    "duration_seconds": 10,
                    "max_events": 500,
                    "profile_kind": cast(GoProfileKind, "mutex"),
                },
            )
            assert rejected.is_error
            assert message in str(rejected.content)

    asyncio.run(exercise())
    assert not list(artifacts.glob("*.runtime-lock-run.json"))


def test_runtime_lock_query_tools_cover_every_projection_and_sort(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    store = ArtifactStore(artifact_root, PathPolicy((tmp_path,)), allow_writes=True)
    with _FIXTURE.open("rb") as source:
        evidence = import_runtime_lock_ndjson(source)
    store.save(evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence")
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = _structured(
                await client.call_tool(
                    "analyze_runtime_lock_evidence",
                    {"runtime_lock_evidence_id": evidence.runtime_lock_evidence_id},
                )
            )
            analysis_id = cast(str, analyzed["artifact_id"])
            for projection in (
                "lock",
                "execution_context",
                "call_path",
                "wait_outcome",
                "lock_kind",
            ):
                for sort_by in (
                    "observed_or_estimated_wait_ns",
                    "exact_wait_count",
                    "thresholded_wait_count",
                    "sampled_observation_count",
                    "cumulative_observation_count",
                    "exact_hold_ns",
                    "owner_observed_count",
                ):
                    page = _structured(
                        await client.call_tool(
                            "list_runtime_lock_hotspots",
                            {
                                "runtime_lock_analysis_id": analysis_id,
                                "projection": projection,
                                "sort_by": sort_by,
                                "cursor": 0,
                                "limit": 1,
                            },
                        )
                    )
                    assert page["projection"] == projection
                    assert page["total_items"] >= len(cast(list[object], page["items"]))
            paths = _structured(
                await client.call_tool(
                    "get_runtime_lock_call_paths",
                    {"runtime_lock_analysis_id": analysis_id, "cursor": 1, "limit": 1},
                )
            )
            assert paths["cursor"] == 1
            diagnosis = _structured(
                await client.call_tool(
                    "build_runtime_lock_diagnosis_bundle",
                    {"runtime_lock_analysis_id": analysis_id},
                )
            )
            assert diagnosis["summary"]["runtime"] == "python"

    asyncio.run(exercise())


def test_docker_optimization_comparison_mcp_persists_the_complete_evidence_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, runtime, _adapter, project = _four_adapter_server(tmp_path, monkeypatch)
    benchmarks = (
        _benchmark("mcp-baseline", (100, 101, 99), commit="baseline"),
        _benchmark("mcp-candidate", (120, 121, 119), commit="candidate"),
    )
    (tmp_path / "comparison-evidence").mkdir()
    _, _, _, _, measurements, analyses = _measurement_pair(
        tmp_path / "comparison-evidence",
        benchmarks=benchmarks,
    )

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {"allowed_modes": ["stat", "record"]},
                )
            )
            authorized = _structured(
                await client.call_tool(
                    "authorize_docker_optimization_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview["authorization_summary_sha256"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            session_id = cast(str, authorized["session_id"])
            baseline_reference = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session_id,
                        "build_kind": "baseline",
                        "candidate_round": 0,
                    },
                )
            )
            (project / "src/app").write_bytes(b"candidate treatment")
            candidate_reference = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session_id,
                        "build_kind": "candidate",
                        "candidate_round": 1,
                    },
                )
            )
            baseline_build = runtime.build_result(
                session_id,
                cast(str, baseline_reference["artifact_id"]),
            ).artifact
            candidate_build = runtime.build_result(
                session_id,
                cast(str, candidate_reference["artifact_id"]),
            ).artifact
            bound_measurements = (
                _bind_measurement_image(measurements[0], baseline_build.final_image_digest),
                _bind_measurement_image(measurements[1], candidate_build.final_image_digest),
            )

            def load_measurement(
                _store: ArtifactStore,
                artifact_id: str,
            ) -> ContainerMeasurementArtifact:
                return (
                    bound_measurements[0]
                    if artifact_id == bound_measurements[0].measurement_id
                    else bound_measurements[1]
                )

            def load_analysis(
                _store: ArtifactStore,
                artifact_id: str,
            ) -> AnalysisArtifact:
                return analyses[0] if artifact_id == analyses[0].analysis_id else analyses[1]

            def load_benchmark(
                _store: ArtifactStore,
                artifact_id: str,
            ) -> BenchmarkArtifact:
                return benchmarks[0] if artifact_id == benchmarks[0].benchmark_id else benchmarks[1]

            monkeypatch.setattr(ArtifactStore, "load_container_measurement", load_measurement)
            monkeypatch.setattr(ArtifactStore, "load_analysis", load_analysis)
            monkeypatch.setattr(ArtifactStore, "load_benchmark", load_benchmark)
            compared = await client.call_tool(
                "compare_docker_optimization_iterations",
                {
                    "session_id": session_id,
                    "baseline_build_id": baseline_build.build_id,
                    "candidate_build_id": candidate_build.build_id,
                    "baseline_measurement_id": bound_measurements[0].measurement_id,
                    "candidate_measurement_id": bound_measurements[1].measurement_id,
                    "baseline_analysis_id": analyses[0].analysis_id,
                    "candidate_analysis_id": analyses[1].analysis_id,
                    "baseline_benchmark_id": benchmarks[0].benchmark_id,
                    "candidate_benchmark_id": benchmarks[1].benchmark_id,
                },
            )
            assert not compared.is_error, compared.content
            reference = _structured(compared)
            assert reference["artifact_type"] == "docker-optimization-iteration"
            assert reference["summary"]["conclusion"] == "verified_improvement"

    asyncio.run(exercise())
    artifact_root = tmp_path / "artifacts"
    assert len(list(artifact_root.glob("*.profile-comparison.json"))) == 1
    assert len(list(artifact_root.glob("*.benchmark-comparison.json"))) == 1
    assert len(list(artifact_root.glob("*.container-matched-comparison.json"))) == 1
    assert len(list(artifact_root.glob("*.docker-optimization-iteration.json"))) == 1


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("runtime_timeout", "exceeds the selected Runtime Lock evidence window"),
        ("go_without_adapter", "cannot be selected without the Go Runtime Lock Adapter"),
        ("record_budget", "exceeds its mode-specific budget"),
    ),
)
def test_docker_runtime_lock_collection_rejects_before_creating_a_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    server, runtime, adapter, _project = _four_adapter_server(tmp_path, monkeypatch)

    async def exercise() -> None:
        async with Client(cast(Any, server)) as client:
            preview_request: dict[str, object] = {"allowed_modes": ["stat", "record"]}
            if case == "runtime_timeout":
                preview_request["runtime_lock_adapters"] = ["native_pthread"]
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    preview_request,
                )
            )
            authorized = _structured(
                await client.call_tool(
                    "authorize_docker_optimization_session",
                    {
                        "preview_id": preview["preview_id"],
                        "preview_content_sha256": preview["content_sha256"],
                        "authorization_summary_sha256": preview["authorization_summary_sha256"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            session_id = cast(str, authorized["session_id"])
            request: dict[str, object] = {
                "session_id": session_id,
                "build_id": "docker-build-" + "a" * 20,
                "mode": "stat",
                "duration_seconds": 1,
                "workload_timeout_seconds": 3,
                "max_output_bytes": 1 << 20,
            }
            if case == "runtime_timeout":
                request.update(
                    runtime_lock_adapter="native_pthread",
                    runtime_lock_max_events=100,
                    workload_timeout_seconds=31,
                )
            elif case == "go_without_adapter":
                request["runtime_lock_go_profile_kind"] = "mutex"
            else:
                request.update(mode="record", duration_seconds=31)
            rejected = await client.call_tool(
                "collect_docker_optimization_workload",
                request,
            )
            assert rejected.is_error
            assert message in str(rejected.content)
            assert runtime.snapshot(session_id).workload_runs_used == 0

    asyncio.run(exercise())
    assert adapter.cleaned == []


def test_docker_runtime_lock_inner_failure_is_charged_and_revokes_internal_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    internal_session_id = "container-session-" + "a" * 20
    revoked: list[str] = []

    class FailingExistingDockerRuntime:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def authorize_optimization_build(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> SimpleNamespace:
            return SimpleNamespace(session_id=internal_session_id)

        def prepare_managed_run(self, *_args: object, **_kwargs: object) -> None:
            raise server_module.PerfLensError(
                server_module.ErrorCode.EXTERNAL_TOOL_FAILED,
                "runtime_lock_atomicity_test",
                "Synthetic inner managed-runtime failure",
                recoverable=True,
            )

        def revoke(self, session_id: str) -> None:
            revoked.append(session_id)

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        server_module,
        "ExistingDockerRuntime",
        FailingExistingDockerRuntime,
    )
    server, runtime, _adapter, _project = _four_adapter_server(tmp_path, monkeypatch)

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
                        "authorization_summary_sha256": preview["authorization_summary_sha256"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
                        ),
                    },
                )
            )
            session_id = cast(str, session["session_id"])
            baseline = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session_id,
                        "build_kind": "baseline",
                        "candidate_round": 0,
                    },
                )
            )
            failed = await client.call_tool(
                "collect_docker_optimization_workload",
                {
                    "session_id": session_id,
                    "build_id": baseline["artifact_id"],
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 3,
                    "max_output_bytes": 1 << 20,
                    "runtime_lock_adapter": "native_pthread",
                    "runtime_lock_max_events": 100,
                },
            )
            assert failed.is_error
            assert "Synthetic inner managed-runtime failure" in str(failed.content)
            current = runtime.snapshot(session_id)
            assert current.workload_runs_used == 1
            assert current.runtime_lock_status == "unavailable"

    asyncio.run(exercise())
    assert revoked == [internal_session_id]


@pytest.mark.parametrize("full_configuration", (False, True))
def test_runtime_lock_mcp_main_wires_default_and_explicit_security_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    full_configuration: bool,
) -> None:
    allowed = tmp_path / "allowed"
    secondary = tmp_path / "secondary"
    artifacts = allowed / "artifacts"
    allowed.mkdir()
    secondary.mkdir()
    captured: list[ServerConfig] = []
    run_transports: list[str] = []

    class FakeServer:
        def run(self, transport: str) -> None:
            run_transports.append(transport)

    def fake_create_server(config: ServerConfig) -> FakeServer:
        captured.append(config)
        return FakeServer()

    arguments = [
        "perflens-mcp",
        "--allowed-root",
        str(allowed),
        "--allowed-root",
        str(secondary),
        "--artifact-root",
        str(artifacts),
    ]
    if full_configuration:
        arguments.extend(
            [
                "--allow-writes",
                "--allow-process-execution",
                "--allow-active-collection",
                "--allow-pid-attach",
                "--allow-automatic-collection",
                "--allow-project-execution",
                "--allow-docker-targets",
                "--allow-docker-optimization",
                "--allow-runtime-locks",
                "--docker-project-config",
                str(allowed / "container-workload.toml"),
                "--runtime-lock-project-config",
                str(allowed / "runtime-locks.toml"),
                "--docker-runtime-root",
                str(allowed / "docker-runtime"),
                "--docker-builder-policy",
                str(allowed / "builder.toml"),
                "--docker-gate-path",
                str(allowed / "container-gate"),
                "--collector-socket",
                str(allowed / "collector.sock"),
                "--automatic-mode",
                "stat",
                "--automatic-mode",
                "lock",
                "--automatic-max-duration-seconds",
                "7.5",
                "--automatic-max-frequency-hz",
                "77",
                "--automatic-max-output-bytes",
                "4096",
                "--automatic-plan-ttl-seconds",
                "45",
                "--disable-automatic-software-fallback",
                "--perf-path",
                str(allowed / "perf"),
                "--max-artifact-bytes",
                "8192",
            ]
        )
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(server_module, "create_server", fake_create_server)

    server_module.main()

    assert run_transports == ["stdio"]
    assert len(captured) == 1
    config = captured[0]
    assert config.allowed_roots == (allowed, secondary)
    assert config.artifact_root == artifacts
    assert config.allow_runtime_locks is full_configuration
    assert config.allow_docker_optimization is full_configuration
    assert config.automatic_collection_policy.enabled is full_configuration
    assert config.automatic_collection_policy.allowed_modes == (
        ("stat", "lock") if full_configuration else ("record", "stat")
    )
    assert config.automatic_collection_policy.max_duration_seconds == (
        7.5 if full_configuration else 30.0
    )
    assert config.automatic_collection_policy.allow_software_fallback is (not full_configuration)
    assert config.max_artifact_bytes == (8192 if full_configuration else 128 << 20)
