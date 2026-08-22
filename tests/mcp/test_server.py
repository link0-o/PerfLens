from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.client import Client
from tests.support.docker import make_container_resource_context
from tests.support.trace import make_scheduler_trace_evidence

from perflens.application.evidence import contract_content_sha256
from perflens.collection.collector import ACTIVE_COLLECTION_AUTHORIZATION
from perflens.collection.planning import (
    AutomaticCollectionPolicy,
    CollectionPlanRequest,
)
from perflens.contracts.artifacts import (
    BenchmarkArtifact,
    BenchmarkComparison,
    BenchmarkEnvironment,
    BenchmarkMetric,
    CollectionArtifact,
    CollectionPlanArtifact,
    ContainerCollectionCgroupBinding,
    ContainerCollectionNamespaceBinding,
    ContainerCollectionTargetBinding,
    PerfStatMetric,
    ProfileComparison,
)
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerMatchedComparisonArtifact,
    ContainerNamespaceIdentity,
    ContainerOptimizationSessionArtifact,
    ContainerResourceLimits,
    ContainerRunArtifact,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
)
from perflens.docker.capability import discover_docker_capability
from perflens.docker.project_config import render_default_docker_project_policy
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy


def _docker_target() -> ContainerTargetArtifact:
    provisional = ContainerTargetArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        target_id="container-target-" + "4" * 20,
        created_at="2026-08-21T00:00:00+00:00",
        target_kind="existing_container",
        container_identity_sha256="5" * 64,
        image_identity_sha256="6" * 64,
        container_pid=12,
        host_pid=1234,
        host_uid=os.geteuid(),
        host_start_time_ticks=5678,
        executable_name="worker",
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCgroupIdentity(inode=105, identity_sha256="7" * 64),
        uid_mapping="rootless_same_uid",
        adapter_recipe_id="local-docker-read-v1",
        adapter_sha256="8" * 64,
        identity_fingerprint="9" * 64,
        content_sha256="0" * 64,
    )
    return ContainerTargetArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _fake_docker_plan() -> CollectionPlanArtifact:
    return CollectionPlanArtifact(
        schema_version="1.0",
        plan_id="plan-" + "a" * 20,
        mode="stat",
        target_type="pid",
        target_pid=1234,
        target_uid=os.geteuid(),
        target_start_time_ticks=5678,
        backend="privileged_broker",
        duration_seconds=1,
        events=("task-clock",),
        requested_event_source="software_only",
        max_output_bytes=1000,
        expires_at="2026-08-21T01:00:00+00:00",
        policy_status="allowed",
        required_privilege="cap_perfmon",
    )


def _fake_docker_collection(
    tmp_path: Path,
    target: ContainerTargetArtifact,
) -> CollectionArtifact:
    binding = ContainerCollectionTargetBinding(
        target_id=target.target_id,
        target_kind=target.target_kind,
        target_content_sha256=target.content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        image_identity_sha256=target.image_identity_sha256,
        identity_fingerprint=target.identity_fingerprint,
        container_pid=target.container_pid,
        host_pid=target.host_pid,
        host_uid=target.host_uid,
        host_start_time_ticks=target.host_start_time_ticks,
        executable_name=target.executable_name,
        namespace=ContainerCollectionNamespaceBinding(
            pid_namespace_inode=target.namespace.pid_namespace_inode,
            user_namespace_inode=target.namespace.user_namespace_inode,
            mount_namespace_inode=target.namespace.mount_namespace_inode,
            cgroup_namespace_inode=target.namespace.cgroup_namespace_inode,
        ),
        cgroup=ContainerCollectionCgroupBinding(
            inode=target.cgroup.inode,
            identity_sha256=target.cgroup.identity_sha256,
        ),
        uid_mapping=target.uid_mapping,
        rootful_risk_authorized=target.rootful_risk_authorized,
        adapter_recipe_id=target.adapter_recipe_id,
        adapter_sha256=target.adapter_sha256,
    )
    return CollectionArtifact(
        schema_version="1.0",
        collection_id="collection-" + "b" * 16,
        mode="stat",
        target_type="pid",
        target_argument_count=0,
        target_pid=1234,
        target_runtime="docker",
        container_target=binding,
        output_path=str(tmp_path / "fake.stat.csv"),
        output_sha256="c" * 64,
        output_bytes=120,
        output_format="perf_stat_delimited",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-21T00:00:00+00:00",
        finished_at="2026-08-21T00:00:01+00:00",
        duration_seconds=1,
        events=("task-clock",),
        requested_event_source="software_only",
        actual_event_source="software",
        evidence_limitations=(
            "instructions-per-cycle unavailable",
            "hardware cache-miss evidence unavailable",
            "hardware branch-miss evidence unavailable",
        ),
        collector_config_sha256="a" * 64,
        collector_privilege_mode="paranoid3_helper",
        collector_feature_profile="full_diagnostics",
        host_kernel_release="6.12-test",
        perf_executable_sha256="b" * 64,
        metrics=(
            PerfStatMetric(
                event="task-clock",
                value=1000,
                unit="msec",
                status="measured",
            ),
        ),
    )


def _managed_workload() -> ContainerWorkloadSpecArtifact:
    treatment_path_sha256 = hashlib.sha256(
        b"perflens-container-treatment-path-v1\0workload.py"
    ).hexdigest()
    provisional = ContainerWorkloadSpecArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        workload_spec_id="container-workload-" + "f" * 20,
        created_at="2026-08-21T00:00:00+00:00",
        project_identity_sha256="1" * 64,
        image_digest="sha256:" + "6" * 64,
        container_gate_sha256="2" * 64,
        entrypoint="/usr/bin/python3",
        working_directory="/workspace",
        container_user=f"{os.geteuid()}:{os.getegid()}",
        resources=ContainerResourceLimits(cpus=1, memory_bytes=64 << 20, pids=32),
        allowed_modes=("stat",),
        authorization_mode="per_run",
        max_workload_runs=1,
        correctness_command_sha256="4" * 64,
        benchmark_output_contract_sha256="6" * 64,
        treatment_path_sha256=(treatment_path_sha256,),
        workload_fingerprint="3" * 64,
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _managed_docker_target() -> ContainerTargetArtifact:
    existing = _docker_target()
    provisional = ContainerTargetArtifact.model_validate(
        {
            **existing.model_dump(mode="json"),
            "target_kind": "managed_temporary_container",
            "adapter_recipe_id": "local-docker-managed-v1",
            "identity_fingerprint": "d" * 64,
            "content_sha256": "0" * 64,
        }
    )
    return ContainerTargetArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _managed_session(
    workload_spec_sha256: str,
    *,
    state: str = "active",
) -> ContainerOptimizationSessionArtifact:
    inactive = None if state == "active" else "Docker authorization budget was exhausted."
    provisional = ContainerOptimizationSessionArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        session_id="container-session-" + "e" * 20,
        created_at="2026-08-21T00:00:00+00:00",
        expires_at="2026-08-21T02:00:00+00:00",
        target_kind="managed_temporary_container",
        authorization_mode="per_run",
        project_identity_sha256="1" * 64,
        client_connection_identity_sha256="2" * 64,
        authorization_receipt_sha256="3" * 64,
        workload_spec_sha256=workload_spec_sha256,
        allowed_modes=("stat",),
        state=cast(Any, state),
        max_workload_runs=1,
        workload_runs_used=1 if state != "active" else 0,
        max_active_seconds=1200,
        active_seconds_used=1 if state != "active" else 0,
        max_evidence_bytes=1 << 20,
        evidence_bytes_used=120 if state != "active" else 0,
        instance_count=1 if state != "active" else 0,
        invalidation_reason=inactive,
        content_sha256="0" * 64,
    )
    return ContainerOptimizationSessionArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _managed_run_artifact(
    resource_context_id: str,
    workload_spec_sha256: str,
) -> ContainerRunArtifact:
    provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        run_id="container-run-" + "5" * 20,
        created_at="2026-08-21T00:01:01+00:00",
        session_id="container-session-" + "e" * 20,
        workload_spec_sha256=workload_spec_sha256,
        container_identity_sha256="5" * 64,
        image_identity_sha256="6" * 64,
        target_identity_sha256="d" * 64,
        container_pid=12,
        host_pid=1234,
        host_start_time_ticks=5678,
        started_at="2026-08-21T00:00:01+00:00",
        finished_at="2026-08-21T00:01:01+00:00",
        status="exited",
        exit_code=0,
        collection_ids=("collection-" + "b" * 16,),
        resource_context_id=resource_context_id,
        cleanup_status="removed",
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _structured(result: Any) -> dict[str, Any]:
    payload = result.structured_content
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_tools_have_typed_schemas_annotations_and_permissions(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            result = await client.list_tools()
            tools = {tool.name: tool for tool in result.tools}
            assert set(tools) == {
                "analyze_profile",
                "verify_analysis",
                "list_hotspots",
                "get_hotspot_details",
                "get_call_paths",
                "classify_hotspots",
                "build_diagnosis_bundle",
                "read_artifact_page",
                "resolve_source",
                "get_source_context",
                "analyze_benchmark",
                "compare_profiles",
                "compare_benchmarks",
                "compare_container_measurements",
                "collect_profile",
                "inspect_collection_capabilities",
                "inspect_docker_capability",
                "discover_docker_processes",
                "resolve_docker_target",
                "authorize_docker_session",
                "authorize_managed_docker_session",
                "revoke_docker_session",
                "collect_docker_target",
                "collect_managed_docker_workload",
                "plan_automatic_collection",
                "execute_collection_plan",
                "collect_project_workload",
                "analyze_collection",
                "analyze_trace_evidence",
                "verify_trace_analysis",
            }
            for tool in tools.values():
                assert tool.input_schema["type"] == "object"
                assert tool.output_schema is not None
                assert tool.annotations is not None
                assert tool.annotations.open_world_hint is False
            read_annotations = tools["list_hotspots"].annotations
            write_annotations = tools["analyze_profile"].annotations
            assert read_annotations is not None
            assert write_annotations is not None
            assert read_annotations.read_only_hint is True
            assert write_annotations.read_only_hint is False
            assert tools["analyze_profile"].meta == {"perflens/permission": "WRITES_ARTIFACTS"}
            active_annotations = tools["collect_profile"].annotations
            assert active_annotations is not None
            assert active_annotations.destructive_hint is True
            assert active_annotations.idempotent_hint is False
            assert tools["collect_profile"].meta == {"perflens/permission": "ACTIVE_COLLECTION"}
            capability_annotations = tools["inspect_collection_capabilities"].annotations
            docker_annotations = tools["inspect_docker_capability"].annotations
            plan_annotations = tools["plan_automatic_collection"].annotations
            assert capability_annotations is not None
            assert docker_annotations is not None
            assert plan_annotations is not None
            assert capability_annotations.read_only_hint is True
            assert docker_annotations.read_only_hint is True
            assert plan_annotations.read_only_hint is True
            assert tools["execute_collection_plan"].meta == {
                "perflens/permission": "AUTOMATIC_COLLECTION"
            }
            assert tools["authorize_docker_session"].meta == {
                "perflens/permission": "DOCKER_AUTHORIZATION"
            }
            assert tools["revoke_docker_session"].meta == {
                "perflens/permission": "DOCKER_AUTHORIZATION"
            }
            assert tools["authorize_managed_docker_session"].meta == {
                "perflens/permission": "DOCKER_AUTHORIZATION"
            }
            existing_authorization_annotations = tools[
                "authorize_docker_session"
            ].annotations
            managed_authorization_annotations = tools[
                "authorize_managed_docker_session"
            ].annotations
            assert existing_authorization_annotations is not None
            assert managed_authorization_annotations is not None
            assert existing_authorization_annotations.destructive_hint is True
            assert managed_authorization_annotations.destructive_hint is True
            assert tools["collect_docker_target"].meta == {
                "perflens/permission": "DOCKER_COLLECTION"
            }
            assert tools["collect_managed_docker_workload"].meta == {
                "perflens/permission": "DOCKER_COLLECTION"
            }
            assert tools["compare_container_measurements"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            docker_authorization = tools["authorize_docker_session"].input_schema["properties"][
                "authorization"
            ]
            assert docker_authorization["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
            )
            managed_authorization = tools["authorize_managed_docker_session"].input_schema[
                "properties"
            ]
            assert set(managed_authorization) == {"authorization"}
            assert managed_authorization["authorization"]["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
            )
            managed_collection = tools["collect_managed_docker_workload"].input_schema["properties"]
            assert not {
                "image",
                "entrypoint",
                "arguments",
                "mounts",
                "network",
                "docker_options",
                "treatment_paths",
            }.intersection(managed_collection)
            assert tools["collect_project_workload"].meta == {
                "perflens/permission": "PROJECT_EXECUTION"
            }
            project_authorization = tools["collect_project_workload"].input_schema["properties"][
                "authorization"
            ]
            assert project_authorization["const"] == "I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION"
            assert tools["analyze_collection"].meta == {"perflens/permission": "PROCESS_EXECUTION"}
            assert tools["analyze_trace_evidence"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["verify_trace_analysis"].meta == {"perflens/permission": "READ_ONLY"}

    asyncio.run(exercise())


def test_compare_container_measurements_tool_stores_only_verified_comparison_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    requested: list[tuple[str, str]] = []
    baseline_measurement = SimpleNamespace(measurement_id="container-measurement-" + "1" * 20)
    candidate_measurement = SimpleNamespace(measurement_id="container-measurement-" + "2" * 20)
    baseline_analysis = SimpleNamespace(analysis_id="analysis-before")
    candidate_analysis = SimpleNamespace(analysis_id="analysis-after")
    baseline_benchmark = SimpleNamespace(benchmark_id="benchmark-before")
    candidate_benchmark = SimpleNamespace(benchmark_id="benchmark-after")
    profile_comparison = ProfileComparison(
        comparison_id="profile-comparison-" + "3" * 16,
        baseline_analysis_id="analysis-before",
        candidate_analysis_id="analysis-after",
        comparable=True,
        metadata_differences={},
        hotspot_deltas=(),
        call_path_deltas=(),
        dso_changes={},
        baseline_unresolved_percent=0,
        candidate_unresolved_percent=0,
        unresolved_delta_percent=0,
        warnings=(),
    )
    benchmark_comparison = BenchmarkComparison(
        comparison_id="benchmark-comparison-" + "4" * 16,
        baseline_benchmark_id="benchmark-before",
        candidate_benchmark_id="benchmark-after",
        comparable=True,
        condition_differences={},
        expected_variables={"commit": ("before", "after")},
        minimum_practical_impact_percent=1,
        metrics=(),
        warnings=(),
    )
    provisional = ContainerMatchedComparisonArtifact(
        schema_version="1.0",
        perflens_version="0.3.1",
        comparison_id="container-comparison-" + "5" * 20,
        created_at="2026-08-22T00:00:00+00:00",
        baseline_measurement_id=baseline_measurement.measurement_id,
        baseline_measurement_content_sha256="1" * 64,
        candidate_measurement_id=candidate_measurement.measurement_id,
        candidate_measurement_content_sha256="2" * 64,
        baseline_analysis_id="analysis-before",
        baseline_analysis_content_sha256="3" * 64,
        candidate_analysis_id="analysis-after",
        candidate_analysis_content_sha256="4" * 64,
        profile_comparison_id=profile_comparison.comparison_id,
        profile_comparison_content_sha256="5" * 64,
        baseline_benchmark_id="benchmark-before",
        baseline_benchmark_content_sha256="6" * 64,
        candidate_benchmark_id="benchmark-after",
        candidate_benchmark_content_sha256="7" * 64,
        benchmark_comparison_id=benchmark_comparison.comparison_id,
        benchmark_comparison_content_sha256="8" * 64,
        environment_match=True,
        treatment_changed=True,
        baseline_treatment_sha256=("9" * 64,),
        candidate_treatment_sha256=("a" * 64,),
        correctness_status="passed",
        resource_transfer_status="no_observed_regression",
        comparable=True,
        conclusion="verified_improvement",
        improved_metrics=("throughput",),
        allowed_conclusions=("Verified Improvement is evidence-bound.",),
        forbidden_conclusions=("No microarchitectural mechanism is proven.",),
        content_sha256="0" * 64,
    )
    comparison = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )

    def load_measurement(_store: ArtifactStore, artifact_id: str):
        requested.append(("measurement", artifact_id))
        return (
            baseline_measurement
            if artifact_id == baseline_measurement.measurement_id
            else candidate_measurement
        )

    def load_analysis(_store: ArtifactStore, artifact_id: str):
        requested.append(("analysis", artifact_id))
        return baseline_analysis if artifact_id == "analysis-before" else candidate_analysis

    def load_benchmark(_store: ArtifactStore, artifact_id: str):
        requested.append(("benchmark", artifact_id))
        return baseline_benchmark if artifact_id == "benchmark-before" else candidate_benchmark

    def fake_compare_profiles(*_args: Any, **_kwargs: Any) -> ProfileComparison:
        return profile_comparison

    def fake_compare_benchmarks(*_args: Any, **_kwargs: Any) -> BenchmarkComparison:
        return benchmark_comparison

    def fake_compare_containers(
        *_args: Any,
        **_kwargs: Any,
    ) -> ContainerMatchedComparisonArtifact:
        return comparison

    monkeypatch.setattr(ArtifactStore, "load_container_measurement", load_measurement)
    monkeypatch.setattr(ArtifactStore, "load_analysis", load_analysis)
    monkeypatch.setattr(ArtifactStore, "load_benchmark", load_benchmark)
    monkeypatch.setattr(
        "perflens.mcp.server.compare_profile_artifacts",
        fake_compare_profiles,
    )
    monkeypatch.setattr(
        "perflens.mcp.server.compare_benchmark_artifacts",
        fake_compare_benchmarks,
    )
    monkeypatch.setattr(
        "perflens.mcp.server.compare_container_measurements",
        fake_compare_containers,
    )
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "compare_container_measurements",
                {
                    "baseline_measurement_id": baseline_measurement.measurement_id,
                    "candidate_measurement_id": candidate_measurement.measurement_id,
                    "baseline_analysis_id": "analysis-before",
                    "candidate_analysis_id": "analysis-after",
                    "baseline_benchmark_id": "benchmark-before",
                    "candidate_benchmark_id": "benchmark-after",
                },
            )
            assert not result.is_error
            reference = _structured(result)
            assert reference["artifact_id"] == comparison.comparison_id
            assert reference["summary"]["conclusion"] == "verified_improvement"
            assert reference["summary"]["correctness_status"] == "passed"

    asyncio.run(exercise())
    assert requested == [
        ("measurement", baseline_measurement.measurement_id),
        ("measurement", candidate_measurement.measurement_id),
        ("analysis", "analysis-before"),
        ("analysis", "analysis-after"),
        ("benchmark", "benchmark-before"),
        ("benchmark", "benchmark-after"),
    ]
    assert (
        artifact_root / f"{comparison.comparison_id}.container-matched-comparison.json"
    ).is_file()


def test_docker_capability_requires_project_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy = tmp_path / "perflens-setup/container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(render_default_docker_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    expected = discover_docker_capability(
        rootful_socket=tmp_path / "missing-rootful.sock",
        rootless_socket=tmp_path / "missing-rootless.sock",
    )
    monkeypatch.setattr(
        "perflens.mcp.server.discover_docker_capability",
        lambda: expected,
    )

    denied_server = create_server(ServerConfig((tmp_path,), artifact_root))
    allowed_server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            docker_project_config=policy,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(enabled=True),
        )
    )

    async def exercise() -> None:
        async with Client(denied_server) as client:
            denied = await client.call_tool("inspect_docker_capability", {})
            assert denied.is_error
            assert "disabled by project MCP policy" in str(denied.content)
        async with Client(allowed_server) as client:
            allowed = await client.call_tool("inspect_docker_capability", {})
            assert not allowed.is_error
            payload = _structured(allowed)
            assert payload["schema_version"] == "1.0"
            assert payload["status"] == "unavailable"
            policy.write_text(
                render_default_docker_project_policy() + "\n# changed after startup\n",
                encoding="utf-8",
            )
            policy.chmod(0o600)
            replaced = await client.call_tool("inspect_docker_capability", {})
            assert replaced.is_error
            assert "changed after MCP startup" in str(replaced.content)

    asyncio.run(exercise())


def test_docker_target_resolution_authorization_and_revocation_are_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy = tmp_path / "perflens-setup/container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(render_default_docker_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    target = _docker_target()
    collection = _fake_docker_collection(tmp_path, target)
    planned_requests: list[CollectionPlanRequest] = []
    plan_denied = {"value": False}

    def fake_resolve(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(artifact=target, instance="instance", kernel="kernel")

    resource_context = make_container_resource_context(
        source_collection_id=collection.collection_id,
        source_output_sha256=collection.output_sha256,
    )
    resource_captures: list[object] = []

    class FakeCgroupReader:
        def __init__(self, resolved: SimpleNamespace) -> None:
            assert resolved.artifact == target

        def capture(self) -> object:
            snapshot = object()
            resource_captures.append(snapshot)
            return snapshot

    def fake_build_resource(
        _reader: FakeCgroupReader,
        before: object,
        after: object,
        *,
        source_collection_id: str,
        source_output_sha256: str,
    ):
        assert (before, after) == tuple(resource_captures[-2:])
        assert source_collection_id == collection.collection_id
        assert source_output_sha256 == collection.output_sha256
        return resource_context

    def fake_create_plan(
        request: CollectionPlanRequest,
        **_kwargs: object,
    ) -> CollectionPlanArtifact:
        planned_requests.append(request)
        plan = _fake_docker_plan()
        if plan_denied["value"]:
            return plan.model_copy(
                update={
                    "policy_status": "denied",
                    "warnings": ("simulated automatic-collection policy denial",),
                }
            )
        return plan

    def fake_assert_plan_current(
        _plan: CollectionPlanArtifact,
        **_kwargs: object,
    ) -> None:
        return None

    class FakeBrokerClient:
        fail = False
        callback_count = 1

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(
            self,
            _plan: CollectionPlanArtifact,
            *,
            ready_callback: Any = None,
        ) -> CollectionArtifact:
            if ready_callback is not None:
                for _ in range(self.callback_count):
                    ready_callback()
            if self.fail:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "collector_broker",
                    "simulated Docker collection failure",
                )
            return collection

    monkeypatch.setattr(
        "perflens.docker.runtime.open_local_docker_adapter",
        lambda: cast(Any, object()),
    )
    monkeypatch.setattr(
        "perflens.docker.runtime.resolve_existing_container_target",
        fake_resolve,
    )
    monkeypatch.setattr("perflens.mcp.server.create_collection_plan", fake_create_plan)
    monkeypatch.setattr(
        "perflens.mcp.server.assert_plan_current",
        fake_assert_plan_current,
    )
    monkeypatch.setattr("perflens.mcp.server.CollectorBrokerClient", FakeBrokerClient)
    monkeypatch.setattr("perflens.mcp.server.CgroupV2ResourceReader", FakeCgroupReader)
    monkeypatch.setattr(
        "perflens.mcp.server.build_container_resource_context",
        fake_build_resource,
    )
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_pid_attach=False,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            docker_project_config=policy,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("record", "stat", "sched"),
            ),
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            resolved = await client.call_tool(
                "resolve_docker_target",
                {"container_reference": "service", "container_pid": 12},
            )
            assert not resolved.is_error
            assert _structured(resolved)["identity_fingerprint"] == "9" * 64

            unauthorized = await client.call_tool(
                "authorize_docker_session",
                {
                    "container_reference": "service",
                    "container_pid": 12,
                    "authorization": "yes",
                },
            )
            assert unauthorized.is_error

            authorized = await client.call_tool(
                "authorize_docker_session",
                {
                    "container_reference": "service",
                    "container_pid": 12,
                    "authorization_mode": "bounded_session",
                    "allowed_modes": ["sched", "stat"],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    ),
                },
            )
            assert not authorized.is_error
            session = _structured(authorized)
            assert session["state"] == "active"
            assert session["allowed_modes"] == ["stat", "sched"]

            collected = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert not collected.is_error
            reference = _structured(collected)
            assert reference["artifact_id"] == collection.collection_id
            assert reference["summary"]["docker_run_number"] == 1
            assert reference["summary"]["docker_session_state"] == "active"
            assert reference["summary"]["container_resource_context_id"] == (
                resource_context.resource_context_id
            )
            assert reference["summary"]["container_cpu_usage_usec"] == 600
            assert reference["summary"]["container_resource_collection_id"] == (
                collection.collection_id
            )
            assert reference["summary"]["container_resource_output_sha256"] == (
                collection.output_sha256
            )
            assert reference["summary"]["container_measurement_quality"] == "partial"
            measurement_id = reference["summary"]["container_measurement_id"]
            assert isinstance(measurement_id, str)
            assert planned_requests[0].container_target == target
            assert (artifact_root / f"{collection.collection_id}.collection.json").is_file()
            assert (
                artifact_root
                / (f"{resource_context.resource_context_id}.container-resource-context.json")
            ).is_file()
            assert (artifact_root / f"{measurement_id}.container-measurement.json").is_file()
            assert len(resource_captures) == 2

            denied_plan_session = _structured(
                await client.call_tool(
                    "authorize_docker_session",
                    {
                        "container_reference": "service",
                        "container_pid": 12,
                        "authorization_mode": "bounded_session",
                        "allowed_modes": ["stat"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                        ),
                    },
                )
            )
            plan_denied["value"] = True
            denied_plan = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": denied_plan_session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert denied_plan.is_error
            assert "outside MCP automatic-collection policy" in str(denied_plan.content)
            assert len(resource_captures) == 2
            plan_denied["value"] = False

            duplicate_callback_session = _structured(
                await client.call_tool(
                    "authorize_docker_session",
                    {
                        "container_reference": "service",
                        "container_pid": 12,
                        "authorization_mode": "bounded_session",
                        "allowed_modes": ["stat"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                        ),
                    },
                )
            )
            FakeBrokerClient.callback_count = 2
            duplicate_callback = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": duplicate_callback_session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert duplicate_callback.is_error
            assert "baseline callback was invoked more than once" in str(duplicate_callback.content)

            missing_callback_session = _structured(
                await client.call_tool(
                    "authorize_docker_session",
                    {
                        "container_reference": "service",
                        "container_pid": 12,
                        "authorization_mode": "bounded_session",
                        "allowed_modes": ["stat"],
                        "authorization": (
                            "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                        ),
                    },
                )
            )
            FakeBrokerClient.callback_count = 0
            missing_callback = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": missing_callback_session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert missing_callback.is_error
            assert "without requesting the Docker resource baseline" in str(
                missing_callback.content
            )
            FakeBrokerClient.callback_count = 1

            revoked = await client.call_tool(
                "revoke_docker_session",
                {"session_id": session["session_id"]},
            )
            assert not revoked.is_error
            assert _structured(revoked)["state"] == "revoked"

            per_run = await client.call_tool(
                "authorize_docker_session",
                {
                    "container_reference": "service",
                    "container_pid": 12,
                    "authorization_mode": "per_run",
                    "allowed_modes": ["stat"],
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    ),
                },
            )
            per_run_session = _structured(per_run)
            FakeBrokerClient.fail = True
            failed = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": per_run_session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert failed.is_error
            repeated = await client.call_tool(
                "collect_docker_target",
                {
                    "session_id": per_run_session["session_id"],
                    "container_reference": "service",
                    "container_pid": 12,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert repeated.is_error
            assert "no longer active" in str(repeated.content)

    asyncio.run(exercise())


def test_managed_docker_session_releases_gate_only_after_broker_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy = tmp_path / "perflens-setup" / "container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(
        render_default_docker_project_policy()
        .replace(
            "allow_managed_temporary_containers = false",
            "allow_managed_temporary_containers = true",
        )
        .replace('image_digest = ""', 'image_digest = "sha256:' + "a" * 64 + '"')
        .replace('entrypoint = ""', 'entrypoint = "/usr/bin/python3"')
        .replace('container_user = ""', f'container_user = "{os.geteuid()}:{os.getegid()}"')
        .replace("treatment_paths = []", 'treatment_paths = ["workload.py"]')
        .replace('benchmark_output = ""', 'benchmark_output = "results.json"'),
        encoding="utf-8",
    )
    policy.chmod(0o600)
    target = _managed_docker_target()
    workload = _managed_workload()
    collection = _fake_docker_collection(tmp_path, target)
    active_session = _managed_session(workload.content_sha256)
    exhausted_session = _managed_session(workload.content_sha256, state="exhausted")
    resource_context = make_container_resource_context(
        source_collection_id=collection.collection_id,
        source_output_sha256=collection.output_sha256,
    )
    container_run = _managed_run_artifact(
        resource_context.resource_context_id,
        workload.content_sha256,
    )
    treatment_file = tmp_path / "workload.py"
    treatment_file.write_text("print('workload')\n", encoding="utf-8")
    benchmark = BenchmarkArtifact(
        benchmark_id="benchmark-" + "7" * 16,
        name="managed throughput",
        repetitions=2,
        metrics={
            "throughput": BenchmarkMetric(
                unit="operations/second",
                higher_is_better=True,
                values=(100.0, 101.0),
                median=100.5,
                mean=100.5,
                standard_deviation=0.5,
            )
        },
        environment=BenchmarkEnvironment(containerized=True),
        error_count=0,
        source_format="perflens",
    )
    operations: list[str] = []
    requests: list[CollectionPlanRequest] = []
    plan_denied = {"value": False}

    class FakeCoordinator:
        def release(self, prepared: SimpleNamespace) -> None:
            operations.append("release")
            prepared.state = "released"

        def wait(self, prepared: SimpleNamespace, *, timeout_seconds: int) -> int:
            assert timeout_seconds > 0
            operations.append("wait")
            prepared.exit_code = 0
            return 0

        def cleanup(self, prepared: SimpleNamespace) -> str:
            operations.append("cleanup")
            prepared.state = "cleaned"
            return "removed"

    prepared = SimpleNamespace(
        target=SimpleNamespace(artifact=target),
        receipt=SimpleNamespace(scratch_directory=tmp_path / "runtime" / "scratch"),
        state="prepared",
        exit_code=None,
    )
    coordinated = SimpleNamespace(
        prepared=prepared,
        coordinator=FakeCoordinator(),
        authorization=SimpleNamespace(workload=workload),
    )

    class FakeCgroupReader:
        def __init__(self, resolved: SimpleNamespace) -> None:
            assert resolved.artifact == target
            self.capture_count = 0

        def capture(self) -> object:
            self.capture_count += 1
            operations.append(f"cgroup-{self.capture_count}")
            return object()

    def fake_build_resource(
        _reader: FakeCgroupReader,
        _before: object,
        _after: object,
        *,
        source_collection_id: str,
        source_output_sha256: str,
    ):
        operations.append("resource")
        assert source_collection_id == collection.collection_id
        assert source_output_sha256 == collection.output_sha256
        return resource_context

    class FakeDockerRuntime:
        def __init__(self, **_kwargs: object) -> None:
            self.prepare_count = 0

        def authorize_managed(self, *, explicit_authorization: str):
            assert explicit_authorization.startswith("I_EXPLICITLY_AUTHORIZE")
            return active_session

        def prepare_managed_run(self, *_args: object, **_kwargs: object):
            self.prepare_count += 1
            operations.append("prepare")
            return coordinated

        def finish_managed_run(self, *_args: object, **_kwargs: object):
            operations.append("finish")
            return exhausted_session

    runtime_instances: list[FakeDockerRuntime] = []

    def fake_runtime_factory(**kwargs: object) -> FakeDockerRuntime:
        runtime = FakeDockerRuntime(**kwargs)
        runtime_instances.append(runtime)
        return runtime

    def fake_create_plan(
        request: CollectionPlanRequest,
        **_kwargs: object,
    ) -> CollectionPlanArtifact:
        requests.append(request)
        plan = _fake_docker_plan()
        if plan_denied["value"]:
            return plan.model_copy(
                update={
                    "policy_status": "denied",
                    "warnings": ("simulated automatic-collection policy denial",),
                }
            )
        return plan

    def fake_assert_current(_plan: CollectionPlanArtifact) -> None:
        return None

    def fake_build_run(**kwargs: object) -> ContainerRunArtifact:
        assert kwargs["resource_context_id"] == resource_context.resource_context_id
        assert kwargs["benchmark"] == benchmark
        build_artifacts = cast(tuple[str, ...], kwargs["build_artifact_sha256"])
        assert len(build_artifacts) == 1
        provisional = container_run.model_copy(
            update={
                "treatment_path_sha256": workload.treatment_path_sha256,
                "build_artifact_sha256": build_artifacts,
                "benchmark_id": benchmark.benchmark_id,
                "benchmark_content_sha256": contract_content_sha256(benchmark),
            }
        )
        return provisional.model_copy(
            update={
                "content_sha256": contract_content_sha256(
                    provisional,
                    exclude={"content_sha256"},
                )
            }
        )

    class FakeBrokerClient:
        fail = False
        callback_count = 1

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(
            self,
            _plan: CollectionPlanArtifact,
            *,
            ready_callback: Any = None,
        ) -> CollectionArtifact:
            operations.append("broker")
            assert ready_callback is not None
            for _ in range(self.callback_count):
                ready_callback()
            if self.fail:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "collector_broker",
                    "simulated managed Docker collection failure",
                )
            return collection

    monkeypatch.setattr("perflens.mcp.server.ExistingDockerRuntime", fake_runtime_factory)
    monkeypatch.setattr("perflens.mcp.server.create_collection_plan", fake_create_plan)
    monkeypatch.setattr("perflens.mcp.server.assert_plan_current", fake_assert_current)
    monkeypatch.setattr("perflens.mcp.server.CollectorBrokerClient", FakeBrokerClient)
    monkeypatch.setattr("perflens.mcp.server.CgroupV2ResourceReader", FakeCgroupReader)
    monkeypatch.setattr(
        "perflens.mcp.server.build_container_resource_context",
        fake_build_resource,
    )
    monkeypatch.setattr(
        "perflens.mcp.server.build_container_run_artifact",
        fake_build_run,
    )

    def fake_load_benchmark(
        scratch_root: Path,
        relative_path: str,
        **kwargs: object,
    ) -> BenchmarkArtifact:
        assert scratch_root == prepared.receipt.scratch_directory
        assert relative_path == "results.json"
        assert kwargs == {"source_format": "auto", "benchmark_name": None}
        operations.append("benchmark")
        return benchmark

    monkeypatch.setattr(
        "perflens.mcp.server.load_managed_benchmark",
        fake_load_benchmark,
    )
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_pid_attach=False,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            docker_project_config=policy,
            docker_runtime_root=tmp_path / "runtime",
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat",),
                max_duration_seconds=10,
                max_output_bytes=1000,
            ),
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            authorized = await client.call_tool(
                "authorize_managed_docker_session",
                {
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    )
                },
            )
            assert not authorized.is_error
            assert _structured(authorized)["target_kind"] == "managed_temporary_container"

            denied = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 2,
                    "workload_timeout_seconds": 1,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert denied.is_error
            assert runtime_instances[0].prepare_count == 0

            result = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert not result.is_error
            reference = _structured(result)
            assert reference["artifact_id"] == container_run.run_id
            assert reference["summary"]["docker_session_state"] == "exhausted"
            assert reference["summary"]["container_resource_context_id"] == (
                resource_context.resource_context_id
            )
            assert reference["summary"]["container_resource_collection_id"] == (
                collection.collection_id
            )
            assert reference["summary"]["container_measurement_quality"] == "verified"
            measurement_id = reference["summary"]["container_measurement_id"]
            assert isinstance(measurement_id, str)
            assert operations == [
                "prepare",
                "broker",
                "cgroup-1",
                "release",
                "cgroup-2",
                "resource",
                "wait",
                "benchmark",
                "cleanup",
                "finish",
            ]
            assert requests[0].container_target == target
            assert (artifact_root / f"{container_run.run_id}.container-run.json").is_file()
            assert (
                artifact_root
                / (f"{resource_context.resource_context_id}.container-resource-context.json")
            ).is_file()
            assert (
                artifact_root / f"{workload.workload_spec_id}.container-workload-spec.json"
            ).is_file()
            assert (artifact_root / f"{measurement_id}.container-measurement.json").is_file()
            assert reference["summary"]["container_benchmark_id"] == benchmark.benchmark_id
            assert (artifact_root / f"{benchmark.benchmark_id}.benchmark.json").is_file()

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            coordinated.authorization.workload = workload.model_copy(
                update={"treatment_path_sha256": ("f" * 64,)}
            )
            mismatched_treatment = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert mismatched_treatment.is_error
            assert "differ from the authorized workload" in str(mismatched_treatment.content)
            assert operations == ["prepare", "cleanup", "finish"]
            coordinated.authorization.workload = workload

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            plan_denied["value"] = True
            denied_plan = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert denied_plan.is_error
            assert "outside MCP automatic-collection policy" in str(denied_plan.content)
            assert operations == ["prepare", "cleanup", "finish"]
            plan_denied["value"] = False

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            FakeBrokerClient.callback_count = 2
            duplicate_callback = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert duplicate_callback.is_error
            assert "baseline callback was invoked more than once" in str(duplicate_callback.content)
            assert operations == [
                "prepare",
                "broker",
                "cgroup-1",
                "release",
                "cleanup",
                "finish",
            ]

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            FakeBrokerClient.callback_count = 0
            missing_callback = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert missing_callback.is_error
            assert "without releasing the managed Docker workload" in str(missing_callback.content)
            assert operations == ["prepare", "broker", "cleanup", "finish"]

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            FakeBrokerClient.callback_count = 1
            FakeBrokerClient.fail = True
            failed = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "events": ["task-clock"],
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert failed.is_error
            assert operations == [
                "prepare",
                "broker",
                "cgroup-1",
                "release",
                "cleanup",
                "finish",
            ]

    asyncio.run(exercise())


def test_trace_evidence_is_analyzed_verified_and_paged_without_a_raw_path(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    evidence = make_scheduler_trace_evidence()
    store.save(evidence, evidence.trace_evidence_id, "trace-evidence")
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = _structured(
                await client.call_tool(
                    "analyze_trace_evidence",
                    {"trace_evidence_id": evidence.trace_evidence_id},
                )
            )
            assert analyzed["artifact_type"] == "scheduler-analysis"
            summary = cast(dict[str, Any], analyzed["summary"])
            assert summary["artifact_content_sha256"]
            assert summary["summary_sha256"]
            assert summary["verification_status"] == "partial"
            analysis_id = cast(str, analyzed["artifact_id"])

            verification = _structured(
                await client.call_tool(
                    "verify_trace_analysis",
                    {"analysis_id": analysis_id},
                )
            )
            assert verification["verification_status"] == "partial"
            assert all(
                check["status"] != "failed"
                for check in cast(list[dict[str, Any]], verification["checks"])
            )

            page = _structured(
                await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": analysis_id,
                        "artifact_type": "scheduler-analysis",
                    },
                )
            )
            assert '"scheduler_analysis_id"' in cast(str, page["text"])
            assert "private scheduler trace" not in cast(str, page["text"])
            assert "/var/lib/perflens-trace" not in cast(str, page["text"])

    asyncio.run(exercise())


def test_end_to_end_analysis_details_diagnosis_and_paging(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    profile = tmp_path / "profile.folded"
    profile.write_text("main;worker;malloc 70\nmain;worker;compute 30\n")
    candidate_profile = tmp_path / "candidate.folded"
    candidate_profile.write_text("main;worker;malloc 50\nmain;worker;compute 50\n")
    baseline_benchmark = tmp_path / "baseline-benchmark.json"
    candidate_benchmark = tmp_path / "candidate-benchmark.json"
    baseline_benchmark.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "command": "./bench",
                        "times": [1.0, 1.01, 0.99],
                        "exit_codes": [0, 0, 0],
                    }
                ]
            }
        )
    )
    candidate_benchmark.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "command": "./bench",
                        "times": [0.8, 0.81, 0.79],
                        "exit_codes": [0, 0, 0],
                    }
                ]
            }
        )
    )
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = await client.call_tool("analyze_profile", {"path": str(profile)})
            analysis = _structured(analyzed)
            analysis_id = cast(str, analysis["artifact_id"])
            candidate_analysis = _structured(
                await client.call_tool("analyze_profile", {"path": str(candidate_profile)})
            )

            hotspots = _structured(
                await client.call_tool(
                    "list_hotspots",
                    {"analysis_id": analysis_id, "limit": 1},
                )
            )
            assert hotspots["total_items"] == 4
            assert hotspots["next_cursor"] == 1
            assert hotspots["evidence_quality"]["parser_invariants_passed"] is True
            hotspot_id = hotspots["items"][0]["hotspot_id"]

            verification = _structured(
                await client.call_tool("verify_analysis", {"analysis_id": analysis_id})
            )
            assert verification["status"] == "partial"
            assert verification["checks"][0]["name"] == "analysis_content_sha256"

            details = _structured(
                await client.call_tool(
                    "get_hotspot_details",
                    {"analysis_id": analysis_id, "hotspot_id": hotspot_id},
                )
            )
            assert details["hotspot"]["symbol"] == "malloc"
            assert details["classifications"][0]["conclusion_status"] == "candidate"

            paths = _structured(
                await client.call_tool(
                    "get_call_paths",
                    {"analysis_id": analysis_id, "symbol": "malloc"},
                )
            )
            assert paths["total_items"] == 1

            classifications = _structured(
                await client.call_tool("classify_hotspots", {"analysis_id": analysis_id})
            )
            assert classifications["items"][0]["category"] == "memory-allocation"

            bundle = _structured(
                await client.call_tool(
                    "build_diagnosis_bundle",
                    {"analysis_id": analysis_id},
                )
            )
            diagnosis_path = artifact_root / f"{bundle['artifact_id']}.diagnosis.json"
            diagnosis_snapshot = diagnosis_path.read_bytes()
            repeated_bundle = _structured(
                await client.call_tool(
                    "build_diagnosis_bundle",
                    {"analysis_id": analysis_id},
                )
            )
            assert repeated_bundle == bundle
            assert diagnosis_path.read_bytes() == diagnosis_snapshot
            page = _structured(
                await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": bundle["artifact_id"],
                        "artifact_type": "diagnosis",
                        "limit": 128,
                    },
                )
            )
            assert page["total_bytes"] > 128
            assert page["next_offset"] == 128
            assert page["text"].startswith("{")

            profile_comparison = _structured(
                await client.call_tool(
                    "compare_profiles",
                    {
                        "baseline_analysis_id": analysis_id,
                        "candidate_analysis_id": candidate_analysis["artifact_id"],
                    },
                )
            )
            assert profile_comparison["summary"]["hotspot_delta_count"] > 0

            benchmark_ids: list[str] = []
            for benchmark_path in (baseline_benchmark, candidate_benchmark):
                normalized = _structured(
                    await client.call_tool("analyze_benchmark", {"path": str(benchmark_path)})
                )
                benchmark_ids.append(cast(str, normalized["artifact_id"]))
            benchmark_comparison = _structured(
                await client.call_tool(
                    "compare_benchmarks",
                    {
                        "baseline_benchmark_id": benchmark_ids[0],
                        "candidate_benchmark_id": benchmark_ids[1],
                    },
                )
            )
            assert benchmark_comparison["summary"]["metric_count"] == 1

    asyncio.run(exercise())


def test_artifact_paging_cannot_bypass_analysis_integrity_gate(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    profile = tmp_path / "profile.folded"
    profile.write_text("main;worker 10\n", encoding="utf-8")
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server) as client:
            analyzed = _structured(
                await client.call_tool("analyze_profile", {"path": str(profile)})
            )
            analysis_id = cast(str, analyzed["artifact_id"])
            artifact_path = artifact_root / f"{analysis_id}.analysis.json"
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
            payload["metadata"]["total_weight"] = 11
            artifact_path.write_text(json.dumps(payload), encoding="utf-8")

            paged = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": analysis_id,
                    "artifact_type": "analysis",
                },
            )
            assert paged.is_error

    asyncio.run(exercise())


def test_server_enforces_write_process_and_path_authorization(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    artifact_root = allowed / "artifacts"
    artifact_root.mkdir()
    profile = allowed / "profile.folded"
    profile.write_text("main 1\n")
    outside = tmp_path / "outside.folded"
    outside.write_text("secret 1\n")
    server = create_server(ServerConfig((allowed,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            write_denied = await client.call_tool(
                "analyze_profile",
                {"path": str(profile)},
            )
            path_denied = await client.call_tool(
                "analyze_profile",
                {"path": str(outside)},
            )
            process_denied = await client.call_tool(
                "resolve_source",
                {"binary_path": str(profile), "module_offset": 1},
            )
            collection_denied = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(allowed / "profile.data"),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(profile),
                },
            )
            assert write_denied.is_error
            assert path_denied.is_error
            assert process_denied.is_error
            assert collection_denied.is_error
        assert list(artifact_root.iterdir()) == []

    asyncio.run(exercise())


def test_automatic_collection_is_plannable_but_not_executable_by_default(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            planned = await client.call_tool(
                "plan_automatic_collection",
                {"pid": os.getppid(), "duration_seconds": 0.1},
            )
            payload = _structured(planned)
            assert payload["policy_status"] == "denied"
            executed = await client.call_tool(
                "execute_collection_plan",
                {"plan_id": payload["plan_id"]},
            )
            assert executed.is_error
        assert list(artifact_root.iterdir()) == []

    asyncio.run(exercise())


def test_active_collection_requires_server_and_per_call_authorization(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'PERFILE2')\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    target = tmp_path / "target"
    target.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            perf_path=fake_perf,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            denied = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(tmp_path / "denied.data"),
                    "authorization": "not-authorized",
                    "executable": str(target),
                },
            )
            assert denied.is_error
            assert not (tmp_path / "denied.data").exists()

        async with Client(server, raise_exceptions=True) as client:
            collected = _structured(
                await client.call_tool(
                    "collect_profile",
                    {
                        "output_path": str(tmp_path / "profile.data"),
                        "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                        "executable": str(target),
                    },
                )
            )
            assert collected["artifact_type"] == "collection"
            assert collected["summary"]["mode"] == "record"
            assert (tmp_path / "profile.data").read_bytes() == b"PERFILE2"
            stored = artifact_root / (f"{collected['artifact_id']}.collection.json")
            assert json.loads(stored.read_text(encoding="utf-8"))["authorization"] == "explicit"

    asyncio.run(exercise())


def test_analyze_collection_binds_collection_hash_and_quality_context(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version collection-test')\n"
        "elif args and args[0] == 'script':\n"
        "    print('app 9/9 [000] 1.0: 11 cycles: 400010 leaf (/app) /src/app.c:7')\n"
        "elif 'record' in args:\n"
        "    pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'PERFILE2')\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    target = tmp_path / "target"
    target.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    profile = tmp_path / "profile.data"
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            perf_path=fake_perf,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            collected_result = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(profile),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(target),
                },
            )
            assert not collected_result.is_error
            collected = _structured(collected_result)
            collection_id = cast(str, collected["artifact_id"])
            analyzed_result = await client.call_tool(
                "analyze_collection", {"collection_id": collection_id}
            )
            assert not analyzed_result.is_error
            analyzed = _structured(analyzed_result)
            quality = cast(dict[str, Any], analyzed["evidence_quality"])
            assert quality["source_collection_id"] == collection_id
            assert quality["input_sha256"] == hashlib.sha256(b"PERFILE2").hexdigest()

            trace_collected_result = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(tmp_path / "trace.data"),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(target),
                    "mode": "sched",
                },
            )
            assert not trace_collected_result.is_error
            trace_collection_id = cast(
                str,
                _structured(trace_collected_result)["artifact_id"],
            )
            wrong_analyzer = await client.call_tool(
                "analyze_collection",
                {"collection_id": trace_collection_id},
            )
            assert wrong_analyzer.is_error
            assert "TraceEvidence" in str(wrong_analyzer.content)

            profile.write_bytes(b"PERFILE3")
            rejected = await client.call_tool(
                "analyze_collection", {"collection_id": collection_id}
            )
            assert rejected.is_error

    asyncio.run(exercise())


def test_source_context_is_workspace_bounded(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    source = tmp_path / "sample.c"
    source.write_text("one\ntwo\nthree\n")
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            result = _structured(
                await client.call_tool(
                    "get_source_context",
                    {
                        "file": str(source),
                        "line": 2,
                        "workspace_root": str(tmp_path),
                        "before": 1,
                        "after": 1,
                    },
                )
            )
            assert result["lines"] == ["one", "two", "three"]

    asyncio.run(exercise())
