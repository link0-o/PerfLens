from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

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
    ArtifactReference,
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
from perflens.contracts.docker_build import DockerOptimizationIterationArtifact
from perflens.docker.capability import discover_docker_capability
from perflens.docker.project_config import render_default_docker_project_policy
from perflens.docker.workload import inspect_managed_project_root
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.server import (
    ServerConfig,
    _docker_optimization_iteration_summary,  # pyright: ignore[reportPrivateUsage]
    _finish_optimization_workload_with_evidence,  # pyright: ignore[reportPrivateUsage]
    _managed_evidence_bytes,  # pyright: ignore[reportPrivateUsage]
    _managed_workload_active_seconds,  # pyright: ignore[reportPrivateUsage]
    _remaining_managed_workload_timeout_seconds,  # pyright: ignore[reportPrivateUsage]
    _validate_observed_managed_workload_end,  # pyright: ignore[reportPrivateUsage]
    create_server,
)
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks import NativeLaunchCapability, import_runtime_lock_ndjson
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.native_launcher import (
    NativePthreadProbeDiscovery,
    NativePthreadProbePolicy,
)
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)


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


def _fake_docker_plan(
    *,
    mode: Literal["record", "stat"] = "stat",
) -> CollectionPlanArtifact:
    return CollectionPlanArtifact(
        schema_version="1.0",
        plan_id="plan-" + "a" * 20,
        mode=mode,
        target_type="pid",
        target_pid=1234,
        target_uid=os.geteuid(),
        target_start_time_ticks=5678,
        backend="privileged_broker",
        duration_seconds=1,
        frequency_hz=99 if mode == "record" else None,
        call_graph="dwarf" if mode == "record" else None,
        events=("task-clock",) if mode == "stat" else (),
        requested_event_source="software_only",
        record_event="cpu-clock" if mode == "record" else None,
        max_output_bytes=1000,
        expires_at="2026-08-21T01:00:00+00:00",
        policy_status="allowed",
        required_privilege="cap_perfmon",
    )


def _fake_docker_collection(
    tmp_path: Path,
    target: ContainerTargetArtifact,
    *,
    mode: Literal["record", "stat"] = "stat",
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
    output_path = tmp_path / ("fake.perf.data" if mode == "record" else "fake.stat.csv")
    output_payload = b"PERFILE2" if mode == "record" else b"c" * 120
    output_path.write_bytes(output_payload)
    return CollectionArtifact(
        schema_version="1.0",
        collection_id="collection-" + ("d" if mode == "record" else "b") * 16,
        mode=mode,
        target_type="pid",
        target_argument_count=0,
        target_pid=1234,
        target_runtime="docker",
        container_target=binding,
        output_path=str(output_path),
        output_sha256=hashlib.sha256(output_payload).hexdigest(),
        output_bytes=len(output_payload),
        output_format="perf_data" if mode == "record" else "perf_stat_delimited",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-21T00:00:00+00:00",
        finished_at="2026-08-21T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=99 if mode == "record" else None,
        call_graph="dwarf" if mode == "record" else None,
        record_event="cpu-clock" if mode == "record" else None,
        events=("task-clock",) if mode == "stat" else (),
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
            (
                PerfStatMetric(
                    event="task-clock",
                    value=1000,
                    unit="msec",
                    status="measured",
                ),
            )
            if mode == "stat"
            else ()
        ),
    )


def _managed_workload(
    *,
    allowed_modes: tuple[Literal["record", "stat"], ...] = ("stat",),
) -> ContainerWorkloadSpecArtifact:
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
        allowed_modes=allowed_modes,
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
    allowed_modes: tuple[Literal["record", "stat"], ...] = ("stat",),
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
        allowed_modes=allowed_modes,
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


def test_docker_optimization_summary_identifies_its_exact_comparison_chain() -> None:
    iteration = cast(
        DockerOptimizationIterationArtifact,
        SimpleNamespace(
            session_id="docker-optimization-session-" + "1" * 20,
            candidate_round=1,
            comparable=False,
            baseline_build_id="docker-build-" + "a" * 20,
            candidate_build_id="docker-build-" + "b" * 20,
            baseline_measurement_id="container-measurement-" + "c" * 20,
            candidate_measurement_id="container-measurement-" + "d" * 20,
            baseline_analysis_id="analysis-" + "e" * 16,
            candidate_analysis_id="analysis-" + "f" * 16,
            profile_comparison_id="profile-comparison-" + "2" * 16,
            baseline_benchmark_id="benchmark-" + "5" * 16,
            candidate_benchmark_id="benchmark-" + "6" * 16,
            benchmark_comparison_id="benchmark-comparison-" + "3" * 16,
            source_container_comparison_id="container-comparison-" + "4" * 20,
            fixed_environment_match=True,
            treatment_changed=True,
            correctness_status="passed",
            actual_event_source_match=True,
            resource_transfer_status="incomplete",
            deterministic_replay_passed=True,
            conclusion="not_comparable",
            improved_metrics=(),
            regressed_metrics=(),
            warnings=("Profile evidence is partial.",),
        ),
    )

    summary = _docker_optimization_iteration_summary(
        iteration,
        profile_comparable=False,
        benchmark_comparable=True,
        source_environment_match=False,
        baseline_profile_quality_status="partial",
        candidate_profile_quality_status="verified",
        baseline_profile_sample_count=210,
        candidate_profile_sample_count=35,
        profile_metadata_differences={"baseline_quality_status": ("partial", "verified")},
    )

    assert summary["profile_comparison_id"] == iteration.profile_comparison_id
    assert summary["benchmark_comparison_id"] == iteration.benchmark_comparison_id
    assert summary["baseline_build_id"] == iteration.baseline_build_id
    assert summary["candidate_build_id"] == iteration.candidate_build_id
    assert summary["baseline_measurement_id"] == iteration.baseline_measurement_id
    assert summary["candidate_measurement_id"] == iteration.candidate_measurement_id
    assert summary["baseline_analysis_id"] == iteration.baseline_analysis_id
    assert summary["candidate_analysis_id"] == iteration.candidate_analysis_id
    assert summary["baseline_benchmark_id"] == iteration.baseline_benchmark_id
    assert summary["candidate_benchmark_id"] == iteration.candidate_benchmark_id
    assert summary["source_container_comparison_id"] == (iteration.source_container_comparison_id)
    assert summary["profile_comparable"] is False
    assert summary["baseline_profile_quality_status"] == "partial"
    assert summary["candidate_profile_quality_status"] == "verified"
    assert summary["baseline_profile_sample_count"] == 210
    assert summary["candidate_profile_sample_count"] == 35
    assert summary["profile_sample_count_warning"] is True
    assert summary["profile_sample_count_is_advisory"] is True
    assert "baseline_quality_status" in str(summary["profile_noncomparability_reasons"])
    assert summary["benchmark_comparable"] is True
    assert summary["source_generic_environment_match"] is False
    assert summary["source_comparison_includes_authorized_treatment"] is True
    assert summary["fixed_environment_match"] is True
    assert summary["actual_event_source_match"] is True
    assert summary["deterministic_replay_passed"] is True


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
                "compare_runtime_lock_analyses",
                "compare_docker_optimization_iterations",
                "finalize_docker_optimization_candidate",
                "collect_profile",
                "inspect_collection_capabilities",
                "inspect_runtime_lock_capability",
                "preview_runtime_lock_session",
                "authorize_runtime_lock_session",
                "collect_runtime_lock_evidence",
                "import_runtime_lock_evidence",
                "revoke_runtime_lock_session",
                "inspect_docker_capability",
                "inspect_docker_optimization_capability",
                "preview_docker_optimization_session",
                "authorize_docker_optimization_session",
                "build_docker_optimization_candidate",
                "revoke_docker_optimization_session",
                "discover_docker_processes",
                "resolve_docker_target",
                "authorize_docker_session",
                "authorize_managed_docker_session",
                "revoke_docker_session",
                "collect_docker_target",
                "collect_managed_docker_workload",
                "collect_docker_optimization_workload",
                "plan_automatic_collection",
                "execute_collection_plan",
                "collect_project_workload",
                "analyze_collection",
                "analyze_trace_evidence",
                "verify_trace_analysis",
                "analyze_runtime_lock_evidence",
                "verify_runtime_lock_analysis",
                "list_runtime_lock_hotspots",
                "get_runtime_lock_call_paths",
                "build_runtime_lock_diagnosis_bundle",
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
            assert tools["authorize_docker_optimization_session"].meta == {
                "perflens/permission": "DOCKER_OPTIMIZATION_AUTHORIZATION"
            }
            assert tools["build_docker_optimization_candidate"].meta == {
                "perflens/permission": "DOCKER_OPTIMIZATION_BUILD"
            }
            assert tools["authorize_managed_docker_session"].meta == {
                "perflens/permission": "DOCKER_AUTHORIZATION"
            }
            existing_authorization_annotations = tools["authorize_docker_session"].annotations
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
            assert tools["collect_docker_optimization_workload"].meta == {
                "perflens/permission": "DOCKER_OPTIMIZATION_COLLECTION"
            }
            assert tools["compare_container_measurements"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["compare_runtime_lock_analyses"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["compare_docker_optimization_iterations"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["finalize_docker_optimization_candidate"].meta == {
                "perflens/permission": "DOCKER_OPTIMIZATION_DISPOSITION"
            }
            docker_authorization = tools["authorize_docker_session"].input_schema["properties"][
                "authorization"
            ]
            assert docker_authorization["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
            )
            assert "allowed_modes" in tools["authorize_docker_session"].input_schema["required"]
            managed_authorization = tools["authorize_managed_docker_session"].input_schema[
                "properties"
            ]
            assert set(managed_authorization) == {"authorization", "allowed_modes"}
            assert managed_authorization["authorization"]["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
            )
            assert (
                "allowed_modes"
                in tools["authorize_managed_docker_session"].input_schema["required"]
            )
            optimization_authorization = tools[
                "authorize_docker_optimization_session"
            ].input_schema["properties"]
            assert optimization_authorization["authorization"]["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"
            )
            optimization_build = tools["build_docker_optimization_candidate"].input_schema[
                "properties"
            ]
            assert not {
                "image",
                "dockerfile",
                "context",
                "build_args",
                "network",
                "docker_options",
                "source_path",
            }.intersection(optimization_build)
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
            optimization_collection = tools["collect_docker_optimization_workload"].input_schema[
                "properties"
            ]
            assert {
                "runtime_lock_adapter",
                "runtime_lock_max_events",
                "runtime_lock_go_profile_kind",
            }.issubset(optimization_collection)
            assert not {
                "image",
                "entrypoint",
                "arguments",
                "mounts",
                "network",
                "docker_options",
                "source_path",
                "environment",
                "runtime_lock_payload",
                "runtime_lock_output_path",
            }.intersection(optimization_collection)
            optimization_comparison = tools["compare_docker_optimization_iterations"].input_schema[
                "properties"
            ]
            assert not {
                "image",
                "dockerfile",
                "context",
                "build_args",
                "network",
                "docker_options",
                "source_path",
            }.intersection(optimization_comparison)
            optimization_disposition = tools["finalize_docker_optimization_candidate"].input_schema[
                "properties"
            ]
            assert any(
                option.get("const") == "I_EXPLICITLY_ACCEPT_THIS_UNVERIFIED_DOCKER_CANDIDATE"
                for option in optimization_disposition["authorization"]["anyOf"]
            )
            assert not {
                "source_path",
                "content",
                "docker_options",
                "image",
            }.intersection(optimization_disposition)
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
            assert tools["analyze_runtime_lock_evidence"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["verify_runtime_lock_analysis"].meta == {
                "perflens/permission": "READ_ONLY"
            }
            assert (
                "runtime_lock_verification_id"
                in tools["verify_runtime_lock_analysis"].input_schema["properties"]
            )
            assert (
                "runtime_lock_verification_id"
                in tools["build_runtime_lock_diagnosis_bundle"].input_schema["properties"]
            )
            assert tools["list_runtime_lock_hotspots"].meta == {"perflens/permission": "READ_ONLY"}
            assert tools["inspect_runtime_lock_capability"].meta == {
                "perflens/permission": "READ_ONLY"
            }
            assert tools["preview_runtime_lock_session"].meta == {
                "perflens/permission": "READ_ONLY_CONTEXT_SNAPSHOT"
            }
            assert (
                "profile_kind" in tools["preview_runtime_lock_session"].input_schema["properties"]
            )
            assert tools["authorize_runtime_lock_session"].meta == {
                "perflens/permission": "RUNTIME_LOCK_AUTHORIZATION"
            }
            assert tools["import_runtime_lock_evidence"].meta == {
                "perflens/permission": "RUNTIME_LOCK_CONTROLLED_IMPORT"
            }
            assert tools["collect_runtime_lock_evidence"].meta == {
                "perflens/permission": "RUNTIME_LOCK_WORKLOAD_EXECUTION"
            }
            native_collection = tools["collect_runtime_lock_evidence"].input_schema["properties"]
            assert "profile_kind" in native_collection
            assert not {
                "executable",
                "arguments",
                "environment",
                "probe_path",
                "output_path",
            }.intersection(native_collection)
            assert tools["revoke_runtime_lock_session"].meta == {
                "perflens/permission": "RUNTIME_LOCK_AUTHORIZATION"
            }
            artifact_types = set(
                tools["read_artifact_page"].input_schema["properties"]["artifact_type"]["enum"]
            )
            assert {
                "docker-build-capability",
                "docker-build-recipe",
                "docker-build-context",
                "docker-optimization-preview",
                "docker-optimization-session",
                "docker-build",
                "docker-optimization-iteration",
                "docker-optimization-disposition",
                "container-target",
            }.issubset(artifact_types)
            runtime_lock_authorization = tools["authorize_runtime_lock_session"].input_schema[
                "properties"
            ]["authorization"]
            assert runtime_lock_authorization["const"] == (
                "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"
            )

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


def test_docker_optimization_requires_separate_project_opt_in(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy = tmp_path / "perflens-setup/container-workload.toml"
    policy.parent.mkdir()
    policy.write_text(render_default_docker_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    server = create_server(
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
        async with Client(server) as client:
            capability = await client.call_tool(
                "inspect_docker_optimization_capability",
                {},
            )
            assert capability.is_error
            assert "disabled by project MCP policy" in str(capability.content)
            preview = await client.call_tool(
                "preview_docker_optimization_session",
                {"allowed_modes": ["stat"]},
            )
            assert preview.is_error

    asyncio.run(exercise())


def test_runtime_lock_preview_authorize_and_revoke_are_content_bound(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    setup_root = tmp_path / "perflens-setup"
    setup_root.mkdir()
    policy = setup_root / "runtime-locks.toml"
    policy.write_text(
        render_default_runtime_lock_project_policy(),
        encoding="utf-8",
    )
    policy.chmod(0o600)

    with pytest.raises(ValueError, match="Runtime Lock sessions require writes"):
        create_server(
            ServerConfig(
                (tmp_path,),
                artifact_root,
                allow_runtime_locks=True,
                runtime_lock_project_config=policy,
            )
        )
    with pytest.raises(ValueError, match="Configured CPython target requires"):
        create_server(
            ServerConfig(
                (tmp_path,),
                artifact_root,
                runtime_lock_cpython_interpreter=tmp_path / "python3.13t",
            )
        )
    with pytest.raises(ValueError, match="Configured CPython target requires"):
        create_server(
            ServerConfig(
                (tmp_path,),
                artifact_root,
                allow_writes=True,
                allow_runtime_locks=True,
                runtime_lock_project_config=policy,
                runtime_lock_cpython_interpreter=tmp_path / "python3.13t",
            )
        )
    denied_server = create_server(ServerConfig((tmp_path,), artifact_root))
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy,
        )
    )

    async def exercise() -> None:
        async with Client(denied_server) as client:
            denied = await client.call_tool("inspect_runtime_lock_capability", {})
            assert denied.is_error
            assert "disabled by project MCP policy" in str(denied.content)
            denied_preview = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert denied_preview.is_error
            assert "disabled by project MCP policy" in str(denied_preview.content)

        async with Client(server) as client:
            inspected = await client.call_tool("inspect_runtime_lock_capability", {})
            assert not inspected.is_error
            capability = _structured(inspected)
            assert capability["status"] == "available"
            adapters = {item["adapter_id"]: item for item in capability["adapters"]}
            assert adapters["generic_ndjson_import"]["availability"] == "available"
            assert "controlled NDJSON import" in adapters["generic_ndjson_import"]["limitations"][0]
            assert adapters["native_pthread"]["availability"] == "unavailable"

            previewed = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert not previewed.is_error
            preview = _structured(previewed)
            assert preview["target_scope"] == "controlled_import"
            assert preview["allowed_adapters"] == ["generic_ndjson_import"]
            assert preview["allowed_semantics"] == ["exact"]
            assert preview["import_roots"] == ["perflens-runtime-locks"]
            assert not preview["warnings"]
            stored_capability_page = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": preview["capability_id"],
                    "artifact_type": "runtime-lock-capability",
                },
            )
            assert not stored_capability_page.is_error
            assert preview["capability_id"] in cast(
                str,
                _structured(stored_capability_page)["text"],
            )
            stored_capability = json.loads(cast(str, _structured(stored_capability_page)["text"]))
            generic_adapter = next(
                item
                for item in stored_capability["adapters"]
                if item["adapter_id"] == "generic_ndjson_import"
            )
            for artifact_id, artifact_type in (
                (generic_adapter["capability_id"], "runtime-adapter-capability"),
                (preview["preview_id"], "runtime-lock-preview"),
            ):
                page = await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": artifact_id,
                        "artifact_type": artifact_type,
                    },
                )
                assert not page.is_error, (artifact_type, page.content)
                assert artifact_id in cast(str, _structured(page)["text"])

            rejected = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": "0" * 64,
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            assert rejected.is_error
            assert "summary changed" in str(rejected.content)

            authorized = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            assert not authorized.is_error
            session = _structured(authorized)
            assert session["state"] == "active"
            assert "authorization" not in session

            replayed = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            assert replayed.is_error
            assert "missing or consumed" in str(replayed.content)

            second_previewed = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert not second_previewed.is_error
            second_preview = _structured(second_previewed)
            policy.write_text(
                render_default_runtime_lock_project_policy() + "\n# changed after authorization\n",
                encoding="utf-8",
            )
            policy.chmod(0o600)
            stale_authorization = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": second_preview["preview_id"],
                    "preview_content_sha256": second_preview["content_sha256"],
                    "authorization_summary_sha256": second_preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            assert stale_authorization.is_error
            assert "changed after MCP startup" in str(stale_authorization.content)
            revoked = await client.call_tool(
                "revoke_runtime_lock_session",
                {"session_id": session["session_id"]},
            )
            assert not revoked.is_error
            assert _structured(revoked)["state"] == "revoked"

    asyncio.run(exercise())
    assert list(artifact_root.glob("*.runtime-lock-preview.json"))
    assert len(list(artifact_root.glob("*.runtime-lock-session.json"))) == 2


def test_runtime_lock_controlled_import_consumes_lease_and_closes_session(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    setup_root = tmp_path / "perflens-setup"
    setup_root.mkdir()
    policy = setup_root / "runtime-locks.toml"
    policy.write_text(
        render_default_runtime_lock_project_policy().replace(
            "preview_ttl_seconds = 600",
            "preview_ttl_seconds = 120",
        ),
        encoding="utf-8",
    )
    policy.chmod(0o600)
    import_root = tmp_path / "perflens-runtime-locks"
    import_root.mkdir()
    source = import_root / "exact.ndjson"
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    source.write_bytes(fixture.read_bytes())
    source.chmod(0o600)
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy,
        )
    )
    session_id = ""

    async def exercise() -> None:
        nonlocal session_id
        async with Client(server) as client:
            wrong_entry = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "host_launched_workload",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert wrong_entry.is_error
            assert "entry point" in str(wrong_entry.content)

            previewed = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            assert not previewed.is_error
            preview = _structured(previewed)
            preview_lifetime = datetime.fromisoformat(
                preview["expires_at"]
            ) - datetime.fromisoformat(preview["created_at"])
            assert preview_lifetime.total_seconds() == 120
            authorized = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            assert not authorized.is_error
            session_id = cast(str, _structured(authorized)["session_id"])
            imported = await client.call_tool(
                "import_runtime_lock_evidence",
                {
                    "session_id": session_id,
                    "source_path": "perflens-runtime-locks/exact.ndjson",
                    "measurement_semantics": "exact",
                },
            )
            assert not imported.is_error, imported.content
            reference = _structured(imported)
            assert reference["artifact_type"] == "runtime-lock-run"
            assert reference["summary"]["private_source_replay_status"] == "passed"
            assert reference["summary"]["event_count"] == 4
            assert reference["summary"]["settled_session_revision"] == 2
            finalization_page = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": reference["summary"]["runtime_lock_run_finalization_id"],
                    "artifact_type": "runtime-lock-run-finalization",
                },
            )
            assert not finalization_page.is_error, finalization_page.content
            finalization = json.loads(cast(str, _structured(finalization_page)["text"]))
            assert finalization["outcome"] == "completed"
            assert finalization["run_id"] == reference["artifact_id"]
            assert (
                finalization["content_sha256"]
                == reference["summary"]["runtime_lock_run_finalization_content_sha256"]
            )
            assert (
                finalization["final_session_artifact_id"]
                == reference["summary"]["settled_session_artifact_id"]
            )
            run_page = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": reference["artifact_id"],
                    "artifact_type": "runtime-lock-run",
                },
            )
            assert not run_page.is_error, run_page.content
            assert '"target_scope": "controlled_import"' in cast(
                str,
                _structured(run_page)["text"],
            )

    asyncio.run(exercise())
    states = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in artifact_root.glob("*.runtime-lock-session.json")
    ]
    assert any(item["session_id"] == session_id and item["state"] == "revoked" for item in states)


def test_runtime_lock_controlled_import_rejects_symlink_and_terminates_session(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    setup_root = tmp_path / "perflens-setup"
    setup_root.mkdir()
    policy = setup_root / "runtime-locks.toml"
    policy.write_text(render_default_runtime_lock_project_policy(), encoding="utf-8")
    policy.chmod(0o600)
    import_root = tmp_path / "perflens-runtime-locks"
    import_root.mkdir()
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    outside = tmp_path / "outside.ndjson"
    outside.write_bytes(fixture.read_bytes())
    outside.chmod(0o600)
    (import_root / "link.ndjson").symlink_to(outside)
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_runtime_locks=True,
            runtime_lock_project_config=policy,
        )
    )
    session_id = ""

    async def exercise() -> None:
        nonlocal session_id
        async with Client(server) as client:
            previewed = await client.call_tool(
                "preview_runtime_lock_session",
                {
                    "target_scope": "controlled_import",
                    "allowed_adapters": ["generic_ndjson_import"],
                    "allowed_semantics": ["exact"],
                },
            )
            preview = _structured(previewed)
            authorized = await client.call_tool(
                "authorize_runtime_lock_session",
                {
                    "preview_id": preview["preview_id"],
                    "preview_content_sha256": preview["content_sha256"],
                    "authorization_summary_sha256": preview["authorization_summary_sha256"],
                    "authorization": ("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_RUNTIME_LOCK_SESSION"),
                },
            )
            session_id = cast(str, _structured(authorized)["session_id"])
            rejected = await client.call_tool(
                "import_runtime_lock_evidence",
                {
                    "session_id": session_id,
                    "source_path": "perflens-runtime-locks/link.ndjson",
                    "measurement_semantics": "exact",
                },
            )
            assert rejected.is_error
            assert "symlink or escapes" in str(rejected.content)
            second_revoke = await client.call_tool(
                "revoke_runtime_lock_session",
                {"session_id": session_id},
            )
            assert second_revoke.is_error
            assert "not bound to this connection" in str(second_revoke.content)

    asyncio.run(exercise())
    states = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in artifact_root.glob("*.runtime-lock-session.json")
    ]
    assert any(
        item["session_id"] == session_id
        and item["state"] == "revoked"
        and item["invalidation_reason"] == "request_rejected"
        for item in states
    )
    assert not list(artifact_root.glob("*.runtime-lock-evidence.json"))
    assert not list(artifact_root.glob("*.runtime-lock-run.json"))


def test_docker_optimization_preview_authorize_build_and_revoke_are_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.unit.test_docker_optimization_runtime import (
        make_optimization_iteration,
        make_optimization_runtime,
    )

    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    policy = project / "container-workload.toml"
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            docker_project_config=policy,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            preview_result = await client.call_tool(
                "preview_docker_optimization_session",
                {"allowed_modes": ["stat", "record"]},
            )
            assert not preview_result.is_error
            preview = _structured(preview_result)
            assert preview["context_paths"] == ["Dockerfile", "src"]
            assert preview["mutable_paths"] == ["src"]
            invalid = await client.call_tool(
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
            assert not invalid.is_error
            session = _structured(invalid)
            baseline_result = await client.call_tool(
                "build_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "build_kind": "baseline",
                    "candidate_round": 0,
                },
            )
            assert not baseline_result.is_error
            baseline = _structured(baseline_result)
            assert baseline["artifact_type"] == "docker-build"
            for artifact_id, artifact_type in (
                (preview["build_capability_id"], "docker-build-capability"),
                (preview["recipe_id"], "docker-build-recipe"),
                (preview["baseline_context_id"], "docker-build-context"),
                (preview["preview_id"], "docker-optimization-preview"),
                (session["session_artifact_id"], "docker-optimization-session"),
                (baseline["artifact_id"], "docker-build"),
            ):
                page = await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": artifact_id,
                        "artifact_type": artifact_type,
                    },
                )
                assert not page.is_error, (artifact_type, page.content)
                assert _structured(page)["next_offset"] is None
            (project / "src/app").write_bytes(b"candidate")
            candidate_result = await client.call_tool(
                "build_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "build_kind": "candidate",
                    "candidate_round": 1,
                },
            )
            assert not candidate_result.is_error
            candidate = _structured(candidate_result)
            current_session = runtime.snapshot(cast(str, session["session_id"]))
            iteration = make_optimization_iteration(
                current_session,
                runtime.build_result(
                    cast(str, session["session_id"]),
                    cast(str, baseline["artifact_id"]),
                ).artifact,
                runtime.build_result(
                    cast(str, session["session_id"]),
                    cast(str, candidate["artifact_id"]),
                ).artifact,
            )

            def load_iteration(
                _store: ArtifactStore,
                iteration_id: str,
            ) -> DockerOptimizationIterationArtifact:
                if iteration_id != iteration.iteration_id:
                    pytest.fail("unexpected Iteration ID")
                return iteration

            monkeypatch.setattr(
                ArtifactStore,
                "load_docker_optimization_iteration",
                load_iteration,
            )
            missing_consent = await client.call_tool(
                "finalize_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "iteration_id": iteration.iteration_id,
                    "disposition": "retain_candidate",
                },
            )
            assert missing_consent.is_error
            finalized_result = await client.call_tool(
                "finalize_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "iteration_id": iteration.iteration_id,
                    "disposition": "retain_candidate",
                    "authorization": ("I_EXPLICITLY_ACCEPT_THIS_UNVERIFIED_DOCKER_CANDIDATE"),
                },
            )
            assert not finalized_result.is_error
            finalized = _structured(finalized_result)
            assert finalized["artifact_type"] == "docker-optimization-disposition"
            assert finalized["summary"]["iteration_conclusion"] == "not_comparable"
            assert finalized["summary"]["explicit_unverified_acceptance"] is True
            assert finalized["summary"]["final_session_state"] == "revoked"

    asyncio.run(exercise())
    assert len(adapter.cleaned) == 2
    assert len(tuple(artifact_root.glob("*.docker-build.json"))) == 2
    assert len(tuple(artifact_root.glob("*.docker-optimization-disposition.json"))) == 1


def test_docker_optimization_can_finalize_candidate_without_an_iteration(
    tmp_path: Path,
) -> None:
    from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            docker_project_config=project / "container-workload.toml",
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {"allowed_modes": ["stat", "record"]},
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
            baseline = await client.call_tool(
                "build_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "build_kind": "baseline",
                    "candidate_round": 0,
                },
            )
            assert not baseline.is_error
            (project / "src/app").write_bytes(b"candidate")
            candidate = _structured(
                await client.call_tool(
                    "build_docker_optimization_candidate",
                    {
                        "session_id": session["session_id"],
                        "build_kind": "candidate",
                        "candidate_round": 1,
                    },
                )
            )
            finalized_result = await client.call_tool(
                "finalize_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "candidate_build_id": candidate["artifact_id"],
                    "evaluation_reason": "user_stopped",
                    "disposition": "retain_candidate",
                    "authorization": ("I_EXPLICITLY_ACCEPT_THIS_UNVERIFIED_DOCKER_CANDIDATE"),
                },
            )
            assert not finalized_result.is_error
            finalized = _structured(finalized_result)
            assert finalized["summary"]["iteration_id"] is None
            assert finalized["summary"]["iteration_conclusion"] == "not_evaluated"
            assert finalized["summary"]["evaluation_reason"] == "user_stopped"
            assert finalized["summary"]["final_session_state"] == "revoked"

    asyncio.run(exercise())
    assert len(adapter.cleaned) == 2
    assert len(tuple(artifact_root.glob("*.docker-optimization-disposition.json"))) == 1


def test_docker_optimization_collection_failure_is_charged_and_stops_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()

    def reject_internal_session(*_args: object, **_kwargs: object) -> None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "perf_control",
            "Privileged perf binding failed",
            recoverable=True,
            retryable=True,
        )

    monkeypatch.setattr(
        "perflens.mcp.server.ExistingDockerRuntime.authorize_optimization_build",
        reject_internal_session,
    )
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            docker_project_config=project / "container-workload.toml",
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {"allowed_modes": ["stat", "record"]},
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
            failed = await client.call_tool(
                "collect_docker_optimization_workload",
                {
                    "session_id": session["session_id"],
                    "build_id": baseline["artifact_id"],
                    "mode": "stat",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 5,
                    "max_output_bytes": 1 << 20,
                },
            )
            assert failed.is_error
            assert "Privileged perf binding failed" in str(failed.content)
            error = _structured(failed)["error"]
            assert error["code"] == "EXTERNAL_TOOL_FAILED"
            assert error["stage"] == "perf_control"
            assert error["recoverable"] is False
            assert error["retryable"] is False
            assert error["details"]["docker_optimization_workload_attempt_charged"] is True
            assert error["details"]["docker_optimization_automatic_retry_allowed"] is False
            assert error["suggested_actions"]
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 1
            assert current.workload_active_seconds_used == 0
            assert current.evidence_bytes_used == 0

            unchanged_retry = await client.call_tool(
                "collect_docker_optimization_workload",
                {
                    "session_id": session["session_id"],
                    "build_id": baseline["artifact_id"],
                    "mode": "record",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 5,
                    "max_output_bytes": 1 << 20,
                },
            )
            assert unchanged_retry.is_error
            assert "stopped after a failed attempt" in str(unchanged_retry.content)
            assert runtime.snapshot(cast(str, session["session_id"])).workload_runs_used == 1

            (project / "src/app").write_bytes(b"candidate-after-collection-failure")
            blocked_build = await client.call_tool(
                "build_docker_optimization_candidate",
                {
                    "session_id": session["session_id"],
                    "build_kind": "candidate",
                    "candidate_round": 1,
                },
            )
            assert blocked_build.is_error
            assert "stopped after a failed attempt" in str(blocked_build.content)

            revoked = await client.call_tool(
                "revoke_docker_optimization_session",
                {"session_id": session["session_id"]},
            )
            assert not revoked.is_error

    asyncio.run(exercise())
    assert len(adapter.cleaned) == 1


def test_docker_optimization_confirmation_binds_runtime_lock_without_second_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    runtime_policy_path = project / "runtime-locks.toml"
    runtime_policy_path.write_text(
        render_default_runtime_lock_project_policy(docker_enabled=True),
        encoding="utf-8",
    )
    runtime_policy_path.chmod(0o600)
    runtime_policy = load_runtime_lock_project_policy(
        runtime_policy_path,
        allowed_roots=(project,),
        invoking_uid=os.geteuid(),
    )
    project_identity = inspect_managed_project_root(
        project,
        invoking_uid=os.geteuid(),
    )
    capability = inspect_runtime_lock_capability(
        runtime_policy,
        project_identity_sha256=project_identity.identity_sha256,
        native_pthread_capability=NativeLaunchCapability(
            target_scope="host_launched_workload",
            launch_backend="host_launcher",
            availability="available",
            target_identity_sha256=None,
            target_label="native-pthread",
            probe_sha256="2" * 64,
            runtime_glibc_version="2.41",
            supported_semantics=("exact", "thresholded"),
            supported_lock_surfaces=("condition", "mutex", "rwlock_read", "rwlock_write"),
            limitations=("Only an explicitly launched workload is visible.",),
        ),
    )
    probe = project / "libperflens-pthread-probe.so"
    probe.write_bytes(b"fixed packaged probe")
    probe.chmod(0o644)
    probe_policy = NativePthreadProbePolicy(
        path=probe,
        sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        owner_uid=os.geteuid(),
    )
    probe_discovery = NativePthreadProbeDiscovery(
        availability="available",
        policy=probe_policy,
        identity=None,
        limitations=(),
    )

    def reject_internal_session(*_args: object, **_kwargs: object) -> None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "perf_control",
            "Synthetic post-authorization collection stop",
            recoverable=True,
        )

    monkeypatch.setattr(
        "perflens.mcp.server.discover_native_pthread_probe_policy",
        lambda: probe_discovery,
    )
    monkeypatch.setattr(
        "perflens.mcp.server.ExistingDockerRuntime.authorize_optimization_build",
        reject_internal_session,
    )
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            allow_runtime_locks=True,
            docker_project_config=project / "container-workload.toml",
            runtime_lock_project_config=runtime_policy_path,
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
            runtime_lock_capability_factory=lambda: capability,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            preview_result = await client.call_tool(
                "preview_docker_optimization_session",
                {
                    "allowed_modes": ["stat", "record"],
                    "runtime_lock_adapters": ["native_pthread"],
                },
            )
            assert not preview_result.is_error, str(preview_result.content)
            preview = _structured(preview_result)
            assert preview["schema_version"] == "1.1"
            assert preview["runtime_lock_scope"]["allowed_adapters"] == ["native_pthread"]
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
            assert (
                session["runtime_lock_scope"]["content_sha256"]
                == preview["runtime_lock_scope"]["content_sha256"]
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
            failed = await client.call_tool(
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
            assert failed.is_error
            assert "Synthetic post-authorization collection stop" in str(failed.content)
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 1
            assert current.runtime_lock_runs_used == 0
            assert current.runtime_lock_status == "unavailable"

    asyncio.run(exercise())
    assert not tuple(artifact_root.glob("*.runtime-lock-session.json"))
    assert len(adapter.cleaned) == 1


def test_docker_optimization_rejects_runtime_lock_outside_parent_preview_without_charge(
    tmp_path: Path,
) -> None:
    from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

    runtime, project, adapter = make_optimization_runtime(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            allow_automatic_collection=True,
            allow_docker_targets=True,
            allow_docker_optimization=True,
            docker_project_config=project / "container-workload.toml",
            collector_socket=tmp_path / "collector.sock",
            automatic_collection_policy=AutomaticCollectionPolicy(
                enabled=True,
                allowed_modes=("stat", "record"),
            ),
            docker_optimization_runtime_factory=lambda: runtime,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            preview = _structured(
                await client.call_tool(
                    "preview_docker_optimization_session",
                    {"allowed_modes": ["stat", "record"]},
                )
            )
            assert preview["schema_version"] == "1.0"
            assert preview["runtime_lock_scope"] is None
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
                },
            )
            assert rejected.is_error
            assert "outside the parent Docker authorization" in str(rejected.content)
            current = runtime.snapshot(cast(str, session["session_id"]))
            assert current.workload_runs_used == 0
            assert current.runtime_lock_runs_used is None

    asyncio.run(exercise())
    assert not tuple(artifact_root.glob("*.runtime-lock-*.json"))
    assert len(adapter.cleaned) == 1


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
            self.closed = False

        def capture(self) -> object:
            assert not self.closed
            snapshot = object()
            resource_captures.append(snapshot)
            return snapshot

        def close(self) -> None:
            self.closed = True

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

            missing_modes = await client.call_tool(
                "authorize_docker_session",
                {
                    "container_reference": "service",
                    "container_pid": 12,
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    ),
                },
            )
            assert missing_modes.is_error

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
    record_collection = _fake_docker_collection(tmp_path, target, mode="record")
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
    wait_timeouts: list[float] = []
    workload_accounting_windows: list[tuple[float | None, float | None, int, float]] = []
    requests: list[CollectionPlanRequest] = []
    plan_denied = {"value": False}

    class FakeCoordinator:
        def release(self, prepared: SimpleNamespace) -> None:
            operations.append("release")
            prepared.state = "released"

        def wait(self, prepared: SimpleNamespace, *, timeout_seconds: float) -> int:
            assert 0 < timeout_seconds <= 30
            wait_timeouts.append(timeout_seconds)
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
            self.closed = False

        def capture(self) -> object:
            assert not self.closed
            self.capture_count += 1
            operations.append(f"cgroup-{self.capture_count}")
            return object()

        def close(self) -> None:
            if not self.closed:
                self.closed = True
                operations.append("cgroup-close")

    class FakeCgroupMonitor:
        latest: FakeCgroupMonitor | None = None

        def __init__(self, reader: FakeCgroupReader, baseline: object) -> None:
            self.reader = reader
            self.baseline = baseline
            self.started = False
            self.observed_lifecycle_end: float | None = None
            type(self).latest = self

        def start(self) -> None:
            assert not self.started
            self.started = True
            self.reader.capture()

        @property
        def lifecycle_ended_monotonic(self) -> float | None:
            return self.observed_lifecycle_end

        def finish(self) -> object:
            assert self.started
            return self.reader.capture()

        def stop(self) -> None:
            return None

    def fake_build_resource(
        _reader: FakeCgroupReader,
        _before: object,
        _after: object,
        *,
        source_collection_id: str,
        source_output_sha256: str,
    ):
        operations.append("resource")
        expected_collection = (
            record_collection
            if source_output_sha256 == record_collection.output_sha256
            else collection
        )
        assert source_collection_id == expected_collection.collection_id
        assert source_output_sha256 == expected_collection.output_sha256
        return resource_context

    class FakePinnedProcessRoot:
        def close(self) -> None:
            operations.append("module-root-close")

    pinned_process_root = FakePinnedProcessRoot()
    pin_failure = {"value": False}

    def fake_pin_process_root(pinned_target: ContainerTargetArtifact) -> FakePinnedProcessRoot:
        assert pinned_target == target
        if pin_failure["value"]:
            operations.append("module-root-pin-unavailable")
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "container_symbols",
                "simulated unreadable process root",
                recoverable=True,
            )
        operations.append("module-root-pin")
        return pinned_process_root

    def fake_capture_module_snapshot(
        captured_collection: CollectionArtifact,
        **kwargs: object,
    ) -> None:
        assert captured_collection == record_collection
        expected_root = None if pin_failure["value"] else pinned_process_root
        assert kwargs["pinned_process_root"] is expected_root
        operations.append("module-snapshot")
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "container_symbols",
            "simulated post-collection symbol conversion failure",
        )

    class FakeDockerRuntime:
        def __init__(self, **_kwargs: object) -> None:
            self.prepare_count = 0

        def authorize_managed(
            self,
            *,
            explicit_authorization: str,
            allowed_modes: tuple[str, ...],
        ):
            assert explicit_authorization.startswith("I_EXPLICITLY_AUTHORIZE")
            assert allowed_modes == ("stat",)
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
        plan = _fake_docker_plan(mode="record" if request.mode == "record" else "stat")
        if plan_denied["value"]:
            return plan.model_copy(
                update={
                    "policy_status": "denied",
                    "warnings": ("simulated automatic-collection policy denial",),
                }
            )
        return plan

    def fake_assert_current(
        _plan: CollectionPlanArtifact,
        **_kwargs: object,
    ) -> None:
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
        observe_lifecycle_end = False

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def collect(
            self,
            selected_plan: CollectionPlanArtifact,
            *,
            ready_callback: Any = None,
        ) -> CollectionArtifact:
            operations.append("broker")
            assert ready_callback is not None
            for _ in range(self.callback_count):
                ready_callback()
            if self.observe_lifecycle_end:
                assert FakeCgroupMonitor.latest is not None
                FakeCgroupMonitor.latest.observed_lifecycle_end = time.monotonic()
            if self.fail:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "collector_broker",
                    "simulated managed Docker collection failure",
                )
            return record_collection if selected_plan.mode == "record" else collection

    monkeypatch.setattr("perflens.mcp.server.ExistingDockerRuntime", fake_runtime_factory)
    monkeypatch.setattr("perflens.mcp.server.create_collection_plan", fake_create_plan)
    monkeypatch.setattr("perflens.mcp.server.assert_plan_current", fake_assert_current)
    monkeypatch.setattr("perflens.mcp.server.CollectorBrokerClient", FakeBrokerClient)
    monkeypatch.setattr("perflens.mcp.server.CgroupV2ResourceReader", FakeCgroupReader)
    monkeypatch.setattr("perflens.mcp.server.CgroupSnapshotMonitor", FakeCgroupMonitor)
    monkeypatch.setattr(
        "perflens.mcp.server.pin_container_process_root",
        fake_pin_process_root,
    )
    monkeypatch.setattr(
        "perflens.mcp.server.capture_container_module_snapshot",
        fake_capture_module_snapshot,
    )
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
        assert kwargs == {
            "source_format": "auto",
            "benchmark_name": None,
            "output_owner_uid": target.host_uid,
        }
        operations.append("benchmark")
        return benchmark

    monkeypatch.setattr(
        "perflens.mcp.server.load_managed_benchmark",
        fake_load_benchmark,
    )

    def track_workload_accounting(
        *,
        workload_started_monotonic: float | None,
        workload_finished_monotonic: float | None,
        workload_timeout_seconds: int,
        now_monotonic: float,
    ) -> int:
        workload_accounting_windows.append(
            (
                workload_started_monotonic,
                workload_finished_monotonic,
                workload_timeout_seconds,
                now_monotonic,
            )
        )
        return _managed_workload_active_seconds(
            workload_started_monotonic=workload_started_monotonic,
            workload_finished_monotonic=workload_finished_monotonic,
            workload_timeout_seconds=workload_timeout_seconds,
            now_monotonic=now_monotonic,
        )

    monkeypatch.setattr(
        "perflens.mcp.server._managed_workload_active_seconds",
        track_workload_accounting,
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
                allowed_modes=("record", "stat"),
                max_duration_seconds=10,
                max_output_bytes=1000,
            ),
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            missing_modes = await client.call_tool(
                "authorize_managed_docker_session",
                {
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    )
                },
            )
            assert missing_modes.is_error

            authorized = await client.call_tool(
                "authorize_managed_docker_session",
                {
                    "authorization": (
                        "I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_PERFORMANCE_SESSION"
                    ),
                    "allowed_modes": ["stat"],
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

            # Exercise the same internal accounting channel used by the outer
            # optimization tool, while retaining the real managed producer here.
            managed_tool = server._tool_manager.get_tool(  # pyright: ignore[reportPrivateUsage]
                "collect_managed_docker_workload"
            )
            assert managed_tool is not None
            cells = managed_tool.fn.__closure__
            assert cells is not None
            managed_cells = dict(
                zip(managed_tool.fn.__code__.co_freevars, cells, strict=True)
            )
            parent_active_seconds = cast(
                dict[str, int], managed_cells["managed_active_seconds"].cell_contents
            )
            parent_active_seconds[active_session.session_id] = 0
            FakeBrokerClient.observe_lifecycle_end = True
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
            FakeBrokerClient.observe_lifecycle_end = False
            assert not result.is_error
            reference = _structured(result)
            assert len(workload_accounting_windows) == 1
            accounting_start, accounting_finish, accounting_limit, accounting_now = (
                workload_accounting_windows[0]
            )
            assert accounting_start is not None
            assert accounting_finish is not None
            assert accounting_start <= accounting_finish <= accounting_now
            assert accounting_limit == 30
            assert parent_active_seconds[active_session.session_id] == (
                _managed_workload_active_seconds(
                    workload_started_monotonic=accounting_start,
                    workload_finished_monotonic=accounting_finish,
                    workload_timeout_seconds=accounting_limit,
                    now_monotonic=accounting_now,
                )
            )
            assert reference["artifact_id"] == container_run.run_id
            assert reference["summary"]["docker_session_state"] == "exhausted"
            assert reference["summary"]["container_resource_context_id"] == (
                resource_context.resource_context_id
            )
            assert reference["summary"]["container_resource_collection_id"] == (
                collection.collection_id
            )
            assert reference["summary"]["container_measurement_quality"] == "verified"
            assert reference["summary"]["evidence_bytes"] == collection.output_bytes
            assert wait_timeouts[0] == 15.0
            measurement_id = reference["summary"]["container_measurement_id"]
            assert isinstance(measurement_id, str)
            assert operations == [
                "prepare",
                "cgroup-1",
                "broker",
                "cgroup-2",
                "release",
                "wait",
                "benchmark",
                "cgroup-3",
                "resource",
                "cgroup-close",
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
            accounting_count_before_symbol_failure = len(workload_accounting_windows)
            FakeBrokerClient.observe_lifecycle_end = True
            symbol_failure = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "record",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            FakeBrokerClient.observe_lifecycle_end = False
            assert symbol_failure.is_error
            assert "simulated post-collection symbol conversion failure" in str(
                symbol_failure.content
            )
            symbol_failure_accounting = workload_accounting_windows[
                accounting_count_before_symbol_failure:
            ]
            assert len(symbol_failure_accounting) == 2
            assert FakeCgroupMonitor.latest is not None
            observed_failure_end = FakeCgroupMonitor.latest.observed_lifecycle_end
            assert observed_failure_end is not None
            assert all(
                accounting_finish == observed_failure_end
                for _, accounting_finish, _, _ in symbol_failure_accounting
            )
            assert operations == [
                "prepare",
                "module-root-pin",
                "cgroup-1",
                "broker",
                "cgroup-2",
                "release",
                "module-snapshot",
                "module-root-close",
                "cgroup-close",
                "cleanup",
                "finish",
            ]

            operations.clear()
            prepared.state = "prepared"
            prepared.exit_code = None
            pin_failure["value"] = True
            unavailable_pin = await client.call_tool(
                "collect_managed_docker_workload",
                {
                    "session_id": active_session.session_id,
                    "mode": "record",
                    "duration_seconds": 1,
                    "workload_timeout_seconds": 30,
                    "event_source": "software_only",
                    "max_output_bytes": 1000,
                },
            )
            assert unavailable_pin.is_error
            assert "simulated post-collection symbol conversion failure" in str(
                unavailable_pin.content
            )
            assert operations == [
                "prepare",
                "module-root-pin-unavailable",
                "cgroup-1",
                "broker",
                "cgroup-2",
                "release",
                "module-snapshot",
                "cgroup-close",
                "cleanup",
                "finish",
            ]
            pin_failure["value"] = False

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
                "cgroup-1",
                "broker",
                "cgroup-2",
                "release",
                "cgroup-close",
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
            assert operations == [
                "prepare",
                "cgroup-1",
                "broker",
                "cgroup-close",
                "cleanup",
                "finish",
            ]

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
                "cgroup-1",
                "broker",
                "cgroup-2",
                "release",
                "cgroup-close",
                "cleanup",
                "finish",
            ]

    asyncio.run(exercise())


def test_managed_workload_timeout_is_gate_relative_and_keeps_subsecond_precision() -> None:
    assert _remaining_managed_workload_timeout_seconds(
        workload_started_monotonic=100.0,
        workload_timeout_seconds=3,
        now_monotonic=101.041,
    ) == pytest.approx(1.959)
    assert (
        _remaining_managed_workload_timeout_seconds(
            workload_started_monotonic=100.0,
            workload_timeout_seconds=3,
            now_monotonic=99.5,
        )
        == 3.0
    )


def test_observed_managed_workload_end_excludes_post_exit_publication_time() -> None:
    assert _validate_observed_managed_workload_end(
        workload_started_monotonic=100.0,
        lifecycle_ended_monotonic=102.1,
        workload_timeout_seconds=3,
        now_monotonic=104.5,
    ) == pytest.approx(102.1)
    assert (
        _validate_observed_managed_workload_end(
            workload_started_monotonic=100.0,
            lifecycle_ended_monotonic=None,
            workload_timeout_seconds=3,
            now_monotonic=102.5,
        )
        is None
    )


def test_observed_managed_workload_end_rejects_late_exit() -> None:
    with pytest.raises(PerfLensError) as captured:
        _validate_observed_managed_workload_end(
            workload_started_monotonic=100.0,
            lifecycle_ended_monotonic=103.001,
            workload_timeout_seconds=3,
            now_monotonic=104.5,
        )

    assert captured.value.code == ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert captured.value.stage == "docker_workload"


@pytest.mark.parametrize(
    ("started", "finished", "now"),
    (
        (float("nan"), 102.0, 103.0),
        (100.0, float("nan"), 103.0),
        (100.0, 102.0, float("nan")),
        (100.0, 99.9, 103.0),
        (100.0, 103.1, 103.0),
    ),
)
def test_observed_managed_workload_end_rejects_invalid_timestamps(
    started: float,
    finished: float,
    now: float,
) -> None:
    with pytest.raises(PerfLensError) as captured:
        _validate_observed_managed_workload_end(
            workload_started_monotonic=started,
            lifecycle_ended_monotonic=finished,
            workload_timeout_seconds=3,
            now_monotonic=now,
        )

    assert captured.value.code == ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.stage == "docker_resource_context"


def test_managed_workload_accounting_excludes_setup_and_finalization_time() -> None:
    assert (
        _managed_workload_active_seconds(
            workload_started_monotonic=None,
            workload_finished_monotonic=None,
            workload_timeout_seconds=3,
            now_monotonic=500.0,
        )
        == 0
    )
    assert (
        _managed_workload_active_seconds(
            workload_started_monotonic=100.0,
            workload_finished_monotonic=101.041,
            workload_timeout_seconds=3,
            now_monotonic=500.0,
        )
        == 2
    )
    assert (
        _managed_workload_active_seconds(
            workload_started_monotonic=100.0,
            workload_finished_monotonic=None,
            workload_timeout_seconds=3,
            now_monotonic=103.5,
        )
        == 3
    )


@pytest.mark.parametrize("value", (None, 0, -1, True, "120"))
def test_managed_evidence_bytes_rejects_missing_or_invalid_projection(value: object) -> None:
    reference = ArtifactReference(
        artifact_id="container-run-test",
        artifact_type="container-run",
        uri="perflens://container-run/test",
        summary={} if value is None else {"evidence_bytes": cast(Any, value)},
    )

    with pytest.raises(PerfLensError, match="valid evidence byte count"):
        _managed_evidence_bytes(reference)


def test_managed_evidence_bytes_accepts_verified_positive_projection() -> None:
    reference = ArtifactReference(
        artifact_id="container-run-test",
        artifact_type="container-run",
        uri="perflens://container-run/test",
        summary={"evidence_bytes": 120},
    )

    assert _managed_evidence_bytes(reference) == 120


def test_optimization_workload_charges_managed_evidence_bytes(tmp_path: Path) -> None:
    from tests.unit.test_docker_optimization_runtime import make_optimization_runtime

    runtime, _, _ = make_optimization_runtime(tmp_path)
    preview = runtime.preview(allowed_modes=("stat",))
    authorized = runtime.authorize(
        preview_id=preview.preview.preview_id,
        preview_content_sha256=preview.preview.content_sha256,
        authorization_summary_sha256=preview.preview.authorization_summary_sha256,
        explicit_authorization=("I_EXPLICITLY_AUTHORIZE_THIS_BOUNDED_DOCKER_OPTIMIZATION_SESSION"),
    )
    baseline = runtime.build(
        authorized.session_id,
        build_kind="baseline",
        candidate_round=0,
    )
    lease = runtime.begin_workload(
        authorized.session_id,
        build_id=baseline.build.build_id,
        mode="stat",
        reserve_active_seconds=30,
        reserve_evidence_bytes=1 << 20,
    )
    reference = ArtifactReference(
        artifact_id="container-run-test",
        artifact_type="container-run",
        uri="perflens://container-run/test",
        summary={"evidence_bytes": 323_784},
    )

    completed = _finish_optimization_workload_with_evidence(
        runtime,
        authorized.session_id,
        lease,
        actual_active_seconds=1.25,
        collected=reference,
    )

    assert completed.workload_runs_used == 1
    assert completed.workload_active_seconds_used == 2
    assert completed.evidence_bytes_used == 323_784


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


def test_runtime_lock_evidence_is_analyzed_queried_and_diagnosed_without_raw_input(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    with fixture.open("rb") as source:
        evidence = import_runtime_lock_ndjson(source)
    store.save(
        evidence,
        evidence.runtime_lock_evidence_id,
        "runtime-lock-evidence",
    )
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = _structured(
                await client.call_tool(
                    "analyze_runtime_lock_evidence",
                    {"runtime_lock_evidence_id": evidence.runtime_lock_evidence_id},
                )
            )
            assert analyzed["artifact_type"] == "runtime-lock-analysis"
            summary = cast(dict[str, Any], analyzed["summary"])
            assert summary["runtime"] == "python"
            assert summary["measurement_semantics"] == "exact"
            assert summary["verification_status"] == "partial"
            analysis_id = cast(str, analyzed["artifact_id"])

            verification = _structured(
                await client.call_tool(
                    "verify_runtime_lock_analysis",
                    {"runtime_lock_analysis_id": analysis_id},
                )
            )
            assert verification["verification_status"] == "partial"
            assert all(
                check["status"] != "failed"
                for check in cast(list[dict[str, Any]], verification["checks"])
            )

            hotspots = _structured(
                await client.call_tool(
                    "list_runtime_lock_hotspots",
                    {
                        "runtime_lock_analysis_id": analysis_id,
                        "projection": "lock",
                        "limit": 1,
                    },
                )
            )
            assert hotspots["total_items"] == 1
            assert len(cast(list[object], hotspots["items"])) == 1
            assert hotspots["coverage"]["omitted_row_count"] == 0

            paths = _structured(
                await client.call_tool(
                    "get_runtime_lock_call_paths",
                    {"runtime_lock_analysis_id": analysis_id, "limit": 1},
                )
            )
            assert paths["total_items"] == 1
            assert paths["items"][0]["stack_id"] == paths["stacks"][0]["stack_id"]
            assert not paths["stacks"][0]["frames"][0]["source_file"].startswith("/")

            diagnosis = _structured(
                await client.call_tool(
                    "build_runtime_lock_diagnosis_bundle",
                    {"runtime_lock_analysis_id": analysis_id},
                )
            )
            assert diagnosis["artifact_type"] == "runtime-lock-diagnosis"
            diagnosis_id = cast(str, diagnosis["artifact_id"])

            page = _structured(
                await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": diagnosis_id,
                        "artifact_type": "runtime-lock-diagnosis",
                    },
                )
            )
            assert '"runtime_lock_diagnosis_id"' in cast(str, page["text"])
            assert "pthread_mutex_t" not in cast(str, page["text"])
            assert "/home/" not in cast(str, page["text"])

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
