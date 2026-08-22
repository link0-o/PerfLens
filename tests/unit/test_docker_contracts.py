from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError
from tests.support.docker import make_container_resource_context

from perflens.contracts.artifacts import CollectionArtifact, CollectionPlanArtifact
from perflens.contracts.docker import (
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerOptimizationSessionArtifact,
    ContainerProcessInventoryArtifact,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerTargetArtifact,
    ContainerWorkloadSpecArtifact,
    DockerRuntimeCapabilityArtifact,
    derive_container_resource_context_id,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _capability() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "capability_id": "docker-capability-" + "a" * 20,
        "checked_at": "2026-08-21T00:00:00+00:00",
        "status": "available",
        "endpoint_kind": "local_rootless",
        "daemon_mode": "rootless",
        "docker_cli": {
            "path": "/usr/bin/docker",
            "version": "Docker version 28.0.0",
            "binary_sha256": SHA_A,
        },
        "api_version": "1.47",
        "server_operating_system": "linux",
        "cgroup_version": "v2",
        "existing_container_discovery": True,
        "managed_container_execution": True,
        "content_sha256": SHA_B,
    }


def _target() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "target_id": "container-target-" + "a" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "target_kind": "existing_container",
        "container_identity_sha256": SHA_A,
        "image_identity_sha256": SHA_B,
        "container_pid": 12,
        "host_pid": 1234,
        "host_uid": 1000,
        "host_start_time_ticks": 9876,
        "executable_name": "python3",
        "namespace": {
            "pid_namespace_inode": 101,
            "user_namespace_inode": 102,
            "mount_namespace_inode": 103,
            "cgroup_namespace_inode": 104,
        },
        "cgroup": {"version": "v2", "inode": 105, "identity_sha256": SHA_C},
        "uid_mapping": "rootless_same_uid",
        "adapter_recipe_id": "local-docker-read-v1",
        "adapter_sha256": SHA_C,
        "identity_fingerprint": SHA_A,
        "allowed_conclusions": ["container process identity verified"],
        "forbidden_conclusions": ["container-wide perf attribution"],
        "content_sha256": SHA_B,
    }


def _snapshot(observed_at: str, *, usage: int) -> dict[str, Any]:
    return {
        "observed_at": observed_at,
        "cpu_usage_usec": usage,
        "cpu_user_usec": usage,
        "cpu_system_usec": 0,
        "cpu_nr_periods": 2,
        "cpu_nr_throttled": 0,
        "cpu_throttled_usec": 0,
        "cpu_quota_usec": None,
        "cpu_period_usec": 100000,
        "cpuset_cpus_effective": "0-3",
        "memory_current_bytes": 4096,
        "memory_max_bytes": None,
        "memory_events": [["oom", 0], ["oom_kill", 0]],
        "memory_pressure": {"some_total_us": 1, "full_total_us": 0},
        "io_devices": [
            {
                "major": 8,
                "minor": 0,
                "read_bytes": 10,
                "write_bytes": 20,
                "read_ios": 1,
                "write_ios": 2,
            }
        ],
        "io_limits": [
            {
                "major": 8,
                "minor": 0,
                "read_bps": 1048576,
                "write_bps": None,
                "read_iops": 1000,
                "write_iops": None,
            }
        ],
        "io_pressure": {"some_total_us": 2, "full_total_us": 0},
        "pids_current": 2,
        "pids_max": 64,
    }


def _bind_resource_context_id(payload: dict[str, Any]) -> None:
    payload["resource_context_id"] = derive_container_resource_context_id(
        container_identity_sha256=payload["container_identity_sha256"],
        cgroup_identity_sha256=payload["cgroup_identity_sha256"],
        source_collection_id=payload["source_collection_id"],
        source_output_sha256=payload["source_output_sha256"],
        before_observed_at=payload["before"]["observed_at"],
        after_observed_at=payload["after"]["observed_at"],
        created_at=payload["created_at"],
    )


def _workload() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "workload_spec_id": "container-workload-" + "a" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "project_identity_sha256": SHA_A,
        "image_digest": "sha256:" + "d" * 64,
        "container_gate_sha256": "e" * 64,
        "entrypoint": "/usr/bin/python3",
        "arguments": ["/workspace/bench.py", "--rounds", "3"],
        "working_directory": "/workspace",
        "container_user": "1000:1000",
        "resources": {"cpus": 2, "memory_bytes": 536870912, "pids": 64},
        "allowed_modes": ["stat", "record", "sched", "off_cpu", "lock"],
        "authorization_mode": "bounded_session",
        "workload_fingerprint": SHA_B,
        "content_sha256": SHA_C,
    }


def test_available_docker_capability_is_local_linux_and_cgroup_v2() -> None:
    capability = DockerRuntimeCapabilityArtifact.model_validate(_capability())
    assert capability.endpoint_kind == "local_rootless"
    assert capability.remote_endpoint_supported is False
    assert capability.build_or_pull_supported is False

    invalid = _capability()
    invalid["cgroup_version"] = "v1"
    with pytest.raises(ValidationError):
        DockerRuntimeCapabilityArtifact.model_validate(invalid)


def test_unavailable_capability_requires_a_bounded_reason() -> None:
    unavailable = _capability()
    unavailable.update(
        status="unavailable",
        endpoint_kind="missing",
        daemon_mode="unknown",
        docker_cli=None,
        server_operating_system="unknown",
        cgroup_version="unknown",
        existing_container_discovery=False,
        managed_container_execution=False,
    )
    with pytest.raises(ValidationError):
        DockerRuntimeCapabilityArtifact.model_validate(unavailable)
    unavailable["limitations"] = ["Docker CLI is not installed"]
    assert DockerRuntimeCapabilityArtifact.model_validate(unavailable).status == "unavailable"


def test_container_target_binds_kernel_identity_and_rootful_risk() -> None:
    assert ContainerTargetArtifact.model_validate(_target()).host_pid == 1234

    rootful = _target()
    rootful["uid_mapping"] = "rootful_cross_uid"
    with pytest.raises(ValidationError):
        ContainerTargetArtifact.model_validate(rootful)
    rootful["rootful_risk_authorized"] = True
    assert ContainerTargetArtifact.model_validate(rootful).rootful_risk_authorized


def test_container_target_recipe_matches_workflow() -> None:
    target = _target()
    target["target_kind"] = "managed_temporary_container"
    with pytest.raises(ValidationError):
        ContainerTargetArtifact.model_validate(target)
    target["adapter_recipe_id"] = "local-docker-managed-v1"
    assert ContainerTargetArtifact.model_validate(target).target_kind.endswith("container")


def test_process_inventory_never_contains_argv_and_recommendation_is_consistent() -> None:
    inventory = {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "inventory_id": "container-inventory-" + "a" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "container_identity_sha256": SHA_A,
        "observation_duration_ms": 100,
        "candidates": [
            {
                "container_pid": 12,
                "host_pid": 1234,
                "executable_name": "python3",
                "cpu_delta_ticks": 15,
                "recommendation": "dominant",
            }
        ],
        "candidate_count": 1,
        "candidates_truncated": False,
        "automatic_recommendation": "unique",
        "recommended_host_pid": 1234,
        "content_sha256": SHA_B,
    }
    artifact = ContainerProcessInventoryArtifact.model_validate(inventory)
    assert artifact.recommended_host_pid == 1234
    assert "argv" not in artifact.model_dump_json()
    inventory["recommended_host_pid"] = 9999
    with pytest.raises(ValidationError):
        ContainerProcessInventoryArtifact.model_validate(inventory)


def test_resource_context_is_container_scoped_and_time_ordered() -> None:
    context = {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "resource_context_id": "container-resource-" + "a" * 20,
        "created_at": "2026-08-21T00:00:02+00:00",
        "container_identity_sha256": SHA_A,
        "cgroup_identity_sha256": SHA_B,
        "source_collection_id": "collection-" + "1" * 16,
        "source_output_sha256": SHA_C,
        "before": _snapshot("2026-08-21T00:00:00+00:00", usage=10),
        "after": _snapshot("2026-08-21T00:00:01+00:00", usage=20),
        "delta": {
            "cpu_usage_usec": 10,
            "cpu_user_usec": 10,
            "cpu_system_usec": 0,
            "cpu_nr_periods": 0,
            "cpu_nr_throttled": 0,
            "cpu_throttled_usec": 0,
            "memory_event_deltas": [["oom", 0], ["oom_kill", 0]],
            "io_read_bytes": 0,
            "io_write_bytes": 0,
            "io_read_ios": 0,
            "io_write_ios": 0,
            "memory_pressure_some_usec": 0,
            "memory_pressure_full_usec": 0,
            "io_pressure_some_usec": 0,
            "io_pressure_full_usec": 0,
        },
        "quality_status": "verified",
        "allowed_conclusions": ["container cgroup CPU delta"],
        "forbidden_conclusions": ["target process exclusive resource attribution"],
        "content_sha256": SHA_C,
    }
    _bind_resource_context_id(context)
    artifact = ContainerResourceContextArtifact.model_validate(context)
    assert artifact.scope == "entire_container_cgroup_v2"
    context["after"] = _snapshot("2026-08-20T23:59:59+00:00", usage=20)
    _bind_resource_context_id(context)
    with pytest.raises(ValidationError):
        ContainerResourceContextArtifact.model_validate(context)


@pytest.mark.parametrize(
    "case",
    (
        "delta",
        "created_at",
        "counter_decrease",
        "source_binding",
        "unreported_limit_drift",
        "unreported_io_limit_drift",
        "partial_without_limitations",
        "missing_allowed_conclusions",
        "missing_forbidden_conclusions",
    ),
)
def test_resource_context_rejects_forged_or_unbounded_semantics(
    case: str,
) -> None:
    payload = make_container_resource_context().model_dump(mode="json")
    if case == "delta":
        payload["delta"]["cpu_usage_usec"] = 999
    elif case == "created_at":
        payload["created_at"] = "2026-08-20T23:59:59+00:00"
        _bind_resource_context_id(payload)
    elif case == "counter_decrease":
        payload["after"]["cpu_usage_usec"] = 1
    elif case == "source_binding":
        payload["source_output_sha256"] = "9" * 64
    elif case == "unreported_limit_drift":
        payload["after"]["cpu_quota_usec"] = 50_000
    elif case == "unreported_io_limit_drift":
        payload["after"]["io_limits"][0]["read_bps"] = 2_097_152
    elif case == "partial_without_limitations":
        payload["quality_status"] = "partial"
        payload["limitations"] = []
    elif case == "missing_allowed_conclusions":
        payload["allowed_conclusions"] = []
    else:
        assert case == "missing_forbidden_conclusions"
        payload["forbidden_conclusions"] = []
    with pytest.raises(ValidationError):
        ContainerResourceContextArtifact.model_validate(payload)


def test_resource_context_preserves_unknown_optional_counter_semantics() -> None:
    payload = make_container_resource_context().model_dump(mode="json")
    payload["before"]["cpu_user_usec"] = None
    payload["delta"]["cpu_user_usec"] = None
    payload["quality_status"] = "partial"
    payload["limitations"] = ["cpu.stat omits optional user_usec."]
    artifact = ContainerResourceContextArtifact.model_validate(payload)
    assert artifact.delta.cpu_user_usec is None


def test_workload_spec_has_no_arbitrary_docker_argument_surface() -> None:
    artifact = ContainerWorkloadSpecArtifact.model_validate(_workload())
    assert artifact.network_mode == "none"
    assert artifact.workspace_read_only is True
    schema_text = str(ContainerWorkloadSpecArtifact.model_json_schema())
    for forbidden in ("privileged", "docker_socket", "devices", "extra_capabilities"):
        assert forbidden not in schema_text


@pytest.mark.parametrize("entrypoint", ["python3", "/workspace/../bin/run", "/bin/run\x00x"])
def test_workload_rejects_unsafe_container_entrypoint(entrypoint: str) -> None:
    workload = _workload()
    workload["entrypoint"] = entrypoint
    with pytest.raises(ValidationError):
        ContainerWorkloadSpecArtifact.model_validate(workload)


def test_managed_session_binds_spec_and_budget_without_secret_token() -> None:
    session = {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "session_id": "container-session-" + "a" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "expires_at": "2026-08-21T02:00:00+00:00",
        "target_kind": "managed_temporary_container",
        "authorization_mode": "bounded_session",
        "project_identity_sha256": SHA_A,
        "client_connection_identity_sha256": SHA_B,
        "authorization_receipt_sha256": SHA_C,
        "workload_spec_sha256": SHA_A,
        "allowed_modes": ["stat", "record"],
        "state": "active",
        "max_workload_runs": 6,
        "workload_runs_used": 1,
        "max_active_seconds": 1200,
        "active_seconds_used": 10,
        "max_evidence_bytes": 1048576,
        "evidence_bytes_used": 100,
        "instance_count": 1,
        "content_sha256": SHA_B,
    }
    artifact = ContainerOptimizationSessionArtifact.model_validate(session)
    assert artifact.state == "active"
    assert "token" not in artifact.model_dump_json()
    session["workload_runs_used"] = 7
    with pytest.raises(ValidationError):
        ContainerOptimizationSessionArtifact.model_validate(session)


def test_existing_per_run_session_is_single_use() -> None:
    session = {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "session_id": "container-session-" + "b" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "expires_at": "2026-08-21T00:10:00+00:00",
        "target_kind": "existing_container",
        "authorization_mode": "per_run",
        "project_identity_sha256": SHA_A,
        "client_connection_identity_sha256": SHA_B,
        "authorization_receipt_sha256": SHA_C,
        "existing_target_identity_sha256": SHA_A,
        "allowed_modes": ["stat"],
        "state": "active",
        "max_workload_runs": 1,
        "workload_runs_used": 0,
        "max_active_seconds": 60,
        "active_seconds_used": 0,
        "max_evidence_bytes": 1048576,
        "evidence_bytes_used": 0,
        "instance_count": 0,
        "content_sha256": SHA_B,
    }
    assert ContainerOptimizationSessionArtifact.model_validate(session).max_workload_runs == 1
    session["max_workload_runs"] = 2
    with pytest.raises(ValidationError):
        ContainerOptimizationSessionArtifact.model_validate(session)


def test_container_run_binds_one_session_and_sorted_evidence() -> None:
    run = {
        "schema_version": "1.0",
        "perflens_version": "0.3.1",
        "run_id": "container-run-" + "a" * 20,
        "created_at": "2026-08-21T00:00:00+00:00",
        "session_id": "container-session-" + "a" * 20,
        "workload_spec_sha256": SHA_A,
        "container_identity_sha256": SHA_B,
        "image_identity_sha256": SHA_C,
        "target_identity_sha256": SHA_A,
        "container_pid": 10,
        "host_pid": 1000,
        "host_start_time_ticks": 123,
        "started_at": "2026-08-21T00:00:00+00:00",
        "finished_at": "2026-08-21T00:00:01+00:00",
        "status": "exited",
        "exit_code": 0,
        "collection_ids": ["collection-aaaaaaaaaaaaaaaa", "collection-bbbbbbbbbbbbbbbb"],
        "build_artifact_sha256": [SHA_A, SHA_B],
        "cleanup_status": "removed",
        "content_sha256": SHA_C,
    }
    assert len(ContainerRunArtifact.model_validate(run).collection_ids) == 2
    run["collection_ids"] = ["collection-bbbbbbbbbbbbbbbb", "collection-aaaaaaaaaaaaaaaa"]
    with pytest.raises(ValidationError):
        ContainerRunArtifact.model_validate(run)


def _plan() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "plan_id": "plan-" + "a" * 20,
        "mode": "stat",
        "target_type": "pid",
        "target_pid": 1234,
        "target_uid": 1000,
        "target_start_time_ticks": 123,
        "backend": "privileged_broker",
        "duration_seconds": 1,
        "events": ["task-clock"],
        "requested_event_source": "software_only",
        "max_output_bytes": 1024,
        "expires_at": "2026-08-21T00:01:00+00:00",
        "policy_status": "allowed",
        "required_privilege": "cap_perfmon",
    }


def _collection_target_binding() -> dict[str, Any]:
    target = _target()
    return {
        "target_id": target["target_id"],
        "target_kind": target["target_kind"],
        "target_content_sha256": target["content_sha256"],
        "container_identity_sha256": target["container_identity_sha256"],
        "image_identity_sha256": target["image_identity_sha256"],
        "identity_fingerprint": target["identity_fingerprint"],
        "container_pid": target["container_pid"],
        "host_pid": target["host_pid"],
        "host_uid": target["host_uid"],
        "host_start_time_ticks": target["host_start_time_ticks"],
        "executable_name": target["executable_name"],
        "namespace": target["namespace"],
        "cgroup": target["cgroup"],
        "uid_mapping": target["uid_mapping"],
        "rootful_risk_authorized": target.get("rootful_risk_authorized", False),
        "adapter_recipe_id": target["adapter_recipe_id"],
        "adapter_sha256": target["adapter_sha256"],
    }


def test_collection_plan_docker_binding_is_complete_and_host_is_backward_compatible() -> None:
    assert CollectionPlanArtifact.model_validate(_plan()).target_runtime == "host"
    docker = _plan()
    docker.update(
        target_runtime="docker",
        target_start_time_ticks=9876,
        container_target=_collection_target_binding(),
    )
    validated = CollectionPlanArtifact.model_validate(docker)
    assert validated.container_target is not None
    assert validated.container_target.container_pid == 12
    docker["container_target"]["namespace"].pop("mount_namespace_inode")
    with pytest.raises(ValidationError):
        CollectionPlanArtifact.model_validate(docker)


def test_collection_artifact_rejects_partial_docker_binding() -> None:
    collection: dict[str, Any] = {
        "schema_version": "1.0",
        "collection_id": "collection-a",
        "mode": "stat",
        "target_type": "pid",
        "target_argument_count": 0,
        "target_pid": 1234,
        "target_runtime": "docker",
        "output_path": "/tmp/a.stat.csv",
        "output_sha256": SHA_C,
        "output_bytes": 10,
        "output_format": "perf_stat_delimited",
        "perf_executable": "/usr/bin/perf",
        "started_at": "2026-08-21T00:00:00+00:00",
        "finished_at": "2026-08-21T00:00:01+00:00",
        "duration_seconds": 1,
        "events": ["task-clock"],
        "actual_event_source": "software",
    }
    with pytest.raises(ValidationError):
        CollectionArtifact.model_validate(collection)
    collection["container_target"] = _collection_target_binding()
    assert CollectionArtifact.model_validate(collection).target_runtime == "docker"


def test_public_docker_schemas_exclude_private_docker_data() -> None:
    schemas = (
        DockerRuntimeCapabilityArtifact,
        ContainerTargetArtifact,
        ContainerProcessInventoryArtifact,
        ContainerResourceContextArtifact,
        ContainerWorkloadSpecArtifact,
        ContainerOptimizationSessionArtifact,
        ContainerRunArtifact,
        ContainerMeasurementArtifact,
        ContainerMatchedComparisonArtifact,
    )
    text = "\n".join(str(model.model_json_schema()) for model in schemas)
    for forbidden in (
        "inspect_response",
        "environment_variables",
        "docker_labels",
        "docker_socket_path",
        "host_mount_source",
        "discovered_argv",
        "session_token",
    ):
        assert forbidden not in text
