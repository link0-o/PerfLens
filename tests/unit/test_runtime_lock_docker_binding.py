from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import cast

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.docker import (
    ContainerCgroupIdentity,
    ContainerNamespaceIdentity,
    ContainerRunArtifact,
    ContainerTargetArtifact,
)
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeLockEvidenceArtifact
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.docker_binding import bind_runtime_lock_evidence_to_container
from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe


def _evidence(fixture_root: Path) -> RuntimeLockEvidenceArtifact:
    source = (fixture_root / "runtime_locks/native-pthread-exact.ndjson").read_bytes()
    return convert_native_pthread_probe(BytesIO(source)).evidence


def _execution_binding(evidence: RuntimeLockEvidenceArtifact) -> RuntimeLockAdapterExecutionBinding:
    toolchain = derive_runtime_lock_toolchain_identity(())
    configuration = "1" * 64
    metadata = "2" * 64
    runtime_version = evidence.source.runtime_version
    assert runtime_version is not None
    execution_identity = derive_runtime_lock_adapter_execution_identity(
        "native_pthread",
        "native-pthread-adapter-v1",
        "pthread-preload",
        runtime_version,
        "exact",
        "exact",
        None,
        toolchain,
        configuration,
        metadata,
        configuration,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="native_pthread",
        adapter_version="native-pthread-adapter-v1",
        backend_id="pthread-preload",
        runtime_version=runtime_version,
        profile="exact",
        measurement_semantics="exact",
        tools=(),
        toolchain_identity_sha256=toolchain,
        configuration_sha256=configuration,
        metadata_sha256=metadata,
        runtime_payload_identity_sha256=configuration,
        execution_identity_sha256=execution_identity,
    )


def _target_and_run() -> tuple[ContainerTargetArtifact, ContainerRunArtifact]:
    target_provisional = ContainerTargetArtifact(
        schema_version="1.1",
        perflens_version="0.4.0",
        target_id="container-target-" + "3" * 20,
        created_at="2026-08-31T00:00:00+00:00",
        target_kind="managed_temporary_container",
        container_identity_sha256="4" * 64,
        image_identity_sha256="5" * 64,
        container_pid=4242,
        host_pid=42_424,
        host_uid=1000,
        container_uid=1000,
        uid_map_sha256="6" * 64,
        host_start_time_ticks=77,
        executable_name="workload",
        namespace=ContainerNamespaceIdentity(
            pid_namespace_inode=101,
            user_namespace_inode=102,
            mount_namespace_inode=103,
            cgroup_namespace_inode=104,
        ),
        cgroup=ContainerCgroupIdentity(inode=105, identity_sha256="7" * 64),
        uid_mapping="rootful_same_uid",
        adapter_recipe_id="local-docker-managed-v1",
        adapter_sha256="8" * 64,
        identity_fingerprint="9" * 64,
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
    run_provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version="0.4.0",
        run_id="container-run-" + "a" * 20,
        created_at="2026-08-31T00:00:03+00:00",
        session_id="container-session-" + "b" * 20,
        workload_spec_sha256="c" * 64,
        container_identity_sha256=target.container_identity_sha256,
        image_identity_sha256=target.image_identity_sha256,
        target_identity_sha256=target.identity_fingerprint,
        container_pid=target.container_pid,
        host_pid=target.host_pid,
        host_start_time_ticks=target.host_start_time_ticks,
        started_at="2026-08-31T00:00:00+00:00",
        finished_at="2026-08-31T00:00:02+00:00",
        status="exited",
        exit_code=0,
        cleanup_status="removed",
        content_sha256="0" * 64,
    )
    run = run_provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                run_provisional,
                exclude={"content_sha256"},
            )
        }
    )
    return target, run


def test_runtime_lock_evidence_is_rebound_to_verified_container_artifacts(
    fixture_root: Path,
) -> None:
    evidence = _evidence(fixture_root)
    binding = _execution_binding(evidence)
    target, run = _target_and_run()

    bound = bind_runtime_lock_evidence_to_container(
        evidence,
        execution_binding=binding,
        target=target,
        run=run,
    )

    assert bound.target.target_kind == "docker"
    assert bound.target.target_pid == target.container_pid
    assert bound.target.target_uid == target.container_uid
    assert bound.target.container_reference is not None
    assert bound.target.container_reference.container_target_id == target.target_id
    assert bound.target.container_reference.container_run_id == run.run_id
    assert bound.source.adapter_id == "native_pthread"
    assert bound.source.adapter_execution_identity_sha256 == binding.execution_identity_sha256
    assert bound.content_bytes == len(serialize_json(bound))
    assert bound.evidence_fingerprint == compute_runtime_lock_evidence_fingerprint(bound)
    assert bound.content_sha256 == compute_runtime_lock_evidence_content_sha256(bound)


@pytest.mark.parametrize(
    ("evidence_update", "binding_update", "target_update", "run_update"),
    (
        ({"schema_version": "1.0"}, {}, {}, {}),
        ({"target": {"target_kind": "docker"}}, {}, {}, {}),
        ({"target": {"target_pid": 99}}, {}, {}, {}),
        ({"target": {"target_uid": 99}}, {}, {}, {}),
        ({"target": {"target_start_time_ticks": 99}}, {}, {}, {}),
        ({}, {"adapter_id": "java_jfr"}, {}, {}),
        ({}, {"measurement_semantics": "thresholded"}, {}, {}),
        ({}, {"runtime_version": "glibc-2.36"}, {}, {}),
        ({}, {}, {"container_uid": None}, {}),
        ({}, {}, {}, {"host_pid": 77}),
        ({}, {}, {}, {"target_identity_sha256": "f" * 64}),
    ),
)
def test_runtime_lock_container_binding_rejects_unverified_identity_or_semantics(
    fixture_root: Path,
    evidence_update: dict[str, object],
    binding_update: dict[str, object],
    target_update: dict[str, object],
    run_update: dict[str, object],
) -> None:
    evidence = _evidence(fixture_root)
    if "target" in evidence_update:
        target_values = cast(dict[str, object], evidence_update.pop("target"))
        evidence_update["target"] = evidence.target.model_copy(update=target_values)
    evidence = evidence.model_copy(update=evidence_update)
    binding = _execution_binding(evidence).model_copy(update=binding_update)
    target, run = _target_and_run()
    target = target.model_copy(update=target_update)
    run = run.model_copy(update=run_update)

    with pytest.raises(PerfLensError) as raised:
        bind_runtime_lock_evidence_to_container(
            evidence,
            execution_binding=binding,
            target=target,
            run=run,
        )
    assert raised.value.code is ErrorCode.PATH_SAFETY_VIOLATION
