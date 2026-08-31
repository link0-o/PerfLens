from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterCapabilityReference,
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    RuntimeLockCapabilityArtifact,
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockSessionArtifact,
    RuntimeLockSessionBudget,
    RuntimeLockSessionPreviewArtifact,
    RuntimeLockWorkloadBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_capability_id,
    derive_runtime_lock_comparison_id,
    derive_runtime_lock_preview_id,
    derive_runtime_lock_run_boundaries,
    derive_runtime_lock_run_id,
    derive_runtime_lock_session_artifact_id,
    derive_runtime_lock_toolchain_identity,
    derive_runtime_lock_workload_identity,
)

_ZERO = "0" * 64
_ONE = "1" * 64
_TWO = "2" * 64
_THREE = "3" * 64
_FOUR = "4" * 64
_FIVE = "5" * 64
_SIX = "6" * 64


def _times() -> tuple[str, str]:
    created = datetime(2026, 8, 30, tzinfo=UTC)
    return created.isoformat(), (created + timedelta(minutes=10)).isoformat()


def _capability() -> RuntimeLockCapabilityArtifact:
    created, _ = _times()
    return RuntimeLockCapabilityArtifact(
        perflens_version="0.4.0",
        capability_id=derive_runtime_lock_capability_id(_ZERO, _ONE, created),
        created_at=created,
        project_identity_sha256=_ZERO,
        project_policy_sha256=_ONE,
        status="available",
        adapters=(
            RuntimeLockAdapterCapabilityReference(
                adapter_id="cpython_threading",
                capability_id="runtime-adapter-" + "a" * 16,
                capability_content_sha256=_TWO,
                availability="available",
                supported_semantics=("exact", "thresholded"),
            ),
        ),
        content_sha256=_THREE,
    )


def _preview() -> RuntimeLockSessionPreviewArtifact:
    created, expires = _times()
    capability = _capability()
    program_sha256 = "b" * 64
    workload = RuntimeLockWorkloadBinding(
        adapter_id="cpython_threading",
        workload_kind="python_script",
        program="workloads/locks.py",
        program_sha256=program_sha256,
        program_size=128,
        working_directory=".",
        arguments=("--rounds", "10"),
        workload_identity_sha256=derive_runtime_lock_workload_identity(
            "cpython_threading",
            "python_script",
            "workloads/locks.py",
            program_sha256,
            128,
            ".",
            ("--rounds", "10"),
        ),
    )
    return RuntimeLockSessionPreviewArtifact(
        perflens_version="0.4.0",
        preview_id=derive_runtime_lock_preview_id(
            _ZERO,
            _ONE,
            capability.content_sha256,
            created,
        ),
        created_at=created,
        expires_at=expires,
        project_identity_sha256=_ZERO,
        client_connection_identity_sha256=_FOUR,
        project_policy_sha256=_ONE,
        capability_id=capability.capability_id,
        capability_content_sha256=capability.content_sha256,
        runtime_lock_config_sha256=_FIVE,
        target_scope="host_launched_workload",
        allowed_adapters=("cpython_threading",),
        allowed_semantics=("exact", "thresholded"),
        workload=workload,
        budget=RuntimeLockSessionBudget(),
        planned_actions=("Launch one authorized CPython workload.",),
        authorization_summary_sha256=_SIX,
        content_sha256="7" * 64,
    )


def _java_binding() -> RuntimeLockAdapterExecutionBinding:
    tools = (
        RuntimeLockAdapterToolBinding(name="java", version="25.0.4.1", binary_sha256=_FOUR),
        RuntimeLockAdapterToolBinding(name="jfr", version="25.0.4.1", binary_sha256=_FIVE),
    )
    toolchain_identity = derive_runtime_lock_toolchain_identity(tools)
    runtime_payload_identity = "8" * 64
    execution_identity = derive_runtime_lock_adapter_execution_identity(
        "java_jfr",
        "java-jfr-adapter-v1",
        "jfr",
        "25.0.4.1",
        "balanced",
        "thresholded",
        10_000_000,
        toolchain_identity,
        _TWO,
        _THREE,
        runtime_payload_identity,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="java_jfr",
        adapter_version="java-jfr-adapter-v1",
        backend_id="jfr",
        runtime_version="25.0.4.1",
        profile="balanced",
        measurement_semantics="thresholded",
        duration_threshold_ns=10_000_000,
        tools=tools,
        toolchain_identity_sha256=toolchain_identity,
        configuration_sha256=_TWO,
        metadata_sha256=_THREE,
        runtime_payload_identity_sha256=runtime_payload_identity,
        execution_identity_sha256=execution_identity,
        limitations=("Thresholded JFR events do not represent invisible waits.",),
    )


def test_runtime_lock_schema_1_0_session_id_derivation_remains_compatible() -> None:
    session = _session()
    legacy_id = derive_runtime_lock_session_artifact_id(
        session.session_id,
        session.revision,
        session.state,
        session.updated_at,
        session.previous_session_artifact_id,
        session.previous_session_artifact_content_sha256,
        session.workload_runs_used,
        session.active_seconds_used,
        session.evidence_bytes_used,
        session.exact_events_used,
    )
    explicit_none_id = derive_runtime_lock_session_artifact_id(
        session.session_id,
        session.revision,
        session.state,
        session.updated_at,
        session.previous_session_artifact_id,
        session.previous_session_artifact_content_sha256,
        session.workload_runs_used,
        session.active_seconds_used,
        session.evidence_bytes_used,
        session.exact_events_used,
        None,
    )
    assert legacy_id == explicit_none_id == session.session_artifact_id


def _session() -> RuntimeLockSessionArtifact:
    preview = _preview()
    session_id = "runtime-lock-session-" + "8" * 20
    return RuntimeLockSessionArtifact(
        perflens_version="0.4.0",
        session_artifact_id=derive_runtime_lock_session_artifact_id(
            session_id,
            0,
            "active",
            preview.created_at,
            None,
            None,
            0,
            0,
            0,
            0,
        ),
        session_id=session_id,
        revision=0,
        created_at=preview.created_at,
        updated_at=preview.created_at,
        expires_at=(datetime.fromisoformat(preview.created_at) + timedelta(hours=1)).isoformat(),
        state="active",
        project_identity_sha256=preview.project_identity_sha256,
        client_connection_identity_sha256=preview.client_connection_identity_sha256,
        project_policy_sha256=preview.project_policy_sha256,
        capability_id=preview.capability_id,
        capability_content_sha256=preview.capability_content_sha256,
        runtime_lock_config_sha256=preview.runtime_lock_config_sha256,
        preview_id=preview.preview_id,
        preview_content_sha256=preview.content_sha256,
        authorization_receipt_sha256="9" * 64,
        target_scope=preview.target_scope,
        allowed_adapters=preview.allowed_adapters,
        allowed_semantics=preview.allowed_semantics,
        budget=preview.budget,
        content_sha256="a" * 64,
    )


def _run(*, candidate: bool = False) -> RuntimeLockRunArtifact:
    session = _session()
    started = datetime.fromisoformat(session.created_at) + timedelta(seconds=1 + candidate)
    finished = started + timedelta(seconds=1)
    evidence_content = ("b" if candidate else "c") * 64
    return RuntimeLockRunArtifact(
        perflens_version="0.4.0",
        run_id=derive_runtime_lock_run_id(
            session.session_id,
            "cpython_threading",
            evidence_content,
            started.isoformat(),
        ),
        created_at=finished.isoformat(),
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        session_id=session.session_id,
        session_artifact_id=session.session_artifact_id,
        session_artifact_content_sha256=session.content_sha256,
        session_revision=session.revision,
        target_scope=session.target_scope,
        operation_identity_sha256="d" * 64,
        target_identity_sha256="e" * 64,
        adapter_id="cpython_threading",
        measurement_semantics="thresholded",
        workload_identity_sha256="f" * 64,
        runtime_lock_evidence_id="runtime-lock-evidence-" + "1" * 16,
        runtime_lock_evidence_content_sha256=evidence_content,
        runtime_lock_analysis_id="runtime-lock-analysis-" + "2" * 16,
        runtime_lock_analysis_content_sha256="3" * 64,
        runtime_lock_verification_id="runtime-lock-verification-" + "4" * 16,
        runtime_lock_verification_content_sha256="5" * 64,
        duration_seconds=1,
        evidence_bytes=2048,
        event_count=4,
        correctness_status="passed",
        quality_status="complete",
        allowed_conclusions=("runtime_lock_wait_distribution",),
        forbidden_conclusions=("performance_root_cause",),
        content_sha256=("6" if candidate else "7") * 64,
    )


def test_runtime_lock_session_contracts_bind_capability_preview_session_and_run() -> None:
    capability = _capability()
    preview = _preview()
    session = _session()
    run = _run()

    assert capability.status == "available"
    assert preview.capability_id == capability.capability_id
    assert session.preview_id == preview.preview_id
    assert run.session_id == session.session_id
    assert run.operation_identity_sha256 != run.target_identity_sha256


def test_runtime_lock_preview_rejects_unsafe_import_root() -> None:
    payload = _preview().model_dump(mode="json")
    payload["target_scope"] = "controlled_import"
    payload["import_roots"] = ["../secrets"]
    payload["workload"] = None

    with pytest.raises(ValidationError, match="normalized project-relative"):
        RuntimeLockSessionPreviewArtifact.model_validate(payload)


def test_runtime_lock_workload_binding_rejects_secret_or_identity_change() -> None:
    workload = _preview().workload
    assert workload is not None
    payload = workload.model_dump(mode="json")
    payload["arguments"] = ["--token=private"]
    with pytest.raises(ValidationError, match="unsafe material"):
        RuntimeLockWorkloadBinding.model_validate(payload)

    for arguments in (
        ["--password", "private"],
        ["--passwd", "private"],
        ["--pwd", "private"],
        ["--token", "private"],
        ["--secret", "private"],
        ["--credentials", "private"],
        ["--authorization", "private"],
        ["--api-key", "private"],
        ["--client_secret", "private"],
        ["--access-token", "private"],
        ["--refresh_token", "private"],
    ):
        payload = workload.model_dump(mode="json")
        payload["arguments"] = arguments
        with pytest.raises(ValidationError, match="unsafe material"):
            RuntimeLockWorkloadBinding.model_validate(payload)

    payload = workload.model_dump(mode="json")
    payload["program_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="identity differs"):
        RuntimeLockWorkloadBinding.model_validate(payload)


def test_java_jfr_execution_binding_is_content_bound_and_required_by_preview() -> None:
    binding = _java_binding()
    payload = binding.model_dump(mode="json")
    payload["profile"] = "deep"
    with pytest.raises(ValidationError, match="threshold"):
        RuntimeLockAdapterExecutionBinding.model_validate(payload)

    payload = binding.model_dump(mode="json")
    payload["metadata_sha256"] = _FOUR
    with pytest.raises(ValidationError, match="identity differs"):
        RuntimeLockAdapterExecutionBinding.model_validate(payload)

    preview_payload = _preview().model_dump(mode="json")
    original_workload = _preview().workload
    assert original_workload is not None
    java_identity = derive_runtime_lock_workload_identity(
        "java_jfr",
        "java_archive",
        "workloads/app.jar",
        original_workload.program_sha256,
        original_workload.program_size,
        original_workload.working_directory,
        original_workload.arguments,
    )
    java_workload = RuntimeLockWorkloadBinding(
        adapter_id="java_jfr",
        workload_kind="java_archive",
        program="workloads/app.jar",
        program_sha256=original_workload.program_sha256,
        program_size=original_workload.program_size,
        working_directory=original_workload.working_directory,
        arguments=original_workload.arguments,
        workload_identity_sha256=java_identity,
    )
    preview_payload["workload"] = java_workload.model_dump(mode="json")
    preview_payload["schema_version"] = "1.1"
    preview_payload["allowed_adapters"] = ["java_jfr"]
    preview_payload["allowed_semantics"] = ["thresholded"]
    with pytest.raises(ValidationError, match="execution binding"):
        RuntimeLockSessionPreviewArtifact.model_validate(preview_payload)
    preview_payload["adapter_execution_bindings"] = [binding.model_dump(mode="json")]
    assert (
        RuntimeLockSessionPreviewArtifact.model_validate(preview_payload)
        .adapter_execution_bindings[0]
        .execution_identity_sha256
        == binding.execution_identity_sha256
    )

    preview_payload["allowed_semantics"] = ["exact"]
    with pytest.raises(ValidationError, match="semantics scope"):
        RuntimeLockSessionPreviewArtifact.model_validate(preview_payload)

    preview_payload["allowed_semantics"] = ["thresholded"]
    preview_payload["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match=r"Preview 1\.0"):
        RuntimeLockSessionPreviewArtifact.model_validate(preview_payload)


def test_runtime_lock_execution_binding_limitations_are_bounded() -> None:
    payload = _java_binding().model_dump(mode="json")
    payload["limitations"] = ["x" * 2049]
    with pytest.raises(ValidationError):
        RuntimeLockAdapterExecutionBinding.model_validate(payload)

    payload["limitations"] = ["bounded"] * 33
    with pytest.raises(ValidationError):
        RuntimeLockAdapterExecutionBinding.model_validate(payload)


def test_java_jfr_run_requires_execution_identity() -> None:
    payload = _run().model_dump(mode="json")
    payload["adapter_id"] = "java_jfr"
    with pytest.raises(ValidationError, match="execution identity"):
        RuntimeLockRunArtifact.model_validate(payload)

    payload["schema_version"] = "1.0"
    payload["adapter_execution_identity_sha256"] = _ONE
    with pytest.raises(ValidationError, match=r"Run 1\.0"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_session_rejects_budget_overrun() -> None:
    payload = _session().model_dump(mode="json")
    payload["workload_runs_used"] = 7

    with pytest.raises(ValidationError):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_session_requires_reason_only_after_termination() -> None:
    payload = _session().model_dump(mode="json")
    payload["state"] = "revoked"
    payload["revision"] = 1
    payload["previous_session_artifact_id"] = payload["session_artifact_id"]
    payload["previous_session_artifact_content_sha256"] = payload["content_sha256"]
    payload["session_artifact_id"] = derive_runtime_lock_session_artifact_id(
        payload["session_id"],
        payload["revision"],
        "revoked",
        payload["updated_at"],
        payload["previous_session_artifact_id"],
        payload["previous_session_artifact_content_sha256"],
        payload["workload_runs_used"],
        payload["active_seconds_used"],
        payload["evidence_bytes_used"],
        payload["exact_events_used"],
    )

    with pytest.raises(ValidationError, match="must explain"):
        RuntimeLockSessionArtifact.model_validate(payload)

    payload["invalidation_reason"] = "/home/user/private/token=secret"
    with pytest.raises(ValidationError):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_session_requires_a_complete_predecessor_chain() -> None:
    payload = _session().model_dump(mode="json")
    payload["revision"] = 1
    with pytest.raises(ValidationError, match="must reference its predecessor"):
        RuntimeLockSessionArtifact.model_validate(payload)

    payload = _session().model_dump(mode="json")
    payload["previous_session_artifact_id"] = "runtime-lock-session-state-" + "b" * 20
    payload["previous_session_artifact_content_sha256"] = "c" * 64
    with pytest.raises(ValidationError, match=r"initial .* cannot reference"):
        RuntimeLockSessionArtifact.model_validate(payload)


def test_runtime_lock_run_rejects_evidence_identity_mismatch() -> None:
    payload = _run().model_dump(mode="json")
    payload["runtime_lock_evidence_content_sha256"] = "8" * 64

    with pytest.raises(ValidationError, match="Run ID differs"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_run_timestamps_and_duration_must_be_conserved() -> None:
    payload = _run().model_dump(mode="json")
    payload["duration_seconds"] = 0
    with pytest.raises(ValidationError, match="duration differs"):
        RuntimeLockRunArtifact.model_validate(payload)

    payload = _run().model_dump(mode="json")
    payload["created_at"] = payload["started_at"]
    with pytest.raises(ValidationError, match="timestamps are inconsistent"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_run_quality_gate_is_intrinsically_consistent() -> None:
    payload = _run().model_dump(mode="json")
    payload["quality_status"] = "partial"
    with pytest.raises(ValidationError, match="must forbid unqualified"):
        RuntimeLockRunArtifact.model_validate(payload)

    payload = _run().model_dump(mode="json")
    payload["forbidden_conclusions"].append("unqualified_runtime_lock_conclusion")
    with pytest.raises(ValidationError, match="cannot carry the partial-quality gate"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_run_boundaries_only_promote_reviewed_adapter_coverage() -> None:
    expected = derive_runtime_lock_run_boundaries(
        adapter_id="native_pthread",
        analysis_quality_status="complete",
        analysis_allowed_conclusions=("runtime_lock_wait_distribution",),
        analysis_forbidden_conclusions=("performance_root_cause",),
        warnings=("Native launch coverage is partial: reviewed launcher limitation.",),
    )
    assert expected == (
        "partial",
        ("runtime_lock_wait_distribution",),
        ("performance_root_cause", "unqualified_runtime_lock_conclusion"),
    )

    unreviewed = derive_runtime_lock_run_boundaries(
        adapter_id="native_pthread",
        analysis_quality_status="complete",
        analysis_allowed_conclusions=("runtime_lock_wait_distribution",),
        analysis_forbidden_conclusions=("performance_root_cause",),
        warnings=("A caller supplied an arbitrary partial warning.",),
    )
    assert unreviewed == (
        "complete",
        ("runtime_lock_wait_distribution",),
        ("performance_root_cause",),
    )


def test_runtime_lock_comparison_requires_all_matched_inputs_for_verified_improvement() -> None:
    baseline = _run()
    candidate = _run(candidate=True)
    created = datetime(2026, 8, 30, 0, 1, tzinfo=UTC).isoformat()
    comparison = RuntimeLockComparisonArtifact(
        perflens_version="0.4.0",
        comparison_id=derive_runtime_lock_comparison_id(
            baseline.session_id,
            baseline.content_sha256,
            candidate.content_sha256,
            created,
        ),
        created_at=created,
        session_id=baseline.session_id,
        baseline_run_id=baseline.run_id,
        baseline_run_content_sha256=baseline.content_sha256,
        candidate_run_id=candidate.run_id,
        candidate_run_content_sha256=candidate.content_sha256,
        adapter_match=True,
        semantics_match=True,
        threshold_or_sampling_match=True,
        workload_match=True,
        resource_environment_match=True,
        baseline_quality_status="complete",
        candidate_quality_status="complete",
        correctness_status="passed",
        deterministic_replay_passed=True,
        resource_transfer_status="no_observed_regression",
        comparable=True,
        conclusion="verified_improvement",
        improved_metrics=("total_wait_ns",),
        allowed_conclusions=("verified_improvement",),
        forbidden_conclusions=("performance_root_cause",),
        content_sha256="9" * 64,
    )
    assert comparison.conclusion == "verified_improvement"

    payload = comparison.model_dump(mode="json")
    payload["resource_environment_match"] = False
    with pytest.raises(ValidationError, match="comparability"):
        RuntimeLockComparisonArtifact.model_validate(payload)

    payload = comparison.model_dump(mode="json")
    payload["candidate_quality_status"] = "partial"
    with pytest.raises(ValidationError, match="verified Runtime Lock"):
        RuntimeLockComparisonArtifact.model_validate(payload)


def test_runtime_lock_exact_run_enforces_short_duration_and_event_bound() -> None:
    payload = _run().model_dump(mode="json")
    payload["measurement_semantics"] = "exact"
    payload["duration_seconds"] = 4
    finished = datetime.fromisoformat(payload["started_at"]) + timedelta(seconds=4)
    payload["finished_at"] = finished.isoformat()
    payload["created_at"] = finished.isoformat()

    with pytest.raises(ValidationError, match="exact Runtime Lock Run"):
        RuntimeLockRunArtifact.model_validate(payload)
