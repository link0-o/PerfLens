from __future__ import annotations

# pyright: reportPrivateUsage=false
import io
from datetime import datetime
from pathlib import Path
from typing import cast

import pytest
from tests.unit.test_docker_comparison import _measurement_pair
from tests.unit.test_runtime_lock_comparison import (
    _compare,
    _ComparisonInputs,
    _docker_build,
    _docker_run,
    _evidence_with_duration,
    _inputs,
    _inputs_from_evidence,
)

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker_build import DockerBuildArtifact
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockRunFinalizationArtifact,
    derive_runtime_lock_run_finalization_id,
)
from perflens.contracts.runtime_locks import RuntimeLockAnalysisVerificationArtifact
from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import comparison as comparison_module
from perflens.runtime_locks import import_runtime_lock_ndjson
from perflens.runtime_locks.comparison import (
    compare_runtime_lock_analyses,
    docker_runtime_lock_fixed_environment_sha256,
    runtime_lock_resource_environment_sha256,
)
from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe


def _rehash_run(run: RuntimeLockRunArtifact, **changes: object) -> RuntimeLockRunArtifact:
    provisional = run.model_copy(update={**changes, "content_sha256": "0" * 64})
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _rehash_verification(
    verification: RuntimeLockAnalysisVerificationArtifact,
    **changes: object,
) -> RuntimeLockAnalysisVerificationArtifact:
    provisional = verification.model_copy(update={**changes, "content_sha256": "0" * 64})
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def _compare_direct(
    values: _ComparisonInputs,
    *,
    baseline_run: RuntimeLockRunArtifact | None = None,
    candidate_run: RuntimeLockRunArtifact | None = None,
    candidate_verification: RuntimeLockAnalysisVerificationArtifact | None = None,
    baseline_environment: str | None = None,
    candidate_environment: str | None = None,
    created_at: datetime | None = None,
) -> RuntimeLockComparisonArtifact:
    selected_baseline = baseline_run or values.baseline_run
    selected_candidate = candidate_run or values.candidate_run
    return compare_runtime_lock_analyses(
        baseline_run=selected_baseline,
        baseline_analysis=values.baseline_analysis,
        baseline_evidence=values.baseline_evidence,
        baseline_verification=values.baseline_verification,
        candidate_run=selected_candidate,
        candidate_analysis=values.candidate_analysis,
        candidate_evidence=values.candidate_evidence,
        candidate_verification=candidate_verification or values.candidate_verification,
        baseline_resource_environment_sha256=(
            baseline_environment
            or runtime_lock_resource_environment_sha256(
                selected_baseline,
                values.baseline_evidence,
            )
        ),
        candidate_resource_environment_sha256=(
            candidate_environment
            or runtime_lock_resource_environment_sha256(
                selected_candidate,
                values.candidate_evidence,
            )
        ),
        resource_transfer_status="incomplete",
        created_at=created_at,
    )


def test_comparison_rejects_invalid_environment_digest_and_naive_timestamp() -> None:
    values = _inputs()

    with pytest.raises(PerfLensError, match="fingerprints are invalid"):
        _compare_direct(values, baseline_environment="f" * 64)

    with pytest.raises(PerfLensError, match="must include a timezone"):
        _compare_direct(values, created_at=datetime(2026, 8, 31, 0, 10))


def test_comparison_rejects_tampered_content_and_internal_chain() -> None:
    values = _inputs()
    tampered = values.baseline_run.model_copy(update={"content_sha256": "f" * 64})
    with pytest.raises(PerfLensError, match="content digest is invalid"):
        _compare_direct(values, baseline_run=tampered)

    inconsistent = _rehash_run(
        values.baseline_run,
        runtime_lock_analysis_id="runtime-lock-analysis-" + "f" * 20,
    )
    with pytest.raises(PerfLensError, match="evidence chain is inconsistent"):
        _compare_direct(values, baseline_run=inconsistent)

    invalid_contract = values.baseline_run.model_copy(update={"duration_seconds": 30})
    with pytest.raises(PerfLensError, match="contract validation failed"):
        _compare_direct(values, baseline_run=invalid_contract)


def test_comparison_surfaces_adapter_correctness_and_replay_mismatches() -> None:
    values = _inputs()
    candidate = _rehash_run(
        values.candidate_run,
        adapter_execution_identity_sha256="e" * 64,
    )
    comparison = _compare_direct(values, candidate_run=candidate)
    assert comparison.conclusion == "not_comparable"
    assert comparison.adapter_match is False
    assert any("Adapter" in warning for warning in comparison.warnings)

    for correctness, expected in (("failed", "failed"), ("unavailable", "unavailable")):
        candidate = _rehash_run(values.candidate_run, correctness_status=correctness)
        comparison = _compare_direct(values, candidate_run=candidate)
        assert comparison.correctness_status == expected
        assert comparison.conclusion == "not_comparable"
        assert any("correctness" in warning for warning in comparison.warnings)

    skipped = values.candidate_verification.checks[0].model_copy(update={"status": "skipped"})
    verification = _rehash_verification(
        values.candidate_verification,
        checks=(skipped, *values.candidate_verification.checks[1:]),
        verification_status="partial",
    )
    candidate = _rehash_run(
        values.candidate_run,
        runtime_lock_verification_content_sha256=verification.content_sha256,
    )
    comparison = _compare_direct(
        values,
        candidate_run=candidate,
        candidate_verification=verification,
    )
    assert comparison.deterministic_replay_passed is False
    assert any("independently replayed" in warning for warning in comparison.warnings)


def test_comparison_surfaces_semantics_and_partial_quality_boundaries() -> None:
    exact = (Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson").read_bytes()
    thresholded = (
        Path(__file__).parents[1]
        / "fixtures/runtime_locks/native-pthread-thresholded-partial.ndjson"
    ).read_bytes()
    values = _inputs_from_evidence(
        import_runtime_lock_ndjson(io.BytesIO(exact)),
        convert_native_pthread_probe(io.BytesIO(thresholded)).evidence,
    )
    candidate_run = _rehash_run(
        values.candidate_run,
        measurement_semantics="thresholded",
    )

    comparison = _compare_direct(values, candidate_run=candidate_run)

    assert comparison.semantics_match is False
    assert comparison.resource_environment_match is False
    assert comparison.candidate_quality_status == "partial"
    assert any("semantics differ" in warning for warning in comparison.warnings)
    assert any("Partial Runtime Lock evidence" in warning for warning in comparison.warnings)


def _docker_values(
    *,
    candidate_duration_ns: int,
    same_treatment: bool = False,
) -> tuple[
    _ComparisonInputs,
    RuntimeLockRunArtifact,
    RuntimeLockRunArtifact,
    DockerBuildArtifact,
    DockerBuildArtifact,
]:
    values = _inputs_from_evidence(
        _evidence_with_duration(10_000),
        _evidence_with_duration(candidate_duration_ns),
    )
    baseline_build = _docker_build(
        kind="baseline",
        round_number=0,
        marker="d",
        treatment_marker="1",
    )
    candidate_build = _docker_build(
        kind="candidate",
        round_number=1,
        marker="e",
        treatment_marker="1" if same_treatment else "2",
    )
    baseline_run = _docker_run(
        values.baseline_evidence,
        baseline_build,
        ordinal=0,
        measurement_marker="b",
    )
    candidate_run = _docker_run(
        values.candidate_evidence,
        candidate_build,
        ordinal=1,
        measurement_marker="c",
    )
    return values, baseline_run, candidate_run, baseline_build, candidate_build


def test_docker_comparison_requires_bound_build_and_resource_evidence() -> None:
    values, baseline_run, candidate_run, _, _ = _docker_values(candidate_duration_ns=8_000)

    with pytest.raises(PerfLensError, match="requires bound Build and resource evidence"):
        compare_runtime_lock_analyses(
            baseline_run=baseline_run,
            baseline_analysis=values.baseline_analysis,
            baseline_evidence=values.baseline_evidence,
            baseline_verification=values.baseline_verification,
            candidate_run=candidate_run,
            candidate_analysis=values.candidate_analysis,
            candidate_evidence=values.candidate_evidence,
            candidate_verification=values.candidate_verification,
            baseline_resource_environment_sha256="a" * 64,
            candidate_resource_environment_sha256="a" * 64,
            resource_transfer_status="incomplete",
        )


def test_docker_comparison_reports_resource_regression_and_unchanged_treatment() -> None:
    values, baseline_run, candidate_run, baseline_build, candidate_build = _docker_values(
        candidate_duration_ns=8_000
    )
    comparison = compare_runtime_lock_analyses(
        baseline_run=baseline_run,
        baseline_analysis=values.baseline_analysis,
        baseline_evidence=values.baseline_evidence,
        baseline_verification=values.baseline_verification,
        candidate_run=candidate_run,
        candidate_analysis=values.candidate_analysis,
        candidate_evidence=values.candidate_evidence,
        candidate_verification=values.candidate_verification,
        baseline_resource_environment_sha256="a" * 64,
        candidate_resource_environment_sha256="a" * 64,
        resource_transfer_status="regression",
        resource_comparison_id="container-comparison-" + "a" * 20,
        resource_comparison_content_sha256="b" * 64,
        baseline_build=baseline_build,
        candidate_build=candidate_build,
    )
    assert comparison.conclusion == "candidate_regression"
    assert "resource_transfer" in comparison.regressed_metrics
    assert any("resource-transfer regression" in warning for warning in comparison.warnings)

    values, baseline_run, candidate_run, baseline_build, candidate_build = _docker_values(
        candidate_duration_ns=8_000,
        same_treatment=True,
    )
    comparison = _compare(
        values,
        baseline_run=baseline_run,
        candidate_run=candidate_run,
        baseline_resource_environment_sha256="a" * 64,
        candidate_resource_environment_sha256="a" * 64,
        baseline_build=baseline_build,
        candidate_build=candidate_build,
    )
    assert comparison.docker_treatment_changed is False
    assert comparison.conclusion == "not_comparable"
    assert any("distinct authorized Treatment" in warning for warning in comparison.warnings)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("recipe_content_sha256", "d" * 64),
        ("builder_identity_sha256", "d" * 64),
        ("network_policy_sha256", "d" * 64),
        ("platform", "linux/arm64"),
        ("immutable_manifest_sha256", "d" * 64),
    ),
)
def test_docker_comparison_rejects_each_fixed_build_mismatch(field: str, value: object) -> None:
    values, baseline_run, candidate_run, baseline_build, candidate_build = _docker_values(
        candidate_duration_ns=8_000
    )
    candidate_build = candidate_build.model_copy(update={field: value, "content_sha256": "0" * 64})
    candidate_build = candidate_build.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                candidate_build,
                exclude={"content_sha256"},
            )
        }
    )
    candidate_binding = candidate_run.docker_optimization_binding
    assert candidate_binding is not None
    candidate_binding = candidate_binding.model_copy(
        update={"build_content_sha256": candidate_build.content_sha256}
    )
    candidate_run = _rehash_run(candidate_run, docker_optimization_binding=candidate_binding)

    with pytest.raises(PerfLensError, match="fixed Build environment"):
        _compare(
            values,
            baseline_run=baseline_run,
            candidate_run=candidate_run,
            baseline_resource_environment_sha256="a" * 64,
            candidate_resource_environment_sha256="a" * 64,
            baseline_build=baseline_build,
            candidate_build=candidate_build,
        )


def _valid_comparison_payload() -> dict[str, object]:
    return _compare(_inputs()).model_dump(mode="json")


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("same_run", "distinct Runs"),
        ("missing_authority", "explicit authority"),
        ("missing_environment", "replayable environments"),
        ("materiality", "materiality floor"),
        ("environment_match", "environment match"),
        ("docker_binding", "cannot carry Docker bindings"),
        ("resource_transfer", "lacks resource-transfer evidence"),
        ("session_authority", "authority and Session ID disagree"),
        ("comparable", "comparability is inconsistent"),
        ("conclusion", "conclusion disagrees"),
        ("verified", "cannot independently verify"),
        ("boundaries", "preserve conclusion boundaries"),
        ("identifier", "ID differs"),
    ),
)
def test_runtime_lock_comparison_schema_11_rejects_inconsistent_claims(
    case: str,
    message: str,
) -> None:
    payload = _valid_comparison_payload()
    _mutate_comparison(payload, case)

    with pytest.raises(ValueError, match=message):
        RuntimeLockComparisonArtifact.model_validate(payload)


def _mutate_comparison(payload: dict[str, object], case: str) -> None:
    updates: dict[str, object] = {
        "missing_authority": None,
        "missing_environment": None,
        "materiality": 2.0,
        "environment_match": False,
        "docker_binding": "docker-build-" + "a" * 20,
        "resource_transfer": "no_observed_regression",
        "session_authority": "docker-optimization-session-" + "a" * 20,
        "comparable": False,
        "conclusion": "not_comparable",
        "verified": "verified_improvement",
        "boundaries": [],
        "identifier": "runtime-lock-comparison-" + "f" * 20,
    }
    fields = {
        "missing_authority": "comparison_kind",
        "missing_environment": "baseline_resource_environment_sha256",
        "materiality": "minimum_material_change_percent",
        "environment_match": "resource_environment_match",
        "docker_binding": "baseline_build_id",
        "resource_transfer": "resource_transfer_status",
        "session_authority": "session_id",
        "comparable": "comparable",
        "conclusion": "conclusion",
        "verified": "conclusion",
        "boundaries": "allowed_conclusions",
        "identifier": "comparison_id",
    }
    if case == "same_run":
        payload["candidate_run_id"] = payload["baseline_run_id"]
        return
    payload[fields[case]] = updates[case]


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("timestamps", "timestamps are inconsistent"),
        ("duration", "duration differs from its timestamps"),
        ("empty_boundaries", "preserve conclusion boundaries"),
        ("blank_boundary", "conclusions cannot be blank"),
        ("duplicate_boundary", "conclusions must be unique"),
        ("overlap", "boundaries must be disjoint"),
        ("partial_without_gate", "must forbid unqualified conclusions"),
        ("complete_with_gate", "cannot carry the partial-quality gate"),
        ("exact_bound", "exceeds its hard evidence bound"),
        ("legacy_execution", "1.0 cannot carry an Adapter execution identity"),
        ("legacy_authority", "1.0 requires standalone Session authority"),
        ("missing_authority", "1.1 requires an explicit authorization authority"),
        ("missing_revision", "standalone Runtime Lock Run requires its Session revision"),
        ("managed_identity", "requires its authorized execution identity"),
        ("identifier", "ID differs from its evidence"),
    ),
)
def test_runtime_lock_run_schema_11_rejects_inconsistent_claims(
    case: str,
    message: str,
) -> None:
    payload = _inputs().baseline_run.model_dump(mode="json")
    _mutate_run(payload, case)

    with pytest.raises(ValueError, match=message):
        RuntimeLockRunArtifact.model_validate(payload)


def _mutate_run(payload: dict[str, object], case: str) -> None:
    allowed = cast(list[str], payload["allowed_conclusions"])
    forbidden = cast(list[str], payload["forbidden_conclusions"])
    if case == "timestamps":
        payload["finished_at"] = "2026-08-30T23:59:59+00:00"
    elif case == "duration":
        payload["duration_seconds"] = 2
    elif case == "empty_boundaries":
        payload["allowed_conclusions"] = []
    elif case == "blank_boundary":
        payload["allowed_conclusions"] = [*allowed, ""]
    elif case == "duplicate_boundary":
        payload["allowed_conclusions"] = [*allowed, allowed[0]]
    elif case == "overlap":
        payload["allowed_conclusions"] = [*allowed, forbidden[0]]
    elif case == "partial_without_gate":
        payload["quality_status"] = "partial"
    elif case == "complete_with_gate":
        payload["forbidden_conclusions"] = [
            *forbidden,
            "unqualified_runtime_lock_conclusion",
        ]
    elif case == "exact_bound":
        payload.update(
            duration_seconds=4,
            finished_at="2026-08-31T00:00:04+00:00",
            created_at="2026-08-31T00:00:04+00:00",
        )
    elif case == "legacy_execution":
        payload.update(schema_version="1.0", adapter_execution_identity_sha256="a" * 64)
    elif case == "legacy_authority":
        payload.update(schema_version="1.0", adapter_execution_identity_sha256=None)
    elif case == "missing_authority":
        payload["authorization_kind"] = None
    elif case == "missing_revision":
        payload["session_artifact_id"] = None
    elif case == "managed_identity":
        payload.update(
            adapter_id="java_jfr",
            adapter_execution_identity_sha256=None,
            run_id="runtime-lock-run-" + "a" * 20,
        )
    elif case == "identifier":
        payload["run_id"] = "runtime-lock-run-" + "f" * 20
    else:
        raise AssertionError(f"unknown test case: {case}")


def test_docker_runtime_lock_run_contract_binds_outer_scope_and_execution() -> None:
    values, baseline_run, _, _, _ = _docker_values(candidate_duration_ns=8_000)
    del values
    payload = baseline_run.model_dump(mode="json")
    payload["target_scope"] = "host_launched_workload"
    with pytest.raises(ValueError, match="requires its outer optimization evidence"):
        RuntimeLockRunArtifact.model_validate(payload)

    payload = baseline_run.model_dump(mode="json")
    payload["adapter_execution_identity_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="differs from its actual execution binding"):
        RuntimeLockRunArtifact.model_validate(payload)


def test_runtime_lock_comparison_schema_rejects_legacy_and_incomplete_docker_bindings() -> None:
    payload = _valid_comparison_payload()
    payload["schema_version"] = "1.0"
    with pytest.raises(ValueError, match=r"1\.0 requires standalone Session authority"):
        RuntimeLockComparisonArtifact.model_validate(payload)

    values, baseline_run, candidate_run, baseline_build, candidate_build = _docker_values(
        candidate_duration_ns=8_000
    )
    comparison = _compare(
        values,
        baseline_run=baseline_run,
        candidate_run=candidate_run,
        baseline_resource_environment_sha256="a" * 64,
        candidate_resource_environment_sha256="a" * 64,
        baseline_build=baseline_build,
        candidate_build=candidate_build,
    )
    payload = comparison.model_dump(mode="json")
    payload["baseline_measurement_id"] = None
    with pytest.raises(ValueError, match="requires Build, measurement"):
        RuntimeLockComparisonArtifact.model_validate(payload)


def test_runtime_lock_comparison_metric_projection_preserves_each_source_semantics() -> None:
    analysis = _inputs().baseline_analysis

    assert comparison_module._comparison_metrics(
        analysis.model_copy(
            update={"measurement_semantics": "thresholded", "total_thresholded_wait_ns": 12}
        )
    ) == {"total_thresholded_wait_ns": 12}
    assert comparison_module._comparison_metrics(
        analysis.model_copy(
            update={
                "measurement_semantics": "sampled",
                "total_observed_or_estimated_wait_ns": 13,
            }
        )
    ) == {"total_observed_or_estimated_wait_ns": 13}
    assert comparison_module._comparison_metrics(
        analysis.model_copy(
            update={
                "measurement_semantics": "sampled",
                "total_observed_or_estimated_wait_ns": 0,
                "total_sampled_observation_count": 14,
            }
        )
    ) == {"total_sampled_observation_count": 14}
    assert comparison_module._comparison_metrics(
        analysis.model_copy(
            update={
                "measurement_semantics": "cumulative",
                "total_observed_or_estimated_wait_ns": 15,
            }
        )
    ) == {"total_observed_or_estimated_wait_ns": 15}
    assert comparison_module._comparison_metrics(
        analysis.model_copy(
            update={
                "measurement_semantics": "cumulative",
                "total_observed_or_estimated_wait_ns": 0,
                "total_cumulative_observation_count": 16,
            }
        )
    ) == {"total_cumulative_observation_count": 16}
    assert comparison_module._material_change_percent(10, 10) == 0
    assert comparison_module._material_change_percent(0, 10) == 100


def test_docker_environment_hash_uses_fixed_measurement_surface(tmp_path: Path) -> None:
    _, _, _, _, measurements, _ = _measurement_pair(tmp_path)

    assert docker_runtime_lock_fixed_environment_sha256(
        measurements[0]
    ) == docker_runtime_lock_fixed_environment_sha256(measurements[1])

    values, docker_run, _, _, _ = _docker_values(candidate_duration_ns=8_000)
    with pytest.raises(PerfLensError, match="require ContainerMeasurement"):
        runtime_lock_resource_environment_sha256(docker_run, values.baseline_evidence)


def _finalization_payload() -> dict[str, object]:
    session_id = "runtime-lock-session-" + "1" * 20
    operation = "2" * 64
    artifact = RuntimeLockRunFinalizationArtifact(
        schema_version="1.1",
        perflens_version="0.4.0",
        finalization_id=derive_runtime_lock_run_finalization_id(session_id, operation),
        created_at="2026-08-31T00:00:02+00:00",
        session_id=session_id,
        operation_identity_sha256=operation,
        outcome="completed",
        adapter_id="native_pthread",
        measurement_semantics="exact",
        reserved_session_artifact_id="runtime-lock-session-state-" + "3" * 20,
        reserved_session_artifact_content_sha256="4" * 64,
        reserved_session_revision=1,
        final_session_artifact_id="runtime-lock-session-state-" + "5" * 20,
        final_session_artifact_content_sha256="6" * 64,
        final_session_revision=2,
        reserved_active_seconds=3,
        reserved_evidence_bytes=4096,
        reserved_exact_events=20,
        accounted_active_seconds=2,
        accounted_evidence_bytes=2048,
        accounted_exact_events=10,
        run_id="runtime-lock-run-" + "7" * 20,
        run_content_sha256="8" * 64,
        content_sha256="9" * 64,
    )
    return artifact.model_dump(mode="json")


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("revision", "immediately follow"),
        ("active_usage", "usage exceeds its reservation"),
        ("evidence_usage", "usage exceeds its reservation"),
        ("event_usage", "usage exceeds its reservation"),
        ("exact_reservation", "requires an event reservation"),
        ("nonexact_events", "cannot account exact events"),
        ("completed_run", "must bind one Run"),
        ("completed_reason", "must bind one Run"),
        ("failed_run", "must bind one terminal reason"),
        ("failed_reason", "must bind one terminal reason"),
        ("identifier", "ID differs from its operation"),
    ),
)
def test_runtime_lock_finalization_schema_rejects_non_atomic_settlement(
    case: str,
    message: str,
) -> None:
    payload = _finalization_payload()
    if case == "revision":
        payload["final_session_revision"] = 3
    elif case == "active_usage":
        payload["accounted_active_seconds"] = 4
    elif case == "evidence_usage":
        payload["accounted_evidence_bytes"] = 4097
    elif case == "event_usage":
        payload["accounted_exact_events"] = 21
    elif case == "exact_reservation":
        payload.update(reserved_exact_events=0, accounted_exact_events=0)
    elif case == "nonexact_events":
        payload["measurement_semantics"] = "thresholded"
    elif case == "completed_run":
        payload.update(run_id=None, run_content_sha256=None)
    elif case == "completed_reason":
        payload["failure_reason"] = "internal_collection_error"
    elif case == "failed_run":
        payload.update(outcome="failed", failure_reason="internal_collection_error")
    elif case == "failed_reason":
        payload.update(
            outcome="failed",
            run_id=None,
            run_content_sha256=None,
            failure_reason=None,
        )
    elif case == "identifier":
        payload["finalization_id"] = "runtime-lock-run-finalization-" + "f" * 20

    with pytest.raises(ValueError, match=message):
        RuntimeLockRunFinalizationArtifact.model_validate(payload)
