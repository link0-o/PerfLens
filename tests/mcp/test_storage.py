from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel
from tests.support.docker import make_container_resource_context
from tests.support.trace import make_scheduler_trace_evidence

from perflens import __version__
from perflens.application.analyze import analyze_folded
from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.verify_runtime_locks import (
    compute_runtime_lock_analysis_content_sha256,
    verify_runtime_lock_analysis_artifact,
)
from perflens.application.verify_trace import compute_trace_analysis_content_sha256
from perflens.artifacts.filesystem import serialize_json
from perflens.classification.engine import build_diagnosis_bundle
from perflens.contracts.docker import ContainerRunArtifact
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockSessionArtifact,
    derive_runtime_lock_comparison_id,
    derive_runtime_lock_run_finalization_id,
    derive_runtime_lock_run_id,
    derive_runtime_lock_session_artifact_id,
)
from perflens.contracts.trace import SchedulerAnalysisArtifact
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy
from perflens.runtime_locks import import_runtime_lock_ndjson
from perflens.runtime_locks.capability import inspect_runtime_lock_capability
from perflens.runtime_locks.project_config import (
    load_runtime_lock_project_policy,
    render_default_runtime_lock_project_policy,
)
from perflens.runtime_locks.session import (
    EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    RuntimeLockSessionAuthority,
    build_runtime_lock_session_preview,
)


class _TestArtifact(BaseModel):
    value: str


def _rebind_runtime_lock_session(
    session: RuntimeLockSessionArtifact,
    *,
    workload_runs_used: int,
    active_seconds_used: int,
    evidence_bytes_used: int,
    exact_events_used: int,
) -> RuntimeLockSessionArtifact:
    session_artifact_id = derive_runtime_lock_session_artifact_id(
        session.session_id,
        session.revision,
        session.state,
        session.updated_at,
        session.previous_session_artifact_id,
        session.previous_session_artifact_content_sha256,
        workload_runs_used,
        active_seconds_used,
        evidence_bytes_used,
        exact_events_used,
    )
    provisional = RuntimeLockSessionArtifact.model_validate(
        {
            **session.model_dump(mode="python"),
            "session_artifact_id": session_artifact_id,
            "workload_runs_used": workload_runs_used,
            "active_seconds_used": active_seconds_used,
            "evidence_bytes_used": evidence_bytes_used,
            "exact_events_used": exact_events_used,
            "content_sha256": "0" * 64,
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


def _runtime_lock_store_with_two_runs(
    tmp_path: Path,
) -> tuple[ArtifactStore, RuntimeLockRunArtifact, RuntimeLockRunArtifact]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "runtime-lock-artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    policy_path = tmp_path / "runtime-locks.toml"
    policy_path.write_text(render_default_runtime_lock_project_policy(), encoding="utf-8")
    policy_path.chmod(0o600)
    policy = load_runtime_lock_project_policy(policy_path, allowed_roots=(tmp_path,))
    project_identity = "1" * 64
    client_identity = "2" * 64
    inspection = inspect_runtime_lock_capability(
        policy,
        project_identity_sha256=project_identity,
    )
    for adapter in inspection.adapter_capabilities:
        store.save(adapter, adapter.capability_id, "runtime-adapter-capability")
    capability = inspection.capability
    store.save(capability, capability.capability_id, "runtime-lock-capability")
    preview = build_runtime_lock_session_preview(
        capability,
        client_connection_identity_sha256=client_identity,
        runtime_lock_config_sha256=policy.sha256,
        target_scope="controlled_import",
        allowed_adapters=("generic_ndjson_import",),
        allowed_semantics=("exact",),
        import_roots=("perflens-runtime-locks",),
        budget=policy.budget,
        planned_actions=("Import one reviewed Runtime Lock source.",),
    )
    store.save(preview, preview.preview_id, "runtime-lock-preview")
    authority = RuntimeLockSessionAuthority()
    authorized = authority.authorize(
        preview,
        capability,
        preview_content_sha256=preview.content_sha256,
        authorization_summary_sha256=preview.authorization_summary_sha256,
        explicit_authorization=EXPLICIT_RUNTIME_LOCK_SESSION_AUTHORIZATION,
    )
    store.save(
        authorized.artifact,
        authorized.artifact.session_artifact_id,
        "runtime-lock-session",
    )

    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    with fixture.open("rb") as source:
        evidence = import_runtime_lock_ndjson(source)
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
    store.save(evidence, evidence.runtime_lock_evidence_id, "runtime-lock-evidence")
    store.save(analysis, analysis.runtime_lock_analysis_id, "runtime-lock-analysis")
    store.save(
        verification,
        verification.runtime_lock_verification_id,
        "runtime-lock-verification",
    )
    evidence_bytes = len(serialize_json(evidence))
    target_identity = hashlib.sha256(
        "\0".join(
            (
                "perflens-runtime-lock-import-target-v1",
                project_identity,
                evidence.source.source_sha256,
            )
        ).encode()
    ).hexdigest()
    workload_identity = hashlib.sha256(
        "\0".join(
            (
                "perflens-runtime-lock-import-workload-v1",
                project_identity,
                evidence.source.source_sha256,
                evidence.source.measurement_semantics,
            )
        ).encode()
    ).hexdigest()

    runs: list[RuntimeLockRunArtifact] = []
    for ordinal in range(2):
        operation_identity = hashlib.sha256(f"operation-{ordinal}".encode()).hexdigest()
        lease = authority.begin_run(
            authorized.access,
            project_identity_sha256=project_identity,
            client_connection_identity_sha256=client_identity,
            project_policy_sha256=policy.sha256,
            runtime_lock_config_sha256=policy.sha256,
            capability_content_sha256=capability.content_sha256,
            preview_content_sha256=preview.content_sha256,
            adapter_id="generic_ndjson_import",
            measurement_semantics="exact",
            operation_identity_sha256=operation_identity,
            target_identity_sha256=target_identity,
            workload_identity_sha256=workload_identity,
            reserve_active_seconds=2,
            reserve_evidence_bytes=evidence_bytes + 1000,
            reserve_exact_events=len(evidence.events) + 5,
        )
        reserved = authority.snapshot(authorized.access)
        store.save(reserved, reserved.session_artifact_id, "runtime-lock-session")
        started = datetime.now(tz=UTC) + timedelta(seconds=ordinal * 2)
        finished = started + timedelta(seconds=1)
        provisional = RuntimeLockRunArtifact(
            schema_version="1.0",
            perflens_version="0.4.0",
            run_id=derive_runtime_lock_run_id(
                lease.session_id,
                lease.adapter_id,
                evidence.content_sha256,
                started.isoformat(),
            ),
            created_at=finished.isoformat(),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            session_id=lease.session_id,
            session_artifact_id=lease.session_artifact_id,
            session_artifact_content_sha256=lease.session_artifact_content_sha256,
            session_revision=lease.session_revision,
            target_scope="controlled_import",
            operation_identity_sha256=operation_identity,
            target_identity_sha256=target_identity,
            adapter_id="generic_ndjson_import",
            measurement_semantics="exact",
            workload_identity_sha256=workload_identity,
            runtime_lock_evidence_id=evidence.runtime_lock_evidence_id,
            runtime_lock_evidence_content_sha256=evidence.content_sha256,
            runtime_lock_analysis_id=analysis.runtime_lock_analysis_id,
            runtime_lock_analysis_content_sha256=analysis.content_sha256,
            runtime_lock_verification_id=verification.runtime_lock_verification_id,
            runtime_lock_verification_content_sha256=verification.content_sha256,
            duration_seconds=1,
            evidence_bytes=evidence_bytes,
            event_count=len(evidence.events),
            correctness_status="passed",
            quality_status=analysis.quality_status,
            allowed_conclusions=analysis.allowed_conclusions,
            forbidden_conclusions=analysis.forbidden_conclusions,
            content_sha256="0" * 64,
        )
        run = provisional.model_copy(
            update={
                "content_sha256": contract_content_sha256(
                    provisional,
                    exclude={"content_sha256"},
                )
            }
        )
        store.save(run, run.run_id, "runtime-lock-run")
        runs.append(run)
        completed = authority.finish_run(authorized.access, lease, run)
        store.save_runtime_lock_settlement(
            completed.session,
            completed.finalization,
        )
    return store, runs[0], runs[1]


def test_artifact_identifiers_cannot_traverse_root(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=False)
    with pytest.raises(PerfLensError) as captured:
        store.read_page("../secret", "analysis", offset=0, limit=100)
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_artifact_root_must_be_inside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    with pytest.raises(ValueError, match="inside an allowed root"):
        ArtifactStore(outside, PathPolicy((allowed,)), allow_writes=True)


def test_artifact_store_requires_a_positive_size_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        ArtifactStore(
            tmp_path / "artifacts",
            PathPolicy((tmp_path,)),
            allow_writes=True,
            max_artifact_bytes=0,
        )


def test_new_output_file_is_confined_and_must_not_exist(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = PathPolicy((allowed,))
    assert policy.new_output_file(allowed / "profile.data") == allowed / "profile.data"

    outside = tmp_path / "outside.data"
    with pytest.raises(PerfLensError) as captured:
        policy.new_output_file(outside)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_artifact_save_is_no_overwrite_and_content_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)

    output = store.save(_TestArtifact(value="first"), "same-id", "test")
    original = output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600
    assert store.save(_TestArtifact(value="first"), "same-id", "test") == output

    with pytest.raises(PerfLensError, match="different content") as collision:
        store.save(_TestArtifact(value="second"), "same-id", "test")
    assert collision.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert output.read_bytes() == original


@pytest.mark.parametrize("unsafe_kind", ["fifo", "symlink", "hardlink", "mode"])
def test_artifact_reads_reject_unsafe_file_types_without_blocking(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=False)
    artifact = root / "unsafe.analysis.json"
    if unsafe_kind == "fifo":
        os.mkfifo(artifact)
    elif unsafe_kind == "symlink":
        target = tmp_path / "target"
        target.write_text("secret", encoding="utf-8")
        artifact.symlink_to(target)
    else:
        artifact.write_text('{"value":"data"}\n', encoding="utf-8")
        artifact.chmod(0o600)
        if unsafe_kind == "hardlink":
            os.link(artifact, root / "second-link")
        else:
            artifact.chmod(0o644)

    with pytest.raises(PerfLensError) as unsafe:
        store.read_page("unsafe", "analysis", offset=0, limit=100)
    assert unsafe.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_artifact_read_pins_root_and_pages_safe_regular_file(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    output = store.save(_TestArtifact(value="paged"), "page", "test")

    text, next_offset, total = store.read_page("page", "test", offset=0, limit=8)
    assert text == output.read_text(encoding="utf-8")[:8]
    assert next_offset == 8
    assert total == output.stat().st_size

    moved = tmp_path / "moved-artifacts"
    root.rename(moved)
    root.mkdir()
    root.chmod(0o700)
    with pytest.raises(PerfLensError, match="root identity changed") as replaced:
        store.read_page("page", "test", offset=0, limit=8)
    assert replaced.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_json_artifact_byte_paging_is_lossless_for_non_ascii_text(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    output = store.save(_TestArtifact(value="中文性能证据"), "unicode", "test")

    pieces: list[str] = []
    offset = 0
    while True:
        text, next_offset, total = store.read_page("unicode", "test", offset=offset, limit=1)
        pieces.append(text)
        if next_offset is None:
            break
        offset = next_offset

    assert "".join(pieces).encode("utf-8") == output.read_bytes()
    assert total == output.stat().st_size


def test_typed_artifact_filename_cannot_alias_a_different_embedded_id(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    analysis = analyze_folded(profile)
    store.save(analysis, "different-analysis-id", "analysis")

    with pytest.raises(PerfLensError, match="identifier does not match"):
        store.load_analysis("different-analysis-id")


def test_corrupt_diagnosis_is_not_silently_reported_as_missing(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    analysis = analyze_folded(profile)
    diagnosis = build_diagnosis_bundle(analysis)
    store.save(analysis, analysis.analysis_id, "analysis")
    diagnosis_path = store.save(
        diagnosis,
        f"diagnosis-{analysis.analysis_id}",
        "diagnosis",
    )
    payload = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    payload["observations"] = ["forged observation"]
    diagnosis_path.write_text(json.dumps(payload), encoding="utf-8")
    diagnosis_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="does not match"):
        store.load_diagnosis(analysis.analysis_id)


def test_trace_storage_replays_analysis_and_rejects_semantic_tampering(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    evidence = make_scheduler_trace_evidence()
    analysis = build_trace_analysis(evidence)
    assert isinstance(analysis, SchedulerAnalysisArtifact)
    store.save(evidence, evidence.trace_evidence_id, "trace-evidence")
    analysis_path = store.save(
        analysis,
        analysis.scheduler_analysis_id,
        "scheduler-analysis",
    )

    loaded, loaded_evidence, verification = store.load_trace_analysis(
        analysis.scheduler_analysis_id
    )
    assert loaded == analysis
    assert loaded_evidence == evidence
    assert verification.verification_status == "partial"
    page, _, _ = store.read_page(
        evidence.trace_evidence_id,
        "trace-evidence",
        offset=0,
        limit=65_536,
    )
    assert '"trace_evidence_id"' in page
    assert "private scheduler trace" not in page

    forged = analysis.model_copy(update={"analysis_fingerprint": "f" * 64})
    forged = forged.model_copy(
        update={"content_sha256": compute_trace_analysis_content_sha256(forged)}
    )
    analysis_path.write_bytes(serialize_json(forged))
    analysis_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        store.load_trace_analysis(analysis.scheduler_analysis_id)
    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        store.read_page(
            analysis.scheduler_analysis_id,
            "scheduler-analysis",
            offset=0,
            limit=65_536,
        )


def test_runtime_lock_storage_replays_analysis_and_rejects_semantic_tampering(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root, PathPolicy((tmp_path,)), allow_writes=True)
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    with fixture.open("rb") as source:
        evidence = import_runtime_lock_ndjson(source)
    analysis = build_runtime_lock_analysis(evidence)
    store.save(
        evidence,
        evidence.runtime_lock_evidence_id,
        "runtime-lock-evidence",
    )
    analysis_path = store.save(
        analysis,
        analysis.runtime_lock_analysis_id,
        "runtime-lock-analysis",
    )

    loaded, loaded_evidence, verification = store.load_runtime_lock_analysis(
        analysis.runtime_lock_analysis_id
    )
    assert loaded == analysis
    assert loaded_evidence == evidence
    assert verification.verification_status == "partial"
    page, _, _ = store.read_page(
        evidence.runtime_lock_evidence_id,
        "runtime-lock-evidence",
        offset=0,
        limit=65_536,
    )
    assert '"runtime_lock_evidence_id"' in page
    assert "pthread_mutex_t" not in page

    forged = analysis.model_copy(
        update={"forbidden_conclusions": (*analysis.forbidden_conclusions, "forged")}
    )
    forged = forged.model_copy(
        update={"content_sha256": compute_runtime_lock_analysis_content_sha256(forged)}
    )
    analysis_path.write_bytes(serialize_json(forged))
    analysis_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        store.load_runtime_lock_analysis(analysis.runtime_lock_analysis_id)
    with pytest.raises(PerfLensError, match="failed deterministic verification"):
        store.read_page(
            analysis.runtime_lock_analysis_id,
            "runtime-lock-analysis",
            offset=0,
            limit=65_536,
        )


def test_runtime_lock_storage_replays_session_revision_and_run_chains(
    tmp_path: Path,
) -> None:
    store, baseline, candidate = _runtime_lock_store_with_two_runs(tmp_path)

    assert store.load_runtime_lock_run(baseline.run_id) == baseline
    assert store.load_runtime_lock_run(candidate.run_id) == candidate
    session = store.load_runtime_lock_session(candidate.session_artifact_id)
    assert session.revision == candidate.session_revision
    assert session.previous_session_artifact_id is not None


@pytest.mark.parametrize("conclusion_kind", ("allowed", "forbidden"))
def test_runtime_lock_storage_rejects_run_conclusion_projection_tampering(
    tmp_path: Path,
    conclusion_kind: str,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    finalization_id = derive_runtime_lock_run_finalization_id(
        baseline.session_id,
        baseline.operation_identity_sha256,
    )
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    update: dict[str, object]
    if conclusion_kind == "allowed":
        update = {"allowed_conclusions": (*baseline.allowed_conclusions, "forged")}
    else:
        update = {"forbidden_conclusions": (*baseline.forbidden_conclusions, "forged")}
    provisional = baseline.model_copy(update={**update, "content_sha256": "0" * 64})
    forged = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    run_path = store.root / f"{baseline.run_id}.runtime-lock-run.json"
    run_path.write_bytes(serialize_json(forged))
    run_path.chmod(0o600)
    marker = finalization.model_copy(
        update={"run_content_sha256": forged.content_sha256, "content_sha256": "0" * 64}
    )
    marker = marker.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                marker,
                exclude={"content_sha256"},
            )
        }
    )
    marker_path = store.root / (f"{finalization_id}.runtime-lock-run-finalization.json")
    marker_path.write_bytes(serialize_json(marker))
    marker_path.chmod(0o600)

    with pytest.raises(PerfLensError, match="Agent-visible content"):
        store.load_runtime_lock_run(baseline.run_id)


def test_runtime_lock_run_is_unreadable_without_marker_and_rejects_tampered_marker(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    finalization_id = derive_runtime_lock_run_finalization_id(
        baseline.session_id,
        baseline.operation_identity_sha256,
    )
    marker_path = store.root / (f"{finalization_id}.runtime-lock-run-finalization.json")
    original = marker_path.read_bytes()
    marker_path.unlink()
    with pytest.raises(PerfLensError, match="not found or cannot be opened safely"):
        store.load_runtime_lock_run(baseline.run_id)

    marker_path.write_bytes(original)
    marker_path.chmod(0o600)
    finalization = store.load_runtime_lock_run_finalization(finalization_id)
    forged = finalization.model_copy(
        update={"run_content_sha256": "f" * 64, "content_sha256": "0" * 64}
    )
    forged = forged.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged,
                exclude={"content_sha256"},
            )
        }
    )
    marker_path.write_bytes(serialize_json(forged))
    marker_path.chmod(0o600)
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_run(baseline.run_id)


def test_runtime_lock_storage_rejects_session_and_run_cross_chain_tampering(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    session = store.load_runtime_lock_session(baseline.session_artifact_id)
    session_path = store.root / (f"{session.session_artifact_id}.runtime-lock-session.json")
    forged_session = session.model_copy(update={"project_identity_sha256": "f" * 64})
    forged_session = forged_session.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged_session,
                exclude={"content_sha256"},
            )
        }
    )
    session_path.write_bytes(serialize_json(forged_session))
    session_path.chmod(0o600)
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_session(session.session_artifact_id)

    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path / "second")
    run_path = store.root / f"{baseline.run_id}.runtime-lock-run.json"
    forged_run = baseline.model_copy(update={"target_scope": "host_launched_workload"})
    forged_run = forged_run.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged_run,
                exclude={"content_sha256"},
            )
        }
    )
    run_path.write_bytes(serialize_json(forged_run))
    run_path.chmod(0o600)
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_run(baseline.run_id)


def test_runtime_lock_storage_rejects_impossible_session_usage_transitions(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    reserved = store.load_runtime_lock_session(baseline.session_artifact_id)
    assert reserved.previous_session_artifact_id is not None
    initial = store.load_runtime_lock_session(reserved.previous_session_artifact_id)

    forged_initial = _rebind_runtime_lock_session(
        initial,
        workload_runs_used=0,
        active_seconds_used=1,
        evidence_bytes_used=1,
        exact_events_used=0,
    )
    store.save(
        forged_initial,
        forged_initial.session_artifact_id,
        "runtime-lock-session",
    )
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_session(forged_initial.session_artifact_id)

    forged_reservation = _rebind_runtime_lock_session(
        reserved,
        workload_runs_used=reserved.workload_runs_used,
        active_seconds_used=initial.active_seconds_used,
        evidence_bytes_used=initial.evidence_bytes_used,
        exact_events_used=initial.exact_events_used,
    )
    store.save(
        forged_reservation,
        forged_reservation.session_artifact_id,
        "runtime-lock-session",
    )
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_session(forged_reservation.session_artifact_id)


def test_runtime_lock_storage_rejects_run_before_bound_session_revision(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    session = store.load_runtime_lock_session(baseline.session_artifact_id)
    started = datetime.fromisoformat(session.updated_at) - timedelta(seconds=1)
    finished = started + timedelta(seconds=1)
    run_id = derive_runtime_lock_run_id(
        baseline.session_id,
        baseline.adapter_id,
        baseline.runtime_lock_evidence_content_sha256,
        started.isoformat(),
    )
    provisional = RuntimeLockRunArtifact.model_validate(
        {
            **baseline.model_dump(mode="python"),
            "run_id": run_id,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "created_at": finished.isoformat(),
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
    store.save(forged, forged.run_id, "runtime-lock-run")
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_run(forged.run_id)


def test_runtime_lock_storage_rejects_preview_scope_not_supported_by_capability(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    session = store.load_runtime_lock_session(baseline.session_artifact_id)
    preview = store.load_runtime_lock_preview(session.preview_id)
    provisional = preview.model_copy(
        update={
            "allowed_adapters": ("java_jfr",),
            "allowed_semantics": ("thresholded",),
            "authorization_summary_sha256": "0" * 64,
            "content_sha256": "0" * 64,
        }
    )
    summary = contract_content_sha256(
        provisional,
        exclude={"authorization_summary_sha256", "content_sha256"},
    )
    with_summary = provisional.model_copy(update={"authorization_summary_sha256": summary})
    forged = with_summary.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                with_summary,
                exclude={"content_sha256"},
            )
        }
    )
    path = store.root / f"{preview.preview_id}.runtime-lock-preview.json"
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_preview(preview.preview_id)


def test_runtime_lock_storage_rejects_session_schema_downgrade(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    session = store.load_runtime_lock_session(baseline.session_artifact_id)
    provisional = session.model_copy(update={"schema_version": "1.0", "content_sha256": "0" * 64})
    forged = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    path = store.root / f"{session.session_artifact_id}.runtime-lock-session.json"
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_session(session.session_artifact_id)


def test_runtime_lock_storage_rejects_counter_rollback_without_new_workload(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    previous = store.load_runtime_lock_session(baseline.session_artifact_id)
    updated_at = (datetime.fromisoformat(previous.updated_at) + timedelta(seconds=1)).isoformat()
    revision = previous.revision + 1
    session_artifact_id = derive_runtime_lock_session_artifact_id(
        previous.session_id,
        revision,
        "revoked",
        updated_at,
        previous.session_artifact_id,
        previous.content_sha256,
        previous.workload_runs_used,
        0,
        0,
        0,
    )
    provisional = RuntimeLockSessionArtifact.model_validate(
        {
            **previous.model_dump(mode="python"),
            "session_artifact_id": session_artifact_id,
            "revision": revision,
            "previous_session_artifact_id": previous.session_artifact_id,
            "previous_session_artifact_content_sha256": previous.content_sha256,
            "updated_at": updated_at,
            "state": "revoked",
            "active_seconds_used": 0,
            "evidence_bytes_used": 0,
            "exact_events_used": 0,
            "invalidation_reason": "explicitly_revoked",
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
    store.save(forged, forged.session_artifact_id, "runtime-lock-session")

    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_session(forged.session_artifact_id)


def test_runtime_lock_storage_rejects_verification_spliced_from_another_analysis(
    tmp_path: Path,
) -> None:
    store, baseline, _ = _runtime_lock_store_with_two_runs(tmp_path)
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    alternate_source = fixture.read_bytes().replace(b'"target_pid":100', b'"target_pid":200')
    alternate_source = alternate_source.replace(b'"target_tid":100', b'"target_tid":200')
    alternate_source = alternate_source.replace(b'"target_tid":101', b'"target_tid":201')
    alternate_source = alternate_source.replace(
        b'"observed_target_tids":[100,101]',
        b'"observed_target_tids":[200,201]',
    )
    alternate = import_runtime_lock_ndjson(io.BytesIO(alternate_source))
    alternate_analysis = build_runtime_lock_analysis(alternate)
    alternate_verification = verify_runtime_lock_analysis_artifact(
        alternate_analysis,
        alternate,
    )
    store.save(alternate, alternate.runtime_lock_evidence_id, "runtime-lock-evidence")
    store.save(
        alternate_analysis,
        alternate_analysis.runtime_lock_analysis_id,
        "runtime-lock-analysis",
    )
    store.save(
        alternate_verification,
        alternate_verification.runtime_lock_verification_id,
        "runtime-lock-verification",
    )
    provisional = baseline.model_copy(
        update={
            "runtime_lock_verification_id": (alternate_verification.runtime_lock_verification_id),
            "runtime_lock_verification_content_sha256": alternate_verification.content_sha256,
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
    path = store.root / f"{baseline.run_id}.runtime-lock-run.json"
    path.write_bytes(serialize_json(forged))
    path.chmod(0o600)

    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_run(baseline.run_id)


def test_runtime_lock_comparison_is_fail_closed_until_independent_ab_replay(
    tmp_path: Path,
) -> None:
    store, baseline, candidate = _runtime_lock_store_with_two_runs(tmp_path)
    created = datetime.now(tz=UTC).isoformat()
    provisional = RuntimeLockComparisonArtifact(
        schema_version="1.0",
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
        resource_environment_match=False,
        baseline_quality_status=baseline.quality_status,
        candidate_quality_status=candidate.quality_status,
        correctness_status="passed",
        deterministic_replay_passed=True,
        resource_transfer_status="incomplete",
        comparable=False,
        conclusion="not_comparable",
        allowed_conclusions=("runtime_lock_wait_distribution",),
        forbidden_conclusions=("performance_root_cause", "verified_improvement"),
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
    store.save(comparison, comparison.comparison_id, "runtime-lock-comparison")
    assert store.load_runtime_lock_comparison(comparison.comparison_id) == comparison

    forged_created = (datetime.now(tz=UTC) + timedelta(seconds=1)).isoformat()
    forged_payload = {
        **comparison.model_dump(mode="python"),
        "comparison_id": derive_runtime_lock_comparison_id(
            baseline.session_id,
            baseline.content_sha256,
            candidate.content_sha256,
            forged_created,
        ),
        "created_at": forged_created,
        "resource_environment_match": True,
        "resource_transfer_status": "no_observed_regression",
        "comparable": True,
        "conclusion": "verified_improvement",
        "improved_metrics": ("total_wait_ns",),
        "allowed_conclusions": ("runtime_lock_wait_distribution", "verified_improvement"),
        "forbidden_conclusions": ("performance_root_cause",),
        "content_sha256": "0" * 64,
    }
    forged = RuntimeLockComparisonArtifact.model_validate(forged_payload)
    forged = forged.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                forged,
                exclude={"content_sha256"},
            )
        }
    )
    store.save(forged, forged.comparison_id, "runtime-lock-comparison")
    with pytest.raises(PerfLensError, match="does not match"):
        store.load_runtime_lock_comparison(forged.comparison_id)


def test_docker_resource_context_is_content_verified_before_agent_paging(
    tmp_path: Path,
) -> None:
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    context = make_container_resource_context()
    path = store.save(
        context,
        context.resource_context_id,
        "container-resource-context",
    )
    assert store.load_container_resource_context(context.resource_context_id) == context
    page, _, _ = store.read_page(
        context.resource_context_id,
        "container-resource-context",
        offset=0,
        limit=65_536,
    )
    assert '"scope": "entire_container_cgroup_v2"' in page
    assert "/sys/fs/cgroup" not in page

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["delta"]["cpu_usage_usec"] = 999_999
    unhashed = {key: value for key, value in payload.items() if key != "content_sha256"}
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(
            unhashed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(PerfLensError) as loaded:
        store.load_container_resource_context(context.resource_context_id)
    assert loaded.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(PerfLensError) as paged:
        store.read_page(
            context.resource_context_id,
            "container-resource-context",
            offset=0,
            limit=65_536,
        )
    assert paged.value.code is ErrorCode.INVALID_INPUT


def test_container_run_rejects_resource_context_from_another_container(
    tmp_path: Path,
) -> None:
    store = ArtifactStore(
        tmp_path / "artifacts",
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    context = make_container_resource_context(container_identity_sha256="5" * 64)
    store.save(
        context,
        context.resource_context_id,
        "container-resource-context",
    )

    matching_provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        run_id="container-run-" + "a" * 20,
        created_at="2026-08-21T00:00:03+00:00",
        session_id="container-session-" + "c" * 20,
        workload_spec_sha256="d" * 64,
        container_identity_sha256=context.container_identity_sha256,
        image_identity_sha256="e" * 64,
        target_identity_sha256="f" * 64,
        container_pid=1,
        host_pid=1234,
        host_start_time_ticks=5678,
        started_at="2026-08-21T00:00:00+00:00",
        finished_at="2026-08-21T00:00:02+00:00",
        status="exited",
        exit_code=0,
        collection_ids=(context.source_collection_id,),
        resource_context_id=context.resource_context_id,
        cleanup_status="removed",
        content_sha256="0" * 64,
    )
    matching = matching_provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                matching_provisional,
                exclude={"content_sha256"},
            )
        }
    )
    store.save(matching, matching.run_id, "container-run")
    assert store.load_container_run(matching.run_id) == matching
    page, next_offset, _ = store.read_page(
        matching.run_id,
        "container-run",
        offset=0,
        limit=65_536,
    )
    assert next_offset is None
    assert context.resource_context_id in page

    legacy_provisional = matching_provisional.model_copy(
        update={
            "run_id": "container-run-" + "c" * 20,
            "resource_context_id": None,
            "content_sha256": "0" * 64,
        }
    )
    legacy = legacy_provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                legacy_provisional,
                exclude={"content_sha256"},
            )
        }
    )
    store.save(legacy, legacy.run_id, "container-run")
    assert store.load_container_run(legacy.run_id) == legacy
    legacy_page, legacy_next_offset, _ = store.read_page(
        legacy.run_id,
        "container-run",
        offset=0,
        limit=65_536,
    )
    assert legacy_next_offset is None
    assert '"resource_context_id"' not in legacy_page

    provisional = ContainerRunArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        run_id="container-run-" + "b" * 20,
        created_at="2026-08-21T00:00:03+00:00",
        session_id="container-session-" + "c" * 20,
        workload_spec_sha256="d" * 64,
        container_identity_sha256="6" * 64,
        image_identity_sha256="e" * 64,
        target_identity_sha256="f" * 64,
        container_pid=1,
        host_pid=1234,
        host_start_time_ticks=5678,
        started_at="2026-08-21T00:00:00+00:00",
        finished_at="2026-08-21T00:00:02+00:00",
        status="exited",
        exit_code=0,
        collection_ids=(context.source_collection_id,),
        resource_context_id=context.resource_context_id,
        cleanup_status="removed",
        content_sha256="0" * 64,
    )
    run = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    store.save(run, run.run_id, "container-run")

    with pytest.raises(PerfLensError, match="identifier does not match"):
        store.load_container_run(run.run_id)
    with pytest.raises(PerfLensError, match="identifier does not match"):
        store.read_page(run.run_id, "container-run", offset=0, limit=65_536)

    wrong_collection_provisional = matching.model_copy(
        update={
            "run_id": "container-run-" + "d" * 20,
            "collection_ids": ("collection-" + "9" * 16,),
            "content_sha256": "0" * 64,
        }
    )
    wrong_collection = wrong_collection_provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                wrong_collection_provisional,
                exclude={"content_sha256"},
            )
        }
    )
    store.save(wrong_collection, wrong_collection.run_id, "container-run")
    with pytest.raises(PerfLensError, match="identifier does not match"):
        store.load_container_run(wrong_collection.run_id)
    with pytest.raises(PerfLensError, match="identifier does not match"):
        store.read_page(
            wrong_collection.run_id,
            "container-run",
            offset=0,
            limit=65_536,
        )
