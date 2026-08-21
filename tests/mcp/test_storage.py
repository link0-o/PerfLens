from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import BaseModel
from tests.support.docker import make_container_resource_context
from tests.support.trace import make_scheduler_trace_evidence

from perflens import __version__
from perflens.application.analyze import analyze_folded
from perflens.application.analyze_trace import build_trace_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.verify_trace import compute_trace_analysis_content_sha256
from perflens.artifacts.filesystem import serialize_json
from perflens.classification.engine import build_diagnosis_bundle
from perflens.contracts.docker import ContainerRunArtifact
from perflens.contracts.trace import SchedulerAnalysisArtifact
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy


class _TestArtifact(BaseModel):
    value: str


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
        text, next_offset, total = store.read_page(
            "unicode", "test", offset=offset, limit=1
        )
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
