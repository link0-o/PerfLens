from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from perflens.application import analyze as analyze_module
from perflens.application.analyze import analyze_folded, analyze_perf_script
from perflens.application.evidence import (
    compute_analysis_content_sha256,
    validate_collection_invariants,
    verify_collection_artifact,
)
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.contracts.artifacts import CollectionArtifact, PerfStatMetric
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import ResourceLimits
from perflens.metrics.perf_stat import PerfStatMetricAdapter


def test_invalid_utf8_is_visible_and_marks_analysis_partial(tmp_path: Path) -> None:
    profile = tmp_path / "invalid-utf8.perf-script"
    profile.write_bytes(
        b"app 1/1 [000] 1.0: 7 cpu-clock:\n        400001 leaf-\xff (/opt/app) /src/app.c:7\n"
    )

    artifact = analyze_perf_script(profile)

    assert artifact.status == "partial"
    assert artifact.evidence_quality.quality_status == "partial"
    assert artifact.metadata.parse_statistics.unicode_replacement_count == 1
    assert "unqualified_profile_conclusion" in artifact.evidence_quality.forbidden_conclusions


def test_valid_unicode_replacement_character_is_not_reported_as_decode_loss(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "valid-unicode.folded"
    profile.write_text("root;leaf-\ufffd 3\n", encoding="utf-8")

    artifact = analyze_folded(profile)

    assert artifact.status == "complete"
    assert artifact.metadata.parse_statistics.unicode_replacement_count == 0
    assert artifact.evidence_quality.input_bytes == profile.stat().st_size


def test_empty_profile_is_partial_and_cannot_support_an_unqualified_conclusion(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "empty.folded"
    profile.write_bytes(b"")

    artifact = analyze_folded(profile)
    verification = verify_analysis_artifact(artifact, verify_source=True)

    assert artifact.status == "partial"
    assert artifact.metadata.sample_count == 0
    assert artifact.metadata.total_weight == 0
    assert artifact.evidence_quality.allowed_conclusions == ()
    assert "unqualified_profile_conclusion" in artifact.evidence_quality.forbidden_conclusions
    assert verification.status == "partial"


def test_bounded_outputs_report_omitted_weight(tmp_path: Path) -> None:
    profile = tmp_path / "bounded.folded"
    profile.write_text("root;a 7\nroot;b 5\n", encoding="utf-8")

    artifact = analyze_folded(
        profile,
        limits=ResourceLimits(max_hotspots_output=1, max_call_paths_output=1),
    )

    assert artifact.status == "partial"
    assert artifact.evidence_quality.total_hotspot_count == 3
    assert artifact.evidence_quality.exported_hotspot_count == 1
    assert artifact.evidence_quality.omitted_hotspot_self_weight == 5
    assert artifact.evidence_quality.total_call_path_count == 2
    assert artifact.evidence_quality.omitted_call_path_weight == 5
    assert "complete_profile_distribution" in artifact.evidence_quality.forbidden_conclusions


def test_analysis_verifier_rejects_tampered_hotspot_weight(tmp_path: Path) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    artifact = analyze_folded(profile)
    tampered_hotspot = artifact.hotspots[0].model_copy(
        update={"self_weight": artifact.hotspots[0].self_weight + 1}
    )
    tampered = artifact.model_copy(update={"hotspots": (tampered_hotspot, *artifact.hotspots[1:])})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError) as captured:
        verify_analysis_artifact(tampered, verify_source=True)

    assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED
    assert captured.value.stage == "evidence_validation"


def test_analysis_verifier_rejects_tampered_agent_conclusion_gate(tmp_path: Path) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    artifact = analyze_folded(profile)
    tampered_quality = artifact.evidence_quality.model_copy(
        update={"actual_event_source": "hardware", "forbidden_conclusions": ()}
    )
    tampered = artifact.model_copy(update={"evidence_quality": tampered_quality})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError, match="deterministic verification"):
        verify_analysis_artifact(tampered, verify_source=False)


def test_analysis_verifier_rejects_self_rehashed_conclusion_escalation(tmp_path: Path) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    artifact = analyze_folded(profile)
    tampered_quality = artifact.evidence_quality.model_copy(
        update={
            "allowed_conclusions": (
                *artifact.evidence_quality.allowed_conclusions,
                "verified_improvement",
            )
        }
    )
    tampered = artifact.model_copy(update={"evidence_quality": tampered_quality})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError, match="deterministic verification") as captured:
        verify_analysis_artifact(tampered, verify_source=False)

    assert captured.value.details["failure"] == (
        "allowed conclusions do not match the evidence fields"
    )


def test_analysis_verifier_rejects_removed_normalization_identity_gate(
    fixture_root: Path,
) -> None:
    artifact = analyze_perf_script(
        fixture_root / "perf_script" / "cross-language.perf-script"
    )
    gate = "unique_machine_code_identity_from_normalized_symbol"
    tampered_quality = artifact.evidence_quality.model_copy(
        update={
            "forbidden_conclusions": tuple(
                item for item in artifact.evidence_quality.forbidden_conclusions if item != gate
            )
        }
    )
    tampered = artifact.model_copy(update={"evidence_quality": tampered_quality})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError, match="deterministic verification") as captured:
        verify_analysis_artifact(tampered, verify_source=False)

    assert "unique-code identity" in captured.value.details["failure"]


def test_analysis_verifier_rejects_removed_bounded_output_gate(tmp_path: Path) -> None:
    profile = tmp_path / "bounded.folded"
    profile.write_text("root;a 7\nroot;b 5\n", encoding="utf-8")
    artifact = analyze_folded(
        profile,
        limits=ResourceLimits(max_hotspots_output=1, max_call_paths_output=1),
    )
    gate = "complete_profile_distribution"
    tampered_quality = artifact.evidence_quality.model_copy(
        update={
            "forbidden_conclusions": tuple(
                item for item in artifact.evidence_quality.forbidden_conclusions if item != gate
            )
        }
    )
    tampered = artifact.model_copy(update={"evidence_quality": tampered_quality})
    tampered = tampered.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(tampered)}
    )

    with pytest.raises(PerfLensError, match="deterministic verification") as captured:
        verify_analysis_artifact(tampered, verify_source=False)

    assert "complete-distribution" in captured.value.details["failure"]


def test_analysis_verifier_rehashes_the_original_text_profile(tmp_path: Path) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("root;leaf 7\n", encoding="utf-8")
    artifact = analyze_folded(profile)

    verified = verify_analysis_artifact(artifact, verify_source=True)

    assert verified.status == "verified"
    assert all(check.status == "passed" for check in verified.checks)

    profile.write_text("root;other 7\n", encoding="utf-8")
    with pytest.raises(PerfLensError, match="deterministic verification"):
        verify_analysis_artifact(artifact, verify_source=True)


def test_analysis_rejects_input_changed_after_initial_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "changing.folded"
    profile.write_text("root;first 7\n", encoding="utf-8")
    original_hash = analyze_module._sha256_file  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def changing_hash(path: Path, *, max_bytes: int, chunk_size: int = 1 << 20) -> str:
        nonlocal calls
        digest = original_hash(path, max_bytes=max_bytes, chunk_size=chunk_size)
        calls += 1
        if calls == 1:
            profile.write_text("root;other 7\n", encoding="utf-8")
        return digest

    monkeypatch.setattr(analyze_module, "_sha256_file", changing_hash)

    with pytest.raises(PerfLensError, match="changed while it was being analyzed") as captured:
        analyze_folded(profile)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_malformed_record_source_metadata_does_not_contaminate_valid_samples(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "excluded-source.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 7 cpu-clock:\n"
        "        400101 leaf (/app) /src/excluded.c:77\n"
        "        400100 root (/app) /src/excluded.c:1\n\n"
        "app 1/1 [000] 2.0: 11 cpu-clock:\n"
        "        400101 leaf (/app)\n",
        encoding="utf-8",
    )

    artifact = analyze_perf_script(profile, limits=ResourceLimits(max_stack_depth=1))
    verification = verify_analysis_artifact(artifact, verify_source=True)

    assert artifact.status == "partial"
    assert artifact.metadata.sample_count == 1
    assert not artifact.metadata.has_source_lines
    assert artifact.evidence_quality.source_line_frame_count == 0
    assert artifact.hotspots[0].source_locations == ()
    assert verification.status == "partial"


def test_source_location_truncation_is_visible_and_gates_completeness(tmp_path: Path) -> None:
    profile = tmp_path / "many-source-locations.perf-script"
    profile.write_text(
        "".join(
            f"app 1/1 [000] {index}.0: 1 cpu-clock:\n"
            f"        400{index:03d} leaf (/app) /src/leaf.c:{index}\n\n"
            for index in range(1, 18)
        ),
        encoding="utf-8",
    )

    artifact = analyze_perf_script(profile)
    verification = verify_analysis_artifact(artifact, verify_source=True)

    assert artifact.status == "partial"
    assert len(artifact.hotspots[0].source_locations) == 16
    assert artifact.hotspots[0].source_locations_truncated
    assert artifact.evidence_quality.source_locations_truncated_hotspot_count == 1
    assert (
        "complete_source_location_distribution"
        in artifact.evidence_quality.forbidden_conclusions
    )
    assert verification.status == "partial"


def test_collection_invariants_reject_inconsistent_agent_provenance(tmp_path: Path) -> None:
    collection = CollectionArtifact(
        collection_id="collection-test",
        mode="stat",
        target_type="pid",
        target_argument_count=0,
        target_pid=123,
        output_path=str(tmp_path / "stat.csv"),
        output_sha256="a" * 64,
        output_bytes=10,
        output_format="perf_stat_delimited",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-14T00:00:00+00:00",
        finished_at="2026-08-14T00:00:01+00:00",
        duration_seconds=1,
        events=("task-clock",),
        requested_event_source="software_only",
        actual_event_source="software",
        evidence_limitations=(
            "instructions-per-cycle unavailable",
            "hardware cache-miss evidence unavailable",
            "hardware branch-miss evidence unavailable",
        ),
        metrics=(
            PerfStatMetric(
                event="task-clock",
                value=1.0,
                unit="msec",
                status="measured",
            ),
        ),
    )

    validate_collection_invariants(collection)

    forged = collection.model_copy(update={"actual_event_source": "hardware"})
    with pytest.raises(PerfLensError, match="deterministic consistency checks"):
        validate_collection_invariants(forged)

    missing_metrics = collection.model_copy(update={"metrics": ()})
    with pytest.raises(PerfLensError, match="deterministic consistency checks"):
        validate_collection_invariants(missing_metrics)


def test_hybrid_pmu_stat_spellings_replay_against_generic_requested_events(
    tmp_path: Path,
) -> None:
    output = tmp_path / "hybrid-stat.csv"
    payload = (
        b"100;;cpu_core/cycles/;1000000;100.00\n"
        b"200;;cpu_core/instructions/;1000000;100.00\n"
        b"<not counted>;;cpu_atom/cycles/;0;0.00\n"
        b"<not counted>;;cpu_atom/instructions/;0;0.00\n"
    )
    output.write_bytes(payload)
    metrics, warnings = PerfStatMetricAdapter().parse_bytes(payload)
    collection = CollectionArtifact(
        collection_id="collection-hybrid-stat",
        mode="stat",
        target_type="pid",
        target_argument_count=0,
        target_pid=123,
        output_path=str(output),
        output_sha256=hashlib.sha256(payload).hexdigest(),
        output_bytes=len(payload),
        output_format="perf_stat_delimited",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-15T00:00:00+00:00",
        finished_at="2026-08-15T00:00:01+00:00",
        duration_seconds=1,
        events=("cycles", "instructions"),
        requested_event_source="hardware_required",
        actual_event_source="hardware",
        metrics=metrics,
        warnings=warnings,
    )

    validate_collection_invariants(collection)
    verify_collection_artifact(collection)


def test_unreadable_leaf_frame_keeps_self_weight_unknown(tmp_path: Path) -> None:
    profile = tmp_path / "unreadable-leaf.perf-script"
    profile.write_text(
        "app 1/1 [000] 1.0: 7 cpu-clock:\n"
        "        leaf-without-an-ip\n"
        "        400100 caller (/app)\n",
        encoding="utf-8",
    )

    artifact = analyze_perf_script(profile)
    hotspots = {item.symbol: item for item in artifact.hotspots}

    assert artifact.status == "partial"
    assert artifact.evidence_quality.unresolved_self_weight == 7
    assert hotspots["unknown"].self_weight == 7
    assert hotspots["caller"].self_weight == 0
    assert hotspots["caller"].inclusive_weight == 7
    assert artifact.warnings[0].code == "MALFORMED_FRAME"


def test_source_replay_rejects_a_self_consistent_fabricated_distribution(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile.folded"
    profile.write_text("root;a 7\nroot;b 3\n", encoding="utf-8")
    artifact = analyze_folded(profile)
    hotspots = {item.symbol: item for item in artifact.hotspots}
    paths = {item.frames[-1].symbol: item for item in artifact.call_paths}

    forged_hotspots = (
        hotspots["b"].model_copy(
            update={"hotspot_id": "H-001", "self_weight": 7, "inclusive_weight": 7,
                    "self_percent": 70.0, "inclusive_percent": 70.0}
        ),
        hotspots["a"].model_copy(
            update={"hotspot_id": "H-002", "self_weight": 3, "inclusive_weight": 3,
                    "self_percent": 30.0, "inclusive_percent": 30.0}
        ),
        hotspots["root"].model_copy(update={"hotspot_id": "H-003"}),
    )
    forged_paths = (
        paths["b"].model_copy(
            update={"path_id": "P-001", "weight": 7, "percent": 70.0}
        ),
        paths["a"].model_copy(
            update={"path_id": "P-002", "weight": 3, "percent": 30.0}
        ),
    )
    forged = artifact.model_copy(
        update={"hotspots": forged_hotspots, "call_paths": forged_paths}
    )
    forged = forged.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(forged)}
    )

    verify_analysis_artifact(forged, verify_source=False)
    with pytest.raises(PerfLensError, match="deterministic verification") as captured:
        verify_analysis_artifact(forged, verify_source=True)

    assert captured.value.details["failure"] == (
        "deterministic source replay differs from the stored Analysis"
    )


def test_raw_stat_replay_rejects_typed_metric_not_present_in_csv(tmp_path: Path) -> None:
    output = tmp_path / "stat.csv"
    payload = b"1.0;msec;task-clock;1000000;100.00\n"
    output.write_bytes(payload)
    collection = CollectionArtifact(
        collection_id="collection-raw-mismatch",
        mode="stat",
        target_type="pid",
        target_argument_count=0,
        target_pid=123,
        output_path=str(output),
        output_sha256=hashlib.sha256(payload).hexdigest(),
        output_bytes=len(payload),
        output_format="perf_stat_delimited",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-14T00:00:00+00:00",
        finished_at="2026-08-14T00:00:01+00:00",
        duration_seconds=1,
        events=("task-clock",),
        requested_event_source="software_only",
        actual_event_source="software",
        evidence_limitations=(
            "instructions-per-cycle unavailable",
            "hardware cache-miss evidence unavailable",
            "hardware branch-miss evidence unavailable",
        ),
        metrics=(
            PerfStatMetric(
                event="task-clock",
                value=2.0,
                unit="msec",
                run_time_ns=1_000_000,
                running_percent=100.0,
                status="measured",
            ),
        ),
    )

    with pytest.raises(PerfLensError, match="raw-artifact verification") as captured:
        verify_collection_artifact(collection)

    assert captured.value.details["failure"] == (
        "Typed stat metrics differ from the retained raw CSV"
    )


def test_record_event_must_match_claimed_hardware_or_software_source(tmp_path: Path) -> None:
    collection = CollectionArtifact(
        collection_id="collection-record-source",
        mode="record",
        target_type="pid",
        target_argument_count=0,
        target_pid=123,
        output_path=str(tmp_path / "perf.data"),
        output_sha256="a" * 64,
        output_bytes=8,
        output_format="perf_data",
        perf_executable="/usr/bin/perf",
        started_at="2026-08-14T00:00:00+00:00",
        finished_at="2026-08-14T00:00:01+00:00",
        duration_seconds=1,
        frequency_hz=99,
        call_graph="dwarf",
        record_event="cpu-clock",
        requested_event_source="hardware_required",
        actual_event_source="hardware",
    )

    with pytest.raises(PerfLensError, match="deterministic consistency checks"):
        validate_collection_invariants(collection)
