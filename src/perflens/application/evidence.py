"""Deterministic provenance, quality, and conservation checks for profile analysis."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import BaseModel

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CollectionArtifact,
    CollectionEvidenceProvenance,
    ConversionProvenance,
    DiagnosisBundle,
    EvidenceQuality,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    AggregationResult,
    ParseDiagnostics,
    ProfileConversionProvenance,
)
from perflens.metrics.perf_stat import PerfStatMetricAdapter
from perflens.perf_events import HARDWARE_STAT_EVENTS, SOFTWARE_STAT_EVENTS
from perflens.profiles.events import canonical_perf_event
from perflens.profiles.folded import FOLDED_PARSER_VERSION
from perflens.profiles.perf_script import PERF_SCRIPT_PARSER_VERSION
from perflens.stacks.normalize import SYMBOL_NORMALIZATION_VERSION

ProfileSourceType = Literal["folded", "perf_script", "perf_data"]
_PERF_MAP = re.compile(r"^perf-\d+\.map$")


class _ProvenanceStream(Protocol):
    def conversion_provenance(self) -> ProfileConversionProvenance: ...


def build_conversion_provenance(
    *,
    source_type: ProfileSourceType,
    input_sha256: str,
    input_bytes: int,
    stream: object,
) -> ConversionProvenance:
    if source_type == "perf_data":
        method = getattr(stream, "conversion_provenance", None)
        if not callable(method):
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "provenance",
                "perf.data adapter did not provide conversion provenance",
            )
        provenance = cast(_ProvenanceStream, stream).conversion_provenance()
        return ConversionProvenance(
            adapter="perf_data",
            parser_version=provenance.parser_version,
            normalization_version=provenance.normalization_version,
            converter_path=provenance.converter_path,
            converter_sha256=provenance.converter_sha256,
            converter_version=provenance.converter_version,
            argv=provenance.argv,
            locale=provenance.locale,
            transcript_sha256=provenance.transcript_sha256,
            transcript_bytes=provenance.transcript_bytes,
            compatibility_fallbacks=provenance.compatibility_fallbacks,
            diagnostics=provenance.diagnostics,
        )
    return ConversionProvenance(
        adapter=source_type,
        parser_version=(
            FOLDED_PARSER_VERSION if source_type == "folded" else PERF_SCRIPT_PARSER_VERSION
        ),
        normalization_version=SYMBOL_NORMALIZATION_VERSION,
        locale="input",
        transcript_sha256=input_sha256,
        transcript_bytes=input_bytes,
    )


def conversion_provenance_digest(provenance: ConversionProvenance) -> str:
    return contract_content_sha256(provenance)


def contract_content_sha256(
    model: BaseModel,
    *,
    exclude: set[str] | None = None,
) -> str:
    """Hash a contract's canonical JSON content, independent of pretty-printing."""
    payload = model.model_dump(mode="json", exclude_none=True, exclude=exclude)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def build_collection_evidence_provenance(
    collection: CollectionArtifact,
) -> CollectionEvidenceProvenance:
    validate_collection_invariants(collection)
    if collection.output_format != "perf_data" or collection.mode == "stat":
        raise PerfLensError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "collection",
            "Only perf.data collection artifacts can provide profile provenance",
        )
    return CollectionEvidenceProvenance(
        collection_id=collection.collection_id,
        collection_artifact_sha256=contract_content_sha256(collection),
        mode=collection.mode,
        duration_seconds=collection.duration_seconds,
        frequency_hz=collection.frequency_hz,
        call_graph=collection.call_graph,
        record_event=collection.record_event,
        output_sha256=collection.output_sha256,
        output_bytes=collection.output_bytes,
        target_runtime=collection.target_runtime,
        container_target_id=(
            collection.container_target.target_id
            if collection.container_target is not None
            else None
        ),
        container_target_content_sha256=(
            collection.container_target.target_content_sha256
            if collection.container_target is not None
            else None
        ),
        requested_event_source=collection.requested_event_source,
        actual_event_source=collection.actual_event_source,
        fallback_used=collection.fallback_used,
        fallback_reason=collection.fallback_reason,
        evidence_limitations=collection.evidence_limitations,
        collector_config_sha256=collection.collector_config_sha256,
        collector_privilege_mode=collection.collector_privilege_mode,
        collector_feature_profile=collection.collector_feature_profile,
        host_kernel_release=collection.host_kernel_release,
        perf_executable_sha256=collection.perf_executable_sha256,
    )


def validate_collection_invariants(collection: CollectionArtifact) -> None:
    """Reject internally inconsistent raw-to-typed Collection projections."""
    failures: list[str] = []
    if collection.mode == "stat":
        if collection.output_format != "perf_stat_delimited":
            failures.append("stat Collection output format is not perf_stat_delimited")
        if not collection.metrics:
            failures.append("stat Collection contains no typed metrics")
        if not collection.events:
            failures.append("stat Collection contains no requested events")
        if collection.frequency_hz is not None or collection.call_graph is not None:
            failures.append("stat Collection contains sampling settings")
        if collection.record_event is not None:
            failures.append("stat Collection contains a record event")
        base_metrics = tuple(metric for metric in collection.metrics if not metric.derived)
        base_events = tuple(metric.event for metric in base_metrics)
        if len(base_events) != len(set(base_events)):
            failures.append("stat Collection contains duplicate base metric events")
        if len(collection.events) != len(set(collection.events)):
            failures.append("stat Collection contains duplicate requested events")
        canonical_base_events = {canonical_perf_event(event) for event in base_events}
        canonical_requested_events = {
            canonical_perf_event(event) for event in collection.events
        }
        if canonical_base_events != canonical_requested_events:
            failures.append("stat Collection metrics do not match its requested events")
        _validate_ipc_metric(collection, failures)
    else:
        if collection.output_format != "perf_data":
            failures.append("profile Collection output format is not perf_data")
        if collection.metrics:
            failures.append("profile Collection unexpectedly contains stat metrics")
        if collection.events:
            failures.append("profile Collection unexpectedly contains stat events")

    if collection.mode == "record":
        if collection.frequency_hz is None or collection.call_graph is None:
            failures.append("record Collection omits sampling settings")
        if collection.record_event is None:
            failures.append("record Collection omits its selected event")
        elif (
            collection.actual_event_source == "hardware"
            and canonical_perf_event(collection.record_event) != "cycles"
        ):
            failures.append("hardware record Collection did not select cycles")
        elif (
            collection.actual_event_source == "software"
            and canonical_perf_event(collection.record_event) != "cpu-clock"
        ):
            failures.append("software record Collection did not select cpu-clock")
    elif collection.record_event is not None:
        failures.append("non-record Collection contains a record event")

    if collection.mode in {"record", "stat"}:
        if collection.actual_event_source == "unknown":
            failures.append("record/stat Collection has an unknown actual event source")
        if (
            collection.requested_event_source == "software_only"
            and collection.actual_event_source != "software"
        ):
            failures.append("software-only request did not produce software evidence")
        if (
            collection.requested_event_source == "hardware_required"
            and collection.actual_event_source != "hardware"
        ):
            failures.append("hardware-required request did not produce hardware evidence")
        if collection.mode == "stat" and collection.actual_event_source == "hardware":
            hardware_events = {
                canonical_perf_event(event) for event in collection.events
            }.intersection(HARDWARE_STAT_EVENTS)
            if not hardware_events:
                failures.append("hardware Collection contains no hardware event")
            probe_events = hardware_events.intersection({"cycles", "instructions"})
            required_usable = probe_events or hardware_events
            if not any(
                canonical_perf_event(metric.event) in required_usable
                and metric.status == "measured"
                and metric.value is not None
                and (
                    metric.value > 0
                    if canonical_perf_event(metric.event) in probe_events
                    else metric.value >= 0
                )
                for metric in collection.metrics
            ):
                failures.append("hardware Collection contains no usable hardware metric")
        if collection.mode == "stat" and collection.actual_event_source == "software" and any(
            canonical_perf_event(event) not in SOFTWARE_STAT_EVENTS
            for event in collection.events
        ):
            failures.append("software Collection contains a non-software event")

    if collection.fallback_used:
        if collection.requested_event_source != "auto":
            failures.append("fallback is attached to a non-auto request")
        if collection.actual_event_source != "software":
            failures.append("fallback did not produce software evidence")
        if not collection.fallback_reason:
            failures.append("fallback reason is missing")
    elif collection.fallback_reason is not None:
        failures.append("fallback reason is present when fallback_used is false")

    software_limits = {
        "instructions-per-cycle unavailable",
        "hardware cache-miss evidence unavailable",
        "hardware branch-miss evidence unavailable",
    }
    if collection.actual_event_source == "software" and not software_limits.issubset(
        collection.evidence_limitations
    ):
        failures.append("software Collection omits required hardware-evidence limitations")

    if failures:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "evidence_validation",
            "Collection evidence failed deterministic consistency checks",
            details={"collection_id": collection.collection_id, "failures": failures},
            suggested_actions=(
                "Do not use this Collection for Agent conclusions; preserve its raw output.",
            ),
        )


def verify_collection_artifact(
    collection: CollectionArtifact,
    *,
    max_output_bytes: int = 128 << 20,
) -> None:
    """Re-hash and, for stat, independently reparse one immutable raw snapshot."""
    validate_collection_invariants(collection)
    if collection.output_bytes > max_output_bytes:
        raise _collection_verification_error(
            collection,
            "Collection output exceeds the verification byte limit",
        )
    candidate = Path(collection.output_path).expanduser()
    if not candidate.is_absolute():
        raise _collection_verification_error(collection, "Collection output path is not absolute")
    descriptor = -1
    try:
        descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != collection.output_bytes
        ):
            raise _collection_verification_error(
                collection,
                "Collection output identity or size is unsafe",
            )
        payload = bytearray()
        while len(payload) <= collection.output_bytes:
            chunk = os.read(descriptor, min(1 << 20, collection.output_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    except PerfLensError:
        raise
    except OSError as exc:
        raise _collection_verification_error(
            collection,
            "Collection output cannot be opened safely",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if _raw_file_identity(before) != _raw_file_identity(after):
        raise _collection_verification_error(collection, "Collection output changed while read")
    raw = bytes(payload)
    if (
        len(raw) != collection.output_bytes
        or hashlib.sha256(raw).hexdigest() != collection.output_sha256
    ):
        raise _collection_verification_error(
            collection,
            "Collection output does not match its recorded size and SHA-256",
        )
    if collection.mode != "stat":
        return
    reparsed_metrics, reparsed_warnings = PerfStatMetricAdapter(
        max_input_bytes=max_output_bytes
    ).parse_bytes(raw)
    if reparsed_metrics != collection.metrics:
        raise _collection_verification_error(
            collection,
            "Typed stat metrics differ from the retained raw CSV",
        )
    if any(warning not in collection.warnings for warning in reparsed_warnings):
        raise _collection_verification_error(
            collection,
            "Raw stat parse warning is absent from the Collection",
        )


def _validate_ipc_metric(collection: CollectionArtifact, failures: list[str]) -> None:
    base = {metric.event: metric for metric in collection.metrics if not metric.derived}
    derived = [metric for metric in collection.metrics if metric.event == "instructions-per-cycle"]
    cycles = base.get("cycles")
    instructions = base.get("instructions")
    expected_ipc: float | None = None
    if (
        cycles is not None
        and instructions is not None
        and cycles.status == "measured"
        and instructions.status == "measured"
        and cycles.value is not None
        and instructions.value is not None
        and cycles.value > 0
    ):
        expected_ipc = instructions.value / cycles.value
    if expected_ipc is not None:
        if len(derived) != 1 or derived[0].value is None or not math.isclose(
            derived[0].value,
            expected_ipc,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            failures.append("stat Collection IPC does not match measured instructions/cycles")
    elif derived:
        failures.append("stat Collection contains IPC without usable instructions/cycles")


def _raw_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _collection_verification_error(
    collection: CollectionArtifact,
    failure: str,
) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        "Collection evidence failed raw-artifact verification",
        details={"collection_id": collection.collection_id, "failure": failure},
        suggested_actions=(
            "Do not use this Collection for Agent conclusions; retain it for investigation.",
        ),
    )


def compute_analysis_fingerprint(
    *,
    input_sha256: str,
    source_type: str,
    aggregation_semantics: str,
    limits: Mapping[str, int],
    conversion: ConversionProvenance,
    collection: CollectionEvidenceProvenance | None,
) -> str:
    digest = hashlib.sha256()
    components = (
        "perflens-analysis-v3",
        source_type,
        input_sha256,
        aggregation_semantics,
        conversion_provenance_digest(conversion),
        contract_content_sha256(collection) if collection is not None else "no-collection",
        *[f"{key}={value}" for key, value in sorted(limits.items())],
    )
    digest.update("\0".join(components).encode())
    return digest.hexdigest()


def compute_analysis_content_sha256(analysis: AnalysisArtifact) -> str:
    """Bind every Agent-visible Analysis field except the digest itself."""
    return contract_content_sha256(analysis, exclude={"content_sha256"})


def compute_diagnosis_content_sha256(diagnosis: DiagnosisBundle) -> str:
    """Bind every Agent-visible Diagnosis field except the digest itself."""
    return contract_content_sha256(diagnosis, exclude={"content_sha256"})


def validate_aggregation_invariants(
    result: AggregationResult,
    diagnostics: ParseDiagnostics,
    *,
    source_type: ProfileSourceType,
) -> None:
    failures: list[str] = []
    self_total = sum(item.self_weight for item in result.hotspots)
    call_path_total = sum(item.weight for item in result.call_paths)
    if result.record_count != diagnostics.parsed_records:
        failures.append("parsed record count differs from aggregated record count")
    if self_total != result.total_weight:
        failures.append("hotspot Self weight does not equal total profile weight")
    if call_path_total != result.total_weight:
        failures.append("call-path weight does not equal total profile weight")
    if result.unknown_self_weight > result.total_weight:
        failures.append("unknown Self weight exceeds total profile weight")
    if result.call_graph_weight > result.total_weight:
        failures.append("call-graph weight exceeds total profile weight")
    if result.source_line_self_weight > result.total_weight:
        failures.append("source-line Self weight exceeds total profile weight")
    if (
        source_type in {"perf_script", "perf_data"}
        and diagnostics.malformed_records == 0
        and diagnostics.frame_lines != result.total_frame_count + diagnostics.duplicate_frame_lines
    ):
        failures.append("parsed Frame line accounting does not match aggregated frames")
    if failures:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "evidence_validation",
            "Profile evidence failed deterministic conservation checks",
            details={"failures": failures},
            suggested_actions=(
                "Preserve the raw profile and converter diagnostics; do not use this analysis.",
            ),
        )


def build_evidence_quality(
    result: AggregationResult,
    diagnostics: ParseDiagnostics,
    conversion: ConversionProvenance,
    *,
    exported_hotspot_count: int,
    exported_hotspot_self_weight: int,
    exported_call_path_count: int,
    exported_call_path_weight: int,
    input_sha256: str,
    input_bytes: int,
    collection: CollectionEvidenceProvenance | None,
    inherited_limitations: Sequence[str] = (),
) -> EvidenceQuality:
    total = result.total_weight
    unresolved_self_percent = _percent(result.unknown_self_weight, total)
    call_graph_weight_percent = _percent(result.call_graph_weight, total)
    source_line_self_percent = _percent(result.source_line_self_weight, total)
    omitted_hotspot_self_weight = max(0, total - exported_hotspot_self_weight)
    omitted_call_path_weight = max(0, total - exported_call_path_weight)

    actual_event_source: Literal["hardware", "software", "unknown"] = (
        collection.actual_event_source if collection is not None else "unknown"
    )
    fallback_used = collection.fallback_used if collection is not None else None
    fallback_reason = collection.fallback_reason if collection is not None else None
    collection_limitations = (
        collection.evidence_limitations if collection is not None else tuple(inherited_limitations)
    )
    limitations = list(collection_limitations)
    partial_reasons: list[str] = []
    if diagnostics.malformed_records:
        partial_reasons.append(
            f"{diagnostics.malformed_records} malformed profile record(s) were excluded."
        )
    if diagnostics.warning_count:
        partial_reasons.append(
            f"The parser or converter emitted {diagnostics.warning_count} warning(s)."
        )
    if diagnostics.warnings_truncated:
        partial_reasons.append("Additional parse warnings were truncated.")
    if diagnostics.unicode_replacement_count:
        partial_reasons.append(
            f"Input decoding replaced {diagnostics.unicode_replacement_count} invalid character(s)."
        )
    if result.unknown_self_weight:
        partial_reasons.append(f"{unresolved_self_percent:.3f}% of Self weight is unresolved.")
    if conversion.diagnostics:
        partial_reasons.append("The external converter emitted diagnostics.")
    if omitted_hotspot_self_weight:
        partial_reasons.append("The bounded hotspot output omits some Self weight.")
    if omitted_call_path_weight:
        partial_reasons.append("The bounded call-path output omits some sample weight.")

    if total == 0:
        partial_reasons.append("The profile contains no usable weighted samples.")
    if call_graph_weight_percent < 100.0:
        limitations.append(
            f"Only {call_graph_weight_percent:.3f}% of weight has a multi-frame call graph."
        )
    if source_line_self_percent < 100.0:
        limitations.append(
            f"Only {source_line_self_percent:.3f}% of Self weight has a source line."
        )
    if result.normalization_merge_count:
        limitations.append(
            f"{result.normalization_merge_count} logical hotspot(s) merge multiple raw symbol "
            "identities; inspect symbol_variants before treating them as one code instance."
        )
    source_locations_truncated_hotspot_count = sum(
        1 for item in result.hotspots if item.source_locations_truncated
    )
    if source_locations_truncated_hotspot_count:
        partial_reasons.append(
            f"Source locations were truncated for {source_locations_truncated_hotspot_count} "
            "logical hotspot(s)."
        )
    has_jit_perf_map = any(
        _PERF_MAP.fullmatch(item.dso.rsplit("/", 1)[-1]) is not None for item in result.hotspots
    )
    if conversion.adapter == "perf_data" and has_jit_perf_map:
        limitations.append(
            "JIT symbols were resolved through a perf map that is not retained in this Analysis; "
            "cross-time replay requires a frozen sidecar."
        )
    if actual_event_source == "unknown":
        limitations.append("The hardware/software event source is not independently known.")
    if fallback_used:
        limitations.append(
            f"Collection used a fallback event source: {fallback_reason or 'reason unavailable'}."
        )
    limitations.extend(partial_reasons)

    allowed: list[str] = []
    if total:
        allowed.append("sampled_event_hotspot_distribution")
    if result.call_graph_weight:
        allowed.append("call_path_distribution")
    if result.source_line_self_weight:
        allowed.append("source_line_observation")
    if total and is_on_cpu_sampling_event(result.event):
        allowed.append("on_cpu_hotspot_distribution")

    forbidden = ["performance_root_cause", "verified_improvement"]
    if actual_event_source != "hardware":
        forbidden.extend(
            (
                "instructions_per_cycle",
                "hardware_cache_miss_rate",
                "hardware_branch_miss_rate",
                "microarchitectural_bottleneck",
            )
        )
    if not result.call_graph_weight:
        forbidden.append("caller_callee_relationship")
    if not result.source_line_self_weight:
        forbidden.append("exact_source_line_attribution")
    if result.normalization_merge_count:
        forbidden.append("unique_machine_code_identity_from_normalized_symbol")
    if conversion.adapter == "perf_data" and has_jit_perf_map:
        forbidden.append("cross_time_jit_symbol_replay")
    if omitted_hotspot_self_weight or omitted_call_path_weight:
        forbidden.append("complete_profile_distribution")
    if source_locations_truncated_hotspot_count:
        forbidden.append("complete_source_location_distribution")
    quality_status: Literal["verified", "partial"] = "partial" if partial_reasons else "verified"
    if quality_status == "partial":
        forbidden.append("unqualified_profile_conclusion")

    return EvidenceQuality(
        quality_status=quality_status,
        parser_invariants_passed=True,
        actual_event_source=actual_event_source,
        fallback_used=fallback_used,
        fallback_reason=fallback_reason,
        input_sha256=input_sha256,
        input_bytes=input_bytes,
        source_collection_id=(collection.collection_id if collection is not None else None),
        source_collection_artifact_sha256=(
            collection.collection_artifact_sha256 if collection is not None else None
        ),
        sample_count=result.record_count,
        total_weight=total,
        event=result.event,
        weight_unit=result.weight_unit,
        weight_source=result.weight_source,
        malformed_record_count=diagnostics.malformed_records,
        warning_count=diagnostics.warning_count,
        warnings_truncated=diagnostics.warnings_truncated,
        unicode_replacement_count=diagnostics.unicode_replacement_count,
        frame_line_count=diagnostics.frame_lines,
        duplicate_frame_line_count=diagnostics.duplicate_frame_lines,
        address_annotation_line_count=diagnostics.address_annotation_lines,
        source_annotation_line_count=diagnostics.source_annotation_lines,
        aggregated_frame_occurrence_count=result.total_frame_count,
        unresolved_self_weight=result.unknown_self_weight,
        unresolved_self_percent=unresolved_self_percent,
        call_graph_weight=result.call_graph_weight,
        call_graph_weight_percent=call_graph_weight_percent,
        source_line_frame_count=result.source_line_frame_count,
        source_line_self_weight=result.source_line_self_weight,
        source_line_self_percent=source_line_self_percent,
        inline_frame_count=result.inline_frame_count,
        normalization_merge_count=result.normalization_merge_count,
        source_locations_truncated_hotspot_count=(
            source_locations_truncated_hotspot_count
        ),
        total_hotspot_count=len(result.hotspots),
        exported_hotspot_count=exported_hotspot_count,
        omitted_hotspot_self_weight=omitted_hotspot_self_weight,
        total_call_path_count=len(result.call_paths),
        exported_call_path_count=exported_call_path_count,
        omitted_call_path_weight=omitted_call_path_weight,
        allowed_conclusions=tuple(dict.fromkeys(allowed)),
        forbidden_conclusions=tuple(dict.fromkeys(forbidden)),
        collection_limitations=collection_limitations,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _percent(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(value * 100.0 / total, 6)


def is_on_cpu_sampling_event(event: str) -> bool:
    return canonical_perf_event(event) in {"cpu-clock", "task-clock", "cycles"}
