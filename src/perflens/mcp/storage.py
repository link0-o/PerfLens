"""Root-confined artifact storage for MCP tools."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from perflens.application.evidence import (
    compute_diagnosis_content_sha256,
    contract_content_sha256,
    verify_collection_artifact,
)
from perflens.application.runtime_lock_evidence import (
    validate_runtime_lock_evidence_invariants,
)
from perflens.application.runtime_lock_queries import (
    build_runtime_lock_diagnosis_bundle,
)
from perflens.application.trace_evidence import validate_trace_evidence_invariants
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.application.verify_runtime_locks import (
    require_usable_runtime_lock_analysis,
    verify_runtime_lock_analysis_artifact,
)
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json, write_json_new_atomic
from perflens.comparison.benchmarks import compare_benchmarks
from perflens.comparison.profiles import compare_profiles
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    BenchmarkArtifact,
    BenchmarkComparison,
    CollectionArtifact,
    DiagnosisBundle,
    ProfileComparison,
    ProjectRunArtifact,
)
from perflens.contracts.docker import (
    ContainerMatchedComparisonArtifact,
    ContainerMeasurementArtifact,
    ContainerModuleSnapshotArtifact,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerSymbolContextArtifact,
    ContainerWorkloadSpecArtifact,
    derive_container_module_snapshot_id,
    derive_container_symbol_context_id,
)
from perflens.contracts.docker_build import (
    DockerBuildArtifact,
    DockerOptimizationDispositionArtifact,
    DockerOptimizationIterationArtifact,
    DockerOptimizationSessionArtifact,
)
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockCapabilityArtifact,
    RuntimeLockComparisonArtifact,
    RuntimeLockRunArtifact,
    RuntimeLockRunFinalizationArtifact,
    RuntimeLockSessionArtifact,
    RuntimeLockSessionPreviewArtifact,
    derive_runtime_lock_run_boundaries,
    derive_runtime_lock_run_finalization_id,
)
from perflens.contracts.runtime_locks import (
    MeasurementSemantics,
    RuntimeAdapterCapabilityArtifact,
    RuntimeLockAnalysisArtifact,
    RuntimeLockAnalysisVerificationArtifact,
    RuntimeLockDiagnosisBundleArtifact,
    RuntimeLockEvidenceArtifact,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceAnalysisVerificationArtifact,
    TraceEvidenceArtifact,
)
from perflens.docker.comparison import (
    build_container_measurement,
    compare_container_measurements,
)
from perflens.docker.optimization_comparison import (
    compare_docker_optimization_iteration,
)
from perflens.docker.symbols import assert_public_container_analysis
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import validate_new_output_file

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_RUNTIME_LOCK_SESSION_REVISIONS = 32
_RUNTIME_LOCK_ADAPTER_SOURCE_FORMATS = {
    "cpython_threading": "cpython_threading_ndjson_v1",
    "generic_ndjson_import": "perflens_runtime_lock_ndjson_v1",
    "go_pprof": "pprof_text_v1",
    "java_jfr": "jfr_json_v1",
    "native_pthread": "native_interposer_ndjson_v1",
}
ModelT = TypeVar("ModelT", bound=BaseModel)
type TraceAnalysisArtifact = (
    SchedulerAnalysisArtifact | OffCpuAnalysisArtifact | LockAnalysisArtifact
)

_TRACE_ANALYSIS_TYPES: dict[
    str,
    tuple[type[TraceAnalysisArtifact], str],
] = {
    "scheduler-analysis": (SchedulerAnalysisArtifact, "scheduler_analysis_id"),
    "off-cpu-analysis": (OffCpuAnalysisArtifact, "off_cpu_analysis_id"),
    "lock-analysis": (LockAnalysisArtifact, "lock_analysis_id"),
}


class PathPolicy:
    def __init__(self, allowed_roots: tuple[Path, ...]) -> None:
        if not allowed_roots:
            raise ValueError("At least one allowed root is required")
        self.allowed_roots = tuple(root.expanduser().resolve(strict=True) for root in allowed_roots)
        if any(not root.is_dir() for root in self.allowed_roots):
            raise ValueError("Every allowed root must be a directory")

    def input_file(self, path: str | Path) -> Path:
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "mcp",
                "Input file cannot be resolved",
                details={"path": str(path)},
            ) from exc
        if not resolved.is_file() or not self.contains(resolved):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "mcp",
                "Input file is outside the configured allowed roots",
                details={"path": str(resolved)},
            )
        return resolved

    def workspace_root(self, path: str | Path) -> Path:
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "mcp",
                "Workspace root cannot be resolved",
                details={"path": str(path)},
            ) from exc
        if not resolved.is_dir() or not self.contains(resolved):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "mcp",
                "Workspace root is outside the configured allowed roots",
                details={"path": str(resolved)},
            )
        return resolved

    def new_output_file(self, path: str | Path) -> Path:
        resolved = validate_new_output_file(Path(path))
        if not self.contains(resolved):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "mcp",
                "Output file is outside the configured allowed roots",
                details={"path": str(resolved)},
            )
        return resolved

    def contains(self, path: Path) -> bool:
        return any(path.is_relative_to(root) for root in self.allowed_roots)


class ArtifactStore:
    def __init__(
        self,
        root: Path,
        policy: PathPolicy,
        *,
        allow_writes: bool,
        max_artifact_bytes: int = 128 << 20,
    ) -> None:
        if max_artifact_bytes < 1:
            raise ValueError("max_artifact_bytes must be positive")
        candidate = root.expanduser().resolve(strict=False)
        if not policy.contains(candidate):
            raise ValueError("Artifact root must be inside an allowed root")
        if candidate.exists() and not candidate.is_dir():
            raise ValueError("Artifact root must be a directory")
        self.root = candidate
        self.policy = policy
        self.allow_writes = allow_writes
        self.max_artifact_bytes = max_artifact_bytes
        if allow_writes:
            root_existed = self.root.exists()
            self.root.mkdir(parents=True, exist_ok=True)
            if not root_existed:
                self.root.chmod(0o700)
        self._root_identity = self._inspect_root()

    def save(self, model: BaseModel, artifact_id: str, artifact_type: str) -> Path:
        if not self.allow_writes:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "authorization",
                "Artifact writes are disabled by server policy",
                recoverable=True,
            )
        safe_id = self._safe_component(artifact_id)
        safe_type = self._safe_component(artifact_type)
        output = self._path(safe_id, safe_type)
        expected = serialize_json(model)
        self._assert_root_identity()
        try:
            write_json_new_atomic(model, output, max_output_bytes=self.max_artifact_bytes)
        except PerfLensError as exc:
            if exc.code is not ErrorCode.PATH_SAFETY_VIOLATION:
                raise
            existing = self._read_file(output, maximum=self.max_artifact_bytes)
            if existing != expected:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "artifact",
                    "Artifact identifier already exists with different content",
                    details={"artifact_id": safe_id, "artifact_type": safe_type},
                ) from exc
        self._assert_root_identity()
        return output

    def save_runtime_lock_settlement(
        self,
        session: RuntimeLockSessionArtifact,
        finalization: RuntimeLockRunFinalizationArtifact,
    ) -> tuple[Path, Path]:
        """Persist a reconciled Session and publish its finalization marker last."""

        if (
            session.schema_version != "1.1"
            or finalization.final_session_artifact_id != session.session_artifact_id
            or finalization.final_session_artifact_content_sha256 != session.content_sha256
            or finalization.final_session_revision != session.revision
            or session.settlement_finalization_id != finalization.finalization_id
        ):
            raise self._identity_error(
                finalization.finalization_id,
                "runtime-lock-run-finalization",
            )
        session_path = self.save(
            session,
            session.session_artifact_id,
            "runtime-lock-session",
        )
        marker_path = self.save(
            finalization,
            finalization.finalization_id,
            "runtime-lock-run-finalization",
        )
        return session_path, marker_path

    def load_analysis(self, analysis_id: str) -> AnalysisArtifact:
        analysis = self._load(analysis_id, "analysis", AnalysisArtifact)
        self._require_embedded_id(analysis.analysis_id, analysis_id, "analysis")
        verify_analysis_artifact(analysis, verify_source=False)
        assert_public_container_analysis(analysis)
        return analysis

    def load_diagnosis(self, analysis_id: str) -> DiagnosisBundle | None:
        diagnosis_id = f"diagnosis-{analysis_id}"
        if not self._path(diagnosis_id, "diagnosis").exists():
            return None
        diagnosis = self._load(diagnosis_id, "diagnosis", DiagnosisBundle)
        self._require_embedded_id(diagnosis.analysis_id, analysis_id, "diagnosis")
        analysis = self.load_analysis(analysis_id)
        self._verify_diagnosis(diagnosis, analysis)
        return diagnosis

    def load_benchmark(self, benchmark_id: str) -> BenchmarkArtifact:
        benchmark = self._load(benchmark_id, "benchmark", BenchmarkArtifact)
        self._require_embedded_id(benchmark.benchmark_id, benchmark_id, "benchmark")
        return benchmark

    def load_profile_comparison(self, comparison_id: str) -> ProfileComparison:
        comparison = self._load(comparison_id, "profile-comparison", ProfileComparison)
        self._require_embedded_id(comparison.comparison_id, comparison_id, "profile-comparison")
        replayed = compare_profiles(
            self.load_analysis(comparison.baseline_analysis_id),
            self.load_analysis(comparison.candidate_analysis_id),
            minimum_delta_percent=comparison.minimum_delta_percent,
        )
        if replayed != comparison:
            raise self._identity_error(comparison_id, "profile-comparison")
        return comparison

    def load_benchmark_comparison(self, comparison_id: str) -> BenchmarkComparison:
        comparison = self._load(
            comparison_id,
            "benchmark-comparison",
            BenchmarkComparison,
        )
        self._require_embedded_id(
            comparison.comparison_id,
            comparison_id,
            "benchmark-comparison",
        )
        replayed = compare_benchmarks(
            self.load_benchmark(comparison.baseline_benchmark_id),
            self.load_benchmark(comparison.candidate_benchmark_id),
            minimum_practical_impact_percent=(comparison.minimum_practical_impact_percent),
        )
        if replayed != comparison:
            raise self._identity_error(comparison_id, "benchmark-comparison")
        return comparison

    def load_collection(self, collection_id: str) -> CollectionArtifact:
        collection = self._load(collection_id, "collection", CollectionArtifact)
        self._require_embedded_id(collection.collection_id, collection_id, "collection")
        self.policy.input_file(collection.output_path)
        verify_collection_artifact(collection, max_output_bytes=self.max_artifact_bytes)
        return collection

    def load_trace_evidence(self, trace_evidence_id: str) -> TraceEvidenceArtifact:
        evidence = self._load(trace_evidence_id, "trace-evidence", TraceEvidenceArtifact)
        self._require_embedded_id(
            evidence.trace_evidence_id,
            trace_evidence_id,
            "trace-evidence",
        )
        validate_trace_evidence_invariants(evidence)
        return evidence

    def load_runtime_lock_evidence(
        self,
        runtime_lock_evidence_id: str,
    ) -> RuntimeLockEvidenceArtifact:
        evidence = self._load(
            runtime_lock_evidence_id,
            "runtime-lock-evidence",
            RuntimeLockEvidenceArtifact,
        )
        self._require_embedded_id(
            evidence.runtime_lock_evidence_id,
            runtime_lock_evidence_id,
            "runtime-lock-evidence",
        )
        validate_runtime_lock_evidence_invariants(evidence)
        return evidence

    def load_runtime_adapter_capability(
        self,
        capability_id: str,
    ) -> RuntimeAdapterCapabilityArtifact:
        capability = self._load(
            capability_id,
            "runtime-adapter-capability",
            RuntimeAdapterCapabilityArtifact,
        )
        self._require_embedded_id(
            capability.capability_id,
            capability_id,
            "runtime-adapter-capability",
        )
        self._verify_contract_content(
            capability,
            capability.content_sha256,
            capability_id,
            "runtime-adapter-capability",
        )
        return capability

    def load_runtime_lock_capability(
        self,
        capability_id: str,
    ) -> RuntimeLockCapabilityArtifact:
        capability = self._load(
            capability_id,
            "runtime-lock-capability",
            RuntimeLockCapabilityArtifact,
        )
        self._require_embedded_id(
            capability.capability_id,
            capability_id,
            "runtime-lock-capability",
        )
        self._verify_contract_content(
            capability,
            capability.content_sha256,
            capability_id,
            "runtime-lock-capability",
        )
        for reference in capability.adapters:
            adapter = self.load_runtime_adapter_capability(reference.capability_id)
            if (
                adapter.adapter_id != reference.adapter_id
                or adapter.content_sha256 != reference.capability_content_sha256
                or adapter.availability != reference.availability
                or adapter.measurement_semantics != reference.supported_semantics
                or adapter.limitations != reference.limitations
            ):
                raise self._identity_error(capability_id, "runtime-lock-capability")
        return capability

    def load_runtime_lock_preview(
        self,
        preview_id: str,
    ) -> RuntimeLockSessionPreviewArtifact:
        preview = self._load(
            preview_id,
            "runtime-lock-preview",
            RuntimeLockSessionPreviewArtifact,
        )
        self._require_embedded_id(
            preview.preview_id,
            preview_id,
            "runtime-lock-preview",
        )
        self._verify_contract_content(
            preview,
            preview.content_sha256,
            preview_id,
            "runtime-lock-preview",
        )
        expected_summary = contract_content_sha256(
            preview,
            exclude={"authorization_summary_sha256", "content_sha256"},
        )
        capability = self.load_runtime_lock_capability(preview.capability_id)
        references = {reference.adapter_id: reference for reference in capability.adapters}
        covered_semantics: set[MeasurementSemantics] = set()
        preview_scope_matches = True
        for adapter_id in preview.allowed_adapters:
            reference = references.get(adapter_id)
            if reference is None or reference.availability not in {"available", "partial"}:
                preview_scope_matches = False
                break
            selected = set(reference.supported_semantics) & set(preview.allowed_semantics)
            if not selected:
                preview_scope_matches = False
                break
            covered_semantics.update(selected)
        if (
            preview.authorization_summary_sha256 != expected_summary
            or preview.capability_content_sha256 != capability.content_sha256
            or preview.project_identity_sha256 != capability.project_identity_sha256
            or preview.project_policy_sha256 != capability.project_policy_sha256
            or not preview_scope_matches
            or covered_semantics != set(preview.allowed_semantics)
        ):
            raise self._identity_error(preview_id, "runtime-lock-preview")
        return preview

    def load_runtime_lock_analysis(
        self,
        runtime_lock_analysis_id: str,
    ) -> tuple[
        RuntimeLockAnalysisArtifact,
        RuntimeLockEvidenceArtifact,
        RuntimeLockAnalysisVerificationArtifact,
    ]:
        analysis = self._load(
            runtime_lock_analysis_id,
            "runtime-lock-analysis",
            RuntimeLockAnalysisArtifact,
        )
        self._require_embedded_id(
            analysis.runtime_lock_analysis_id,
            runtime_lock_analysis_id,
            "runtime-lock-analysis",
        )
        evidence = self.load_runtime_lock_evidence(analysis.runtime_lock_evidence_id)
        verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
        require_usable_runtime_lock_analysis(verification)
        return analysis, evidence, verification

    def load_runtime_lock_verification(
        self,
        runtime_lock_verification_id: str,
    ) -> RuntimeLockAnalysisVerificationArtifact:
        verification = self._load(
            runtime_lock_verification_id,
            "runtime-lock-verification",
            RuntimeLockAnalysisVerificationArtifact,
        )
        self._require_embedded_id(
            verification.runtime_lock_verification_id,
            runtime_lock_verification_id,
            "runtime-lock-verification",
        )
        self._verify_contract_content(
            verification,
            verification.content_sha256,
            runtime_lock_verification_id,
            "runtime-lock-verification",
        )
        analysis, evidence, _ = self.load_runtime_lock_analysis(
            verification.runtime_lock_analysis_id
        )
        replayed = verify_runtime_lock_analysis_artifact(
            analysis,
            evidence,
            source_replay_receipt=verification.source_replay_receipt,
        )
        if (
            replayed != verification
            or verification.runtime_lock_analysis_content_sha256 != analysis.content_sha256
            or verification.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id
            or verification.runtime_lock_evidence_content_sha256 != evidence.content_sha256
        ):
            raise self._identity_error(
                runtime_lock_verification_id,
                "runtime-lock-verification",
            )
        return verification

    def load_runtime_lock_diagnosis(
        self,
        runtime_lock_diagnosis_id: str,
    ) -> RuntimeLockDiagnosisBundleArtifact:
        diagnosis = self._load(
            runtime_lock_diagnosis_id,
            "runtime-lock-diagnosis",
            RuntimeLockDiagnosisBundleArtifact,
        )
        self._require_embedded_id(
            diagnosis.runtime_lock_diagnosis_id,
            runtime_lock_diagnosis_id,
            "runtime-lock-diagnosis",
        )
        self._verify_contract_content(
            diagnosis,
            diagnosis.content_sha256,
            runtime_lock_diagnosis_id,
            "runtime-lock-diagnosis",
        )
        analysis, evidence, verification = self.load_runtime_lock_analysis(
            diagnosis.runtime_lock_analysis_id
        )
        replayed = build_runtime_lock_diagnosis_bundle(
            analysis,
            evidence,
            verification,
        )
        if replayed != diagnosis:
            raise self._identity_error(
                runtime_lock_diagnosis_id,
                "runtime-lock-diagnosis",
            )
        return diagnosis

    def load_runtime_lock_session(
        self,
        session_artifact_id: str,
    ) -> RuntimeLockSessionArtifact:
        return self._load_runtime_lock_session_chain(session_artifact_id, seen=set())

    def _load_runtime_lock_session_chain(
        self,
        session_artifact_id: str,
        *,
        seen: set[str],
    ) -> RuntimeLockSessionArtifact:
        if session_artifact_id in seen:
            raise self._identity_error(session_artifact_id, "runtime-lock-session")
        seen.add(session_artifact_id)
        session = self._load(
            session_artifact_id,
            "runtime-lock-session",
            RuntimeLockSessionArtifact,
        )
        self._require_embedded_id(
            session.session_artifact_id,
            session_artifact_id,
            "runtime-lock-session",
        )
        self._verify_contract_content(
            session,
            session.content_sha256,
            session_artifact_id,
            "runtime-lock-session",
        )
        if session.revision > _MAX_RUNTIME_LOCK_SESSION_REVISIONS:
            raise self._identity_error(session_artifact_id, "runtime-lock-session")
        preview = self.load_runtime_lock_preview(session.preview_id)
        created = datetime.fromisoformat(session.created_at)
        if (
            session.schema_version != preview.schema_version
            or session.perflens_version != preview.perflens_version
            or session.preview_content_sha256 != preview.content_sha256
            or session.project_identity_sha256 != preview.project_identity_sha256
            or session.client_connection_identity_sha256
            != preview.client_connection_identity_sha256
            or session.project_policy_sha256 != preview.project_policy_sha256
            or session.capability_id != preview.capability_id
            or session.capability_content_sha256 != preview.capability_content_sha256
            or session.runtime_lock_config_sha256 != preview.runtime_lock_config_sha256
            or session.target_scope != preview.target_scope
            or session.allowed_adapters != preview.allowed_adapters
            or session.allowed_semantics != preview.allowed_semantics
            or session.budget != preview.budget
            or created < datetime.fromisoformat(preview.created_at)
            or created > datetime.fromisoformat(preview.expires_at)
            or (datetime.fromisoformat(session.expires_at) - created).total_seconds()
            != session.budget.hard_expiry_seconds
        ):
            raise self._identity_error(session_artifact_id, "runtime-lock-session")
        if session.revision == 0:
            if (
                session.state != "active"
                or session.workload_runs_used != 0
                or session.active_seconds_used != 0
                or session.evidence_bytes_used != 0
                or session.exact_events_used != 0
            ):
                raise self._identity_error(session_artifact_id, "runtime-lock-session")
        else:
            assert session.previous_session_artifact_id is not None
            assert session.previous_session_artifact_content_sha256 is not None
            previous = self._load_runtime_lock_session_chain(
                session.previous_session_artifact_id,
                seen=seen,
            )
            immutable_fields = (
                "schema_version",
                "perflens_version",
                "session_id",
                "created_at",
                "expires_at",
                "project_identity_sha256",
                "client_connection_identity_sha256",
                "project_policy_sha256",
                "capability_id",
                "capability_content_sha256",
                "runtime_lock_config_sha256",
                "preview_id",
                "preview_content_sha256",
                "authorization_receipt_sha256",
                "target_scope",
                "allowed_adapters",
                "allowed_semantics",
                "budget",
            )
            workload_delta = session.workload_runs_used - previous.workload_runs_used
            previous_usage = (
                previous.active_seconds_used,
                previous.evidence_bytes_used,
                previous.exact_events_used,
            )
            current_usage = (
                session.active_seconds_used,
                session.evidence_bytes_used,
                session.exact_events_used,
            )
            if session.settlement_finalization_id is not None:
                usage_transition_valid = self._validate_runtime_lock_settlement_transition(
                    session,
                    previous,
                )
            else:
                usage_transition_valid = (
                    workload_delta == 1
                    and session.state == "active"
                    and current_usage[0] > previous_usage[0]
                    and current_usage[1] > previous_usage[1]
                    and current_usage[2] >= previous_usage[2]
                ) or (workload_delta == 0 and current_usage == previous_usage)
            if (
                previous.content_sha256 != session.previous_session_artifact_content_sha256
                or previous.revision + 1 != session.revision
                or previous.state != "active"
                or not usage_transition_valid
                or datetime.fromisoformat(previous.updated_at)
                > datetime.fromisoformat(session.updated_at)
                or any(
                    getattr(previous, field) != getattr(session, field)
                    for field in immutable_fields
                )
            ):
                raise self._identity_error(session_artifact_id, "runtime-lock-session")
        return session

    def load_runtime_lock_run_finalization(
        self,
        finalization_id: str,
    ) -> RuntimeLockRunFinalizationArtifact:
        finalization = self._load_runtime_lock_run_finalization_record(finalization_id)
        final_session = self.load_runtime_lock_session(finalization.final_session_artifact_id)
        if (
            final_session.content_sha256 != finalization.final_session_artifact_content_sha256
            or final_session.settlement_finalization_id != finalization.finalization_id
        ):
            raise self._identity_error(finalization_id, "runtime-lock-run-finalization")
        return finalization

    def _load_runtime_lock_run_finalization_record(
        self,
        finalization_id: str,
    ) -> RuntimeLockRunFinalizationArtifact:
        finalization = self._load(
            finalization_id,
            "runtime-lock-run-finalization",
            RuntimeLockRunFinalizationArtifact,
        )
        self._require_embedded_id(
            finalization.finalization_id,
            finalization_id,
            "runtime-lock-run-finalization",
        )
        self._verify_contract_content(
            finalization,
            finalization.content_sha256,
            finalization_id,
            "runtime-lock-run-finalization",
        )
        return finalization

    def _validate_runtime_lock_settlement_transition(
        self,
        session: RuntimeLockSessionArtifact,
        previous: RuntimeLockSessionArtifact,
    ) -> bool:
        finalization_id = session.settlement_finalization_id
        if finalization_id is None or session.schema_version != "1.1":
            return False
        finalization = self._load_runtime_lock_run_finalization_record(finalization_id)
        expected_usage = (
            previous.active_seconds_used
            - finalization.reserved_active_seconds
            + finalization.accounted_active_seconds,
            previous.evidence_bytes_used
            - finalization.reserved_evidence_bytes
            + finalization.accounted_evidence_bytes,
            previous.exact_events_used
            - finalization.reserved_exact_events
            + finalization.accounted_exact_events,
        )
        if (
            finalization.schema_version != session.schema_version
            or finalization.perflens_version != session.perflens_version
            or finalization.session_id != session.session_id
            or finalization.reserved_session_artifact_id != previous.session_artifact_id
            or finalization.reserved_session_artifact_content_sha256 != previous.content_sha256
            or finalization.reserved_session_revision != previous.revision
            or finalization.final_session_artifact_id != session.session_artifact_id
            or finalization.final_session_artifact_content_sha256 != session.content_sha256
            or finalization.final_session_revision != session.revision
            or finalization.created_at != session.updated_at
            or finalization.adapter_id not in session.allowed_adapters
            or finalization.measurement_semantics not in session.allowed_semantics
            or session.workload_runs_used != previous.workload_runs_used
            or expected_usage
            != (
                session.active_seconds_used,
                session.evidence_bytes_used,
                session.exact_events_used,
            )
        ):
            return False
        if finalization.outcome == "failed":
            return (
                session.state in {"failed", "exhausted"}
                and session.invalidation_reason == finalization.failure_reason
            )
        if session.state != "active" or session.invalidation_reason is not None:
            return False
        assert finalization.run_id is not None
        assert finalization.run_content_sha256 is not None
        run = self._load(
            finalization.run_id,
            "runtime-lock-run",
            RuntimeLockRunArtifact,
        )
        self._require_embedded_id(
            run.run_id,
            finalization.run_id,
            "runtime-lock-run",
        )
        self._verify_contract_content(
            run,
            run.content_sha256,
            run.run_id,
            "runtime-lock-run",
        )
        return (
            run.content_sha256 == finalization.run_content_sha256
            and datetime.fromisoformat(finalization.created_at)
            >= datetime.fromisoformat(run.created_at)
            and run.session_id == finalization.session_id
            and run.session_artifact_id == previous.session_artifact_id
            and run.session_artifact_content_sha256 == previous.content_sha256
            and run.session_revision == previous.revision
            and run.operation_identity_sha256 == finalization.operation_identity_sha256
            and run.adapter_id == finalization.adapter_id
            and run.measurement_semantics == finalization.measurement_semantics
            and run.duration_seconds == finalization.accounted_active_seconds
            and run.evidence_bytes == finalization.accounted_evidence_bytes
            and (run.event_count if run.measurement_semantics == "exact" else 0)
            == finalization.accounted_exact_events
        )

    def load_runtime_lock_run(self, run_id: str) -> RuntimeLockRunArtifact:
        run = self._load(run_id, "runtime-lock-run", RuntimeLockRunArtifact)
        self._require_embedded_id(run.run_id, run_id, "runtime-lock-run")
        self._verify_contract_content(
            run,
            run.content_sha256,
            run_id,
            "runtime-lock-run",
        )
        session = self.load_runtime_lock_session(run.session_artifact_id)
        preview = self.load_runtime_lock_preview(session.preview_id)
        analysis, evidence, _ = self.load_runtime_lock_analysis(run.runtime_lock_analysis_id)
        verification = self.load_runtime_lock_verification(run.runtime_lock_verification_id)
        finalization = self.load_runtime_lock_run_finalization(
            derive_runtime_lock_run_finalization_id(
                run.session_id,
                run.operation_identity_sha256,
            )
        )
        execution_bindings = {
            binding.adapter_id: binding for binding in preview.adapter_execution_bindings
        }
        execution_binding = execution_bindings.get(run.adapter_id)
        expected_execution_identity = (
            execution_binding.execution_identity_sha256 if execution_binding is not None else None
        )
        execution_binding_matches = (
            run.adapter_execution_identity_sha256 == expected_execution_identity
            and (
                execution_binding is None
                or (
                    run.measurement_semantics == execution_binding.measurement_semantics
                    and evidence.source.measurement_semantics
                    == execution_binding.measurement_semantics
                    and evidence.source.duration_threshold_ns
                    == execution_binding.duration_threshold_ns
                )
            )
        )
        verification_matches_run = (
            verification.runtime_lock_analysis_id == analysis.runtime_lock_analysis_id
            and verification.runtime_lock_analysis_content_sha256 == analysis.content_sha256
            and verification.runtime_lock_evidence_id == evidence.runtime_lock_evidence_id
            and verification.runtime_lock_evidence_content_sha256 == evidence.content_sha256
        )
        if execution_binding is not None and run.adapter_id == "java_jfr":
            source_tool = evidence.source.tool
            bound_tools = {tool.name: tool for tool in execution_binding.tools}
            bound_jfr = bound_tools.get("jfr")
            execution_binding_matches = execution_binding_matches and (
                evidence.source.schema_version == preview.schema_version
                and evidence.source.runtime == "java"
                and evidence.source.adapter_id == execution_binding.adapter_id
                and evidence.source.adapter_version == execution_binding.adapter_version
                and evidence.source.backend_id == execution_binding.backend_id
                and evidence.source.backend_version == execution_binding.runtime_version
                and evidence.source.adapter_execution_identity_sha256
                == execution_binding.execution_identity_sha256
                and evidence.source.configuration_sha256 == execution_binding.configuration_sha256
                and evidence.source.metadata_sha256 == execution_binding.metadata_sha256
                and source_tool is not None
                and bound_jfr is not None
                and source_tool.name == bound_jfr.name
                and source_tool.version == bound_jfr.version
                and source_tool.binary_sha256 == bound_jfr.binary_sha256
            )
        if execution_binding is not None and run.adapter_id == "cpython_threading":
            source_tool = evidence.source.tool
            bound_tools = {tool.name: tool for tool in execution_binding.tools}
            bound_python = bound_tools.get("python")
            execution_binding_matches = execution_binding_matches and (
                evidence.source.schema_version == preview.schema_version
                and evidence.source.runtime == "python"
                and evidence.source.adapter_id == execution_binding.adapter_id
                and evidence.source.adapter_version == execution_binding.adapter_version
                and evidence.source.backend_id == execution_binding.backend_id
                and evidence.source.backend_version == execution_binding.runtime_version
                and evidence.source.adapter_execution_identity_sha256
                == execution_binding.execution_identity_sha256
                and evidence.source.configuration_sha256 == execution_binding.configuration_sha256
                and evidence.source.metadata_sha256 == execution_binding.metadata_sha256
                and source_tool is not None
                and bound_python is not None
                and source_tool.name == bound_python.name
                and source_tool.version == bound_python.version
                and source_tool.binary_sha256 == bound_python.binary_sha256
            )
        run_started = datetime.fromisoformat(run.started_at)
        run_created = datetime.fromisoformat(run.created_at)
        try:
            expected_run_boundaries = derive_runtime_lock_run_boundaries(
                adapter_id=run.adapter_id,
                analysis_quality_status=analysis.quality_status,
                analysis_allowed_conclusions=analysis.allowed_conclusions,
                analysis_forbidden_conclusions=analysis.forbidden_conclusions,
                warnings=run.warnings,
            )
        except ValueError:
            expected_run_boundaries = None
        if (
            run.session_id != session.session_id
            or finalization.outcome != "completed"
            or finalization.run_id != run.run_id
            or finalization.run_content_sha256 != run.content_sha256
            or run.session_artifact_content_sha256 != session.content_sha256
            or run.session_revision != session.revision
            or session.state != "active"
            or run.target_scope != session.target_scope
            or (
                run.target_scope == "host_launched_workload"
                and (
                    preview.workload is None
                    or run.workload_identity_sha256 != preview.workload.workload_identity_sha256
                )
            )
            or run.adapter_id not in session.allowed_adapters
            or run.measurement_semantics not in session.allowed_semantics
            or not execution_binding_matches
            or not verification_matches_run
            or run.runtime_lock_evidence_id != evidence.runtime_lock_evidence_id
            or run.runtime_lock_evidence_content_sha256 != evidence.content_sha256
            or run.runtime_lock_analysis_content_sha256 != analysis.content_sha256
            or run.runtime_lock_verification_id != verification.runtime_lock_verification_id
            or run.runtime_lock_verification_content_sha256 != verification.content_sha256
            or run.measurement_semantics != analysis.measurement_semantics
            or run.measurement_semantics != evidence.source.measurement_semantics
            or evidence.source.source_format != _RUNTIME_LOCK_ADAPTER_SOURCE_FORMATS[run.adapter_id]
            or expected_run_boundaries
            != (
                run.quality_status,
                run.allowed_conclusions,
                run.forbidden_conclusions,
            )
            or run.event_count != len(evidence.events)
            or run.evidence_bytes != len(serialize_json(evidence))
            or run_started < datetime.fromisoformat(session.updated_at)
            or run_created > datetime.fromisoformat(session.expires_at)
            or not self._runtime_lock_target_scope_matches(run, evidence, session)
        ):
            raise self._identity_error(run_id, "runtime-lock-run")
        return run

    def load_runtime_lock_comparison(
        self,
        comparison_id: str,
    ) -> RuntimeLockComparisonArtifact:
        comparison = self._load(
            comparison_id,
            "runtime-lock-comparison",
            RuntimeLockComparisonArtifact,
        )
        self._require_embedded_id(
            comparison.comparison_id,
            comparison_id,
            "runtime-lock-comparison",
        )
        self._verify_contract_content(
            comparison,
            comparison.content_sha256,
            comparison_id,
            "runtime-lock-comparison",
        )
        baseline = self.load_runtime_lock_run(comparison.baseline_run_id)
        candidate = self.load_runtime_lock_run(comparison.candidate_run_id)
        _, baseline_evidence, _ = self.load_runtime_lock_analysis(baseline.runtime_lock_analysis_id)
        _, candidate_evidence, _ = self.load_runtime_lock_analysis(
            candidate.runtime_lock_analysis_id
        )
        expected_correctness = (
            "failed"
            if "failed" in {baseline.correctness_status, candidate.correctness_status}
            else (
                "passed"
                if baseline.correctness_status == candidate.correctness_status == "passed"
                else "unavailable"
            )
        )
        threshold_or_sampling_match = self._runtime_lock_measurement_controls(
            baseline,
            baseline_evidence,
        ) == self._runtime_lock_measurement_controls(candidate, candidate_evidence)
        if (
            baseline.content_sha256 != comparison.baseline_run_content_sha256
            or candidate.content_sha256 != comparison.candidate_run_content_sha256
            or baseline.session_id != comparison.session_id
            or candidate.session_id != comparison.session_id
            or comparison.adapter_match != (baseline.adapter_id == candidate.adapter_id)
            or comparison.semantics_match
            != (baseline.measurement_semantics == candidate.measurement_semantics)
            or comparison.workload_match
            != (baseline.workload_identity_sha256 == candidate.workload_identity_sha256)
            or comparison.threshold_or_sampling_match != threshold_or_sampling_match
            or comparison.resource_environment_match
            or comparison.baseline_quality_status != baseline.quality_status
            or comparison.candidate_quality_status != candidate.quality_status
            or comparison.correctness_status != expected_correctness
            or not comparison.deterministic_replay_passed
            or comparison.resource_transfer_status != "incomplete"
            or comparison.comparable
            or comparison.conclusion != "not_comparable"
            or comparison.improved_metrics
            or comparison.regressed_metrics
            or "verified_improvement" in comparison.allowed_conclusions
            or "verified_improvement" not in comparison.forbidden_conclusions
        ):
            raise self._identity_error(comparison_id, "runtime-lock-comparison")
        return comparison

    @staticmethod
    def _runtime_lock_target_scope_matches(
        run: RuntimeLockRunArtifact,
        evidence: RuntimeLockEvidenceArtifact,
        session: RuntimeLockSessionArtifact,
    ) -> bool:
        if run.target_scope == "controlled_import":
            expected_target = hashlib.sha256(
                "\0".join(
                    (
                        "perflens-runtime-lock-import-target-v1",
                        session.project_identity_sha256,
                        evidence.source.source_sha256,
                    )
                ).encode("utf-8")
            ).hexdigest()
            expected_workload = hashlib.sha256(
                "\0".join(
                    (
                        "perflens-runtime-lock-import-workload-v1",
                        session.project_identity_sha256,
                        evidence.source.source_sha256,
                        evidence.source.measurement_semantics,
                    )
                ).encode("utf-8")
            ).hexdigest()
            return (
                evidence.source.target_scope == "verified_import"
                and run.target_identity_sha256 == expected_target
                and run.workload_identity_sha256 == expected_workload
            )
        if evidence.source.target_scope != "bound_pid":
            return False
        container = evidence.target.container_reference
        if run.target_scope in {"managed_temporary_container", "docker_optimization"}:
            return (
                evidence.target.target_kind == "docker"
                and container is not None
                and container.target_identity_sha256 == run.target_identity_sha256
            )
        return evidence.target.target_kind == "host" and container is None

    @staticmethod
    def _runtime_lock_measurement_controls(
        run: RuntimeLockRunArtifact,
        evidence: RuntimeLockEvidenceArtifact,
    ) -> tuple[str | None, int | None, int | None, int | None, int | None]:
        source = evidence.source
        return (
            run.adapter_execution_identity_sha256,
            source.duration_threshold_ns,
            source.sampling_period,
            source.sampling_fraction,
            source.block_profile_rate_ns,
        )

    def load_container_resource_context(
        self,
        resource_context_id: str,
    ) -> ContainerResourceContextArtifact:
        context = self._load(
            resource_context_id,
            "container-resource-context",
            ContainerResourceContextArtifact,
        )
        self._require_embedded_id(
            context.resource_context_id,
            resource_context_id,
            "container-resource-context",
        )
        self._verify_docker_content(
            context,
            context.content_sha256,
            resource_context_id,
            "container-resource-context",
        )
        return context

    def load_container_module_snapshot(
        self,
        module_snapshot_id: str,
    ) -> ContainerModuleSnapshotArtifact:
        snapshot = self._load(
            module_snapshot_id,
            "container-module-snapshot",
            ContainerModuleSnapshotArtifact,
        )
        self._require_embedded_id(
            snapshot.module_snapshot_id,
            module_snapshot_id,
            "container-module-snapshot",
        )
        self._verify_docker_content(
            snapshot,
            snapshot.content_sha256,
            module_snapshot_id,
            "container-module-snapshot",
        )
        collection = self.load_collection(snapshot.source_collection_id)
        target = collection.container_target
        if (
            collection.target_runtime != "docker"
            or collection.mode != "record"
            or collection.output_format != "perf_data"
            or collection.output_sha256 != snapshot.source_output_sha256
            or target is None
            or target.target_id != snapshot.container_target_id
            or target.target_content_sha256 != snapshot.container_target_content_sha256
            or target.container_identity_sha256 != snapshot.container_identity_sha256
            or target.namespace.mount_namespace_inode != snapshot.mount_namespace_inode
        ):
            raise self._identity_error(module_snapshot_id, "container-module-snapshot")
        return snapshot

    def load_container_module_snapshot_for_collection(
        self,
        collection_id: str,
    ) -> ContainerModuleSnapshotArtifact | None:
        snapshot_id = derive_container_module_snapshot_id(collection_id)
        if not self._path(snapshot_id, "container-module-snapshot").exists():
            return None
        return self.load_container_module_snapshot(snapshot_id)

    def load_container_symbol_context(
        self,
        symbol_context_id: str,
    ) -> ContainerSymbolContextArtifact:
        context = self._load(
            symbol_context_id,
            "container-symbol-context",
            ContainerSymbolContextArtifact,
        )
        self._require_embedded_id(
            context.symbol_context_id,
            symbol_context_id,
            "container-symbol-context",
        )
        self._verify_docker_content(
            context,
            context.content_sha256,
            symbol_context_id,
            "container-symbol-context",
        )
        analysis = self.load_analysis(context.source_analysis_id)
        snapshot = self.load_container_module_snapshot(context.module_snapshot_id)
        collection = analysis.metadata.collection
        if (
            analysis.content_sha256 != context.source_analysis_content_sha256
            or collection is None
            or collection.target_runtime != "docker"
            or collection.collection_id != context.source_collection_id
            or collection.container_target_id != context.container_target_id
            or snapshot.source_collection_id != context.source_collection_id
            or snapshot.content_sha256 != context.module_snapshot_content_sha256
            or snapshot.container_target_id != context.container_target_id
            or snapshot.container_identity_sha256 != context.container_identity_sha256
        ):
            raise self._identity_error(symbol_context_id, "container-symbol-context")
        return context

    def load_container_symbol_context_for_analysis(
        self,
        analysis_id: str,
    ) -> ContainerSymbolContextArtifact | None:
        context_id = derive_container_symbol_context_id(analysis_id)
        if not self._path(context_id, "container-symbol-context").exists():
            return None
        return self.load_container_symbol_context(context_id)

    def load_container_run(self, run_id: str) -> ContainerRunArtifact:
        run = self._load(run_id, "container-run", ContainerRunArtifact)
        self._require_embedded_id(run.run_id, run_id, "container-run")
        self._verify_docker_content(
            run,
            run.content_sha256,
            run_id,
            "container-run",
        )
        if run.resource_context_id is not None:
            context = self.load_container_resource_context(run.resource_context_id)
            if (
                context.container_identity_sha256 != run.container_identity_sha256
                or context.source_collection_id not in run.collection_ids
            ):
                raise self._identity_error(run_id, "container-run")
        if run.benchmark_id is not None:
            benchmark = self.load_benchmark(run.benchmark_id)
            if contract_content_sha256(benchmark) != run.benchmark_content_sha256:
                raise self._identity_error(run_id, "container-run")
        return run

    def load_container_workload_spec(
        self,
        workload_spec_id: str,
    ) -> ContainerWorkloadSpecArtifact:
        workload = self._load(
            workload_spec_id,
            "container-workload-spec",
            ContainerWorkloadSpecArtifact,
        )
        self._require_embedded_id(
            workload.workload_spec_id,
            workload_spec_id,
            "container-workload-spec",
        )
        self._verify_docker_content(
            workload,
            workload.content_sha256,
            workload_spec_id,
            "container-workload-spec",
        )
        return workload

    def load_container_measurement(
        self,
        measurement_id: str,
    ) -> ContainerMeasurementArtifact:
        measurement = self._load(
            measurement_id,
            "container-measurement",
            ContainerMeasurementArtifact,
        )
        self._verify_container_measurement(measurement, measurement_id)
        return measurement

    def load_container_matched_comparison(
        self,
        comparison_id: str,
    ) -> ContainerMatchedComparisonArtifact:
        comparison = self._load(
            comparison_id,
            "container-matched-comparison",
            ContainerMatchedComparisonArtifact,
        )
        self._verify_container_matched_comparison(comparison, comparison_id)
        return comparison

    def load_docker_build(self, build_id: str) -> DockerBuildArtifact:
        build = self._load(build_id, "docker-build", DockerBuildArtifact)
        self._require_embedded_id(build.build_id, build_id, "docker-build")
        self._verify_docker_content(build, build.content_sha256, build_id, "docker-build")
        return build

    def load_docker_optimization_session(
        self,
        session_artifact_id: str,
    ) -> DockerOptimizationSessionArtifact:
        session = self._load(
            session_artifact_id,
            "docker-optimization-session",
            DockerOptimizationSessionArtifact,
        )
        self._require_embedded_id(
            session.session_artifact_id,
            session_artifact_id,
            "docker-optimization-session",
        )
        self._verify_docker_content(
            session,
            session.content_sha256,
            session_artifact_id,
            "docker-optimization-session",
        )
        return session

    def load_docker_optimization_iteration(
        self,
        iteration_id: str,
    ) -> DockerOptimizationIterationArtifact:
        iteration = self._load(
            iteration_id,
            "docker-optimization-iteration",
            DockerOptimizationIterationArtifact,
        )
        self._require_embedded_id(
            iteration.iteration_id,
            iteration_id,
            "docker-optimization-iteration",
        )
        self._verify_docker_content(
            iteration,
            iteration.content_sha256,
            iteration_id,
            "docker-optimization-iteration",
        )
        session = self.load_docker_optimization_session(iteration.session_artifact_id)
        baseline_build = self.load_docker_build(iteration.baseline_build_id)
        candidate_build = self.load_docker_build(iteration.candidate_build_id)
        baseline_measurement = self.load_container_measurement(iteration.baseline_measurement_id)
        candidate_measurement = self.load_container_measurement(iteration.candidate_measurement_id)
        baseline_analysis = self.load_analysis(iteration.baseline_analysis_id)
        candidate_analysis = self.load_analysis(iteration.candidate_analysis_id)
        profile_comparison = self.load_profile_comparison(iteration.profile_comparison_id)
        baseline_benchmark = self.load_benchmark(iteration.baseline_benchmark_id)
        candidate_benchmark = self.load_benchmark(iteration.candidate_benchmark_id)
        benchmark_comparison = self.load_benchmark_comparison(iteration.benchmark_comparison_id)
        source_comparison = self.load_container_matched_comparison(
            iteration.source_container_comparison_id
        )
        replayed = compare_docker_optimization_iteration(
            session=session,
            baseline_build=baseline_build,
            candidate_build=candidate_build,
            baseline_measurement=baseline_measurement,
            candidate_measurement=candidate_measurement,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            profile_comparison=profile_comparison,
            baseline_benchmark=baseline_benchmark,
            candidate_benchmark=candidate_benchmark,
            benchmark_comparison=benchmark_comparison,
            source_container_comparison=source_comparison,
            created_at=datetime.fromisoformat(iteration.created_at),
        )
        if replayed != iteration:
            raise self._identity_error(iteration_id, "docker-optimization-iteration")
        return iteration

    def load_docker_optimization_disposition(
        self,
        disposition_id: str,
    ) -> DockerOptimizationDispositionArtifact:
        disposition = self._load(
            disposition_id,
            "docker-optimization-disposition",
            DockerOptimizationDispositionArtifact,
        )
        self._require_embedded_id(
            disposition.disposition_id,
            disposition_id,
            "docker-optimization-disposition",
        )
        self._verify_docker_content(
            disposition,
            disposition.content_sha256,
            disposition_id,
            "docker-optimization-disposition",
        )
        iteration_mismatch = False
        if disposition.iteration_id is not None:
            iteration = self.load_docker_optimization_iteration(disposition.iteration_id)
            iteration_mismatch = (
                iteration.content_sha256 != disposition.iteration_content_sha256
                or iteration.conclusion != disposition.iteration_conclusion
                or iteration.session_artifact_id != disposition.source_session_artifact_id
                or iteration.session_artifact_content_sha256
                != disposition.source_session_artifact_content_sha256
                or iteration.baseline_build_id != disposition.baseline_build_id
                or iteration.candidate_build_id != disposition.candidate_build_id
            )
        else:
            iteration_mismatch = (
                disposition.iteration_content_sha256 is not None
                or disposition.iteration_conclusion != "not_evaluated"
                or disposition.evaluation_reason is None
            )
        source_session = self.load_docker_optimization_session(
            disposition.source_session_artifact_id
        )
        final_session = self.load_docker_optimization_session(disposition.final_session_artifact_id)
        baseline = self.load_docker_build(disposition.baseline_build_id)
        candidate = self.load_docker_build(disposition.candidate_build_id)
        selected = candidate if disposition.disposition == "retain_candidate" else baseline
        if (
            iteration_mismatch
            or source_session.session_id != disposition.session_id
            or source_session.state != "active"
            or source_session.content_sha256 != disposition.source_session_artifact_content_sha256
            or final_session.session_id != disposition.session_id
            or final_session.state != "revoked"
            or final_session.content_sha256 != disposition.final_session_artifact_content_sha256
            or source_session.project_identity_sha256 != final_session.project_identity_sha256
            or source_session.client_connection_identity_sha256
            != final_session.client_connection_identity_sha256
            or source_session.project_policy_sha256 != final_session.project_policy_sha256
            or source_session.preview_content_sha256 != final_session.preview_content_sha256
            or source_session.recipe_content_sha256 != final_session.recipe_content_sha256
            or source_session.authorization_receipt_sha256
            != final_session.authorization_receipt_sha256
            or source_session.baseline_build_id != baseline.build_id
            or source_session.latest_candidate_build_id != candidate.build_id
            or final_session.baseline_build_id != baseline.build_id
            or final_session.latest_candidate_build_id != candidate.build_id
            or source_session.builds_used != final_session.builds_used
            or source_session.candidate_rounds_used != final_session.candidate_rounds_used
            or source_session.workload_runs_used != final_session.workload_runs_used
            or source_session.build_seconds_used != final_session.build_seconds_used
            or source_session.workload_active_seconds_used
            != final_session.workload_active_seconds_used
            or source_session.evidence_bytes_used != final_session.evidence_bytes_used
            or source_session.temporary_image_bytes_used != final_session.temporary_image_bytes_used
            or baseline.content_sha256 != disposition.baseline_build_content_sha256
            or candidate.content_sha256 != disposition.candidate_build_content_sha256
            or selected.build_id != disposition.selected_build_id
            or selected.content_sha256 != disposition.selected_build_content_sha256
            or selected.treatment_manifest_sha256 != disposition.selected_treatment_manifest_sha256
        ):
            raise self._identity_error(
                disposition_id,
                "docker-optimization-disposition",
            )
        return disposition

    def load_trace_analysis(
        self,
        analysis_id: str,
    ) -> tuple[
        TraceAnalysisArtifact,
        TraceEvidenceArtifact,
        TraceAnalysisVerificationArtifact,
    ]:
        artifact_type, model, id_attribute = self._trace_analysis_type(analysis_id)
        analysis = self._load(analysis_id, artifact_type, model)
        self._require_embedded_id(
            getattr(analysis, id_attribute),
            analysis_id,
            artifact_type,
        )
        evidence = self.load_trace_evidence(analysis.trace_evidence_id)
        verification = verify_trace_analysis_artifact(analysis, evidence)
        require_usable_trace_analysis(verification)
        return analysis, evidence, verification

    def read_page(
        self,
        artifact_id: str,
        artifact_type: str,
        *,
        offset: int,
        limit: int,
    ) -> tuple[str, int | None, int]:
        if offset < 0 or limit < 1 or limit > 65_536:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Invalid artifact page bounds",
                details={"offset": offset, "limit": limit},
            )
        path = self._path(artifact_id, artifact_type)
        if artifact_type in {
            "analysis",
            "benchmark",
            "benchmark-comparison",
            "collection",
            "diagnosis",
            "profile-comparison",
            "project-run",
            "trace-evidence",
            "scheduler-analysis",
            "off-cpu-analysis",
            "lock-analysis",
            "runtime-adapter-capability",
            "runtime-lock-capability",
            "runtime-lock-preview",
            "runtime-lock-evidence",
            "runtime-lock-analysis",
            "runtime-lock-verification",
            "runtime-lock-diagnosis",
            "runtime-lock-session",
            "runtime-lock-run",
            "runtime-lock-run-finalization",
            "runtime-lock-comparison",
            "container-resource-context",
            "container-run",
            "container-workload-spec",
            "container-measurement",
            "container-matched-comparison",
            "container-module-snapshot",
            "container-symbol-context",
        }:
            # Validate and page the exact same immutable byte snapshot. Performing
            # a typed load followed by a second open would leave a replacement
            # window in which unverified bytes could be returned to the Agent.
            payload = self._read_file(path, maximum=self.max_artifact_bytes)
            try:
                self._validate_snapshot(artifact_id, artifact_type, payload)
            except PerfLensError:
                raise
            except ValidationError as exc:
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "artifact",
                    "Artifact was not found or is invalid",
                    details={"artifact_id": artifact_id, "artifact_type": artifact_type},
                ) from exc
            size = len(payload)
            chunk = payload[offset : offset + limit]
        else:
            chunk, size = self._read_file_page(path, offset=offset, limit=limit)
        next_offset = offset + len(chunk) if offset + len(chunk) < size else None
        try:
            text = chunk.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact page is not lossless UTF-8; regenerate it with the current PerfLens",
                details={
                    "artifact_id": artifact_id,
                    "artifact_type": artifact_type,
                    "offset": offset,
                },
            ) from exc
        return text, next_offset, size

    def _validate_snapshot(self, artifact_id: str, artifact_type: str, payload: bytes) -> None:
        if artifact_type == "analysis":
            analysis = AnalysisArtifact.model_validate_json(payload)
            self._require_embedded_id(analysis.analysis_id, artifact_id, artifact_type)
            verify_analysis_artifact(analysis, verify_source=False)
            assert_public_container_analysis(analysis)
            return
        if artifact_type == "collection":
            collection = CollectionArtifact.model_validate_json(payload)
            self._require_embedded_id(collection.collection_id, artifact_id, artifact_type)
            self.policy.input_file(collection.output_path)
            verify_collection_artifact(collection, max_output_bytes=self.max_artifact_bytes)
            return
        if artifact_type == "trace-evidence":
            evidence = TraceEvidenceArtifact.model_validate_json(payload)
            self._require_embedded_id(
                evidence.trace_evidence_id,
                artifact_id,
                artifact_type,
            )
            validate_trace_evidence_invariants(evidence)
            return
        if artifact_type == "runtime-adapter-capability":
            capability = RuntimeAdapterCapabilityArtifact.model_validate_json(payload)
            self._require_embedded_id(
                capability.capability_id,
                artifact_id,
                artifact_type,
            )
            if self.load_runtime_adapter_capability(artifact_id) != capability:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-capability":
            capability = RuntimeLockCapabilityArtifact.model_validate_json(payload)
            self._require_embedded_id(
                capability.capability_id,
                artifact_id,
                artifact_type,
            )
            if self.load_runtime_lock_capability(artifact_id) != capability:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-preview":
            preview = RuntimeLockSessionPreviewArtifact.model_validate_json(payload)
            self._require_embedded_id(preview.preview_id, artifact_id, artifact_type)
            if self.load_runtime_lock_preview(artifact_id) != preview:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-evidence":
            evidence = RuntimeLockEvidenceArtifact.model_validate_json(payload)
            self._require_embedded_id(
                evidence.runtime_lock_evidence_id,
                artifact_id,
                artifact_type,
            )
            validate_runtime_lock_evidence_invariants(evidence)
            tool = evidence.source.tool
            if tool is not None and tool.path is not None and tool.path.startswith("/"):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "runtime_lock_evidence",
                    "Legacy Runtime Lock evidence contains a private absolute tool path",
                )
            return
        if artifact_type == "runtime-lock-analysis":
            analysis = RuntimeLockAnalysisArtifact.model_validate_json(payload)
            self._require_embedded_id(
                analysis.runtime_lock_analysis_id,
                artifact_id,
                artifact_type,
            )
            evidence = self.load_runtime_lock_evidence(analysis.runtime_lock_evidence_id)
            verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
            require_usable_runtime_lock_analysis(verification)
            return
        if artifact_type == "runtime-lock-verification":
            verification = RuntimeLockAnalysisVerificationArtifact.model_validate_json(payload)
            self._require_embedded_id(
                verification.runtime_lock_verification_id,
                artifact_id,
                artifact_type,
            )
            if self.load_runtime_lock_verification(artifact_id) != verification:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-diagnosis":
            diagnosis = RuntimeLockDiagnosisBundleArtifact.model_validate_json(payload)
            self._require_embedded_id(
                diagnosis.runtime_lock_diagnosis_id,
                artifact_id,
                artifact_type,
            )
            self._verify_contract_content(
                diagnosis,
                diagnosis.content_sha256,
                artifact_id,
                artifact_type,
            )
            analysis, evidence, verification = self.load_runtime_lock_analysis(
                diagnosis.runtime_lock_analysis_id
            )
            if (
                build_runtime_lock_diagnosis_bundle(
                    analysis,
                    evidence,
                    verification,
                )
                != diagnosis
            ):
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-session":
            session = RuntimeLockSessionArtifact.model_validate_json(payload)
            self._require_embedded_id(
                session.session_artifact_id,
                artifact_id,
                artifact_type,
            )
            if self.load_runtime_lock_session(artifact_id) != session:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-run":
            run = RuntimeLockRunArtifact.model_validate_json(payload)
            self._require_embedded_id(run.run_id, artifact_id, artifact_type)
            if self.load_runtime_lock_run(artifact_id) != run:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-run-finalization":
            finalization = RuntimeLockRunFinalizationArtifact.model_validate_json(payload)
            self._require_embedded_id(
                finalization.finalization_id,
                artifact_id,
                artifact_type,
            )
            if self.load_runtime_lock_run_finalization(artifact_id) != finalization:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "runtime-lock-comparison":
            comparison = RuntimeLockComparisonArtifact.model_validate_json(payload)
            self._require_embedded_id(comparison.comparison_id, artifact_id, artifact_type)
            if self.load_runtime_lock_comparison(artifact_id) != comparison:
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type in _TRACE_ANALYSIS_TYPES:
            model, id_attribute = _TRACE_ANALYSIS_TYPES[artifact_type]
            analysis = model.model_validate_json(payload)
            self._require_embedded_id(
                getattr(analysis, id_attribute),
                artifact_id,
                artifact_type,
            )
            evidence = self.load_trace_evidence(analysis.trace_evidence_id)
            verification = verify_trace_analysis_artifact(analysis, evidence)
            require_usable_trace_analysis(verification)
            return
        if artifact_type == "container-resource-context":
            context = ContainerResourceContextArtifact.model_validate_json(payload)
            self._require_embedded_id(
                context.resource_context_id,
                artifact_id,
                artifact_type,
            )
            self._verify_docker_content(
                context,
                context.content_sha256,
                artifact_id,
                artifact_type,
            )
            return
        if artifact_type == "container-module-snapshot":
            snapshot = ContainerModuleSnapshotArtifact.model_validate_json(payload)
            self._require_embedded_id(
                snapshot.module_snapshot_id,
                artifact_id,
                artifact_type,
            )
            self._verify_docker_content(
                snapshot,
                snapshot.content_sha256,
                artifact_id,
                artifact_type,
            )
            collection = self.load_collection(snapshot.source_collection_id)
            target = collection.container_target
            if (
                collection.target_runtime != "docker"
                or collection.mode != "record"
                or collection.output_format != "perf_data"
                or collection.output_sha256 != snapshot.source_output_sha256
                or target is None
                or target.target_id != snapshot.container_target_id
                or target.target_content_sha256 != snapshot.container_target_content_sha256
                or target.container_identity_sha256 != snapshot.container_identity_sha256
                or target.namespace.mount_namespace_inode != snapshot.mount_namespace_inode
            ):
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "container-symbol-context":
            context = ContainerSymbolContextArtifact.model_validate_json(payload)
            self._require_embedded_id(context.symbol_context_id, artifact_id, artifact_type)
            self._verify_docker_content(
                context,
                context.content_sha256,
                artifact_id,
                artifact_type,
            )
            analysis = self.load_analysis(context.source_analysis_id)
            snapshot = self.load_container_module_snapshot(context.module_snapshot_id)
            collection = analysis.metadata.collection
            if (
                analysis.content_sha256 != context.source_analysis_content_sha256
                or collection is None
                or collection.target_runtime != "docker"
                or collection.collection_id != context.source_collection_id
                or collection.container_target_id != context.container_target_id
                or snapshot.source_collection_id != context.source_collection_id
                or snapshot.content_sha256 != context.module_snapshot_content_sha256
                or snapshot.container_target_id != context.container_target_id
                or snapshot.container_identity_sha256 != context.container_identity_sha256
            ):
                raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "container-run":
            run = ContainerRunArtifact.model_validate_json(payload)
            self._require_embedded_id(run.run_id, artifact_id, artifact_type)
            self._verify_docker_content(
                run,
                run.content_sha256,
                artifact_id,
                artifact_type,
            )
            if run.resource_context_id is not None:
                context = self.load_container_resource_context(run.resource_context_id)
                if (
                    context.container_identity_sha256 != run.container_identity_sha256
                    or context.source_collection_id not in run.collection_ids
                ):
                    raise self._identity_error(artifact_id, artifact_type)
            return
        if artifact_type == "container-workload-spec":
            workload = ContainerWorkloadSpecArtifact.model_validate_json(payload)
            self._require_embedded_id(workload.workload_spec_id, artifact_id, artifact_type)
            self._verify_docker_content(
                workload,
                workload.content_sha256,
                artifact_id,
                artifact_type,
            )
            return
        if artifact_type == "container-measurement":
            measurement = ContainerMeasurementArtifact.model_validate_json(payload)
            self._verify_container_measurement(measurement, artifact_id)
            return
        if artifact_type == "container-matched-comparison":
            comparison = ContainerMatchedComparisonArtifact.model_validate_json(payload)
            self._verify_container_matched_comparison(comparison, artifact_id)
            return
        if artifact_type == "diagnosis":
            diagnosis = DiagnosisBundle.model_validate_json(payload)
            expected_analysis_id = artifact_id.removeprefix("diagnosis-")
            if artifact_id != f"diagnosis-{expected_analysis_id}":
                raise self._identity_error(artifact_id, artifact_type)
            self._require_embedded_id(
                diagnosis.analysis_id,
                expected_analysis_id,
                artifact_type,
            )
            self._verify_diagnosis(diagnosis, self.load_analysis(expected_analysis_id))
            return
        if artifact_type == "benchmark":
            model = BenchmarkArtifact.model_validate_json(payload)
            embedded_id = model.benchmark_id
        elif artifact_type == "project-run":
            model = ProjectRunArtifact.model_validate_json(payload)
            embedded_id = model.project_run_id
        elif artifact_type == "profile-comparison":
            model = ProfileComparison.model_validate_json(payload)
            embedded_id = model.comparison_id
            replayed = compare_profiles(
                self.load_analysis(model.baseline_analysis_id),
                self.load_analysis(model.candidate_analysis_id),
                minimum_delta_percent=model.minimum_delta_percent,
            )
            if replayed != model:
                raise self._identity_error(artifact_id, artifact_type)
        elif artifact_type == "benchmark-comparison":
            model = BenchmarkComparison.model_validate_json(payload)
            embedded_id = model.comparison_id
            replayed = compare_benchmarks(
                self.load_benchmark(model.baseline_benchmark_id),
                self.load_benchmark(model.candidate_benchmark_id),
                minimum_practical_impact_percent=(model.minimum_practical_impact_percent),
            )
            if replayed != model:
                raise self._identity_error(artifact_id, artifact_type)
        else:
            raise self._identity_error(artifact_id, artifact_type)
        self._require_embedded_id(embedded_id, artifact_id, artifact_type)

    def _verify_docker_content(
        self,
        model: BaseModel,
        content_sha256: str,
        artifact_id: str,
        artifact_type: str,
    ) -> None:
        if content_sha256 != contract_content_sha256(
            model,
            exclude={"content_sha256"},
        ):
            raise self._identity_error(artifact_id, artifact_type)

    def _verify_contract_content(
        self,
        model: BaseModel,
        content_sha256: str,
        artifact_id: str,
        artifact_type: str,
    ) -> None:
        if content_sha256 != contract_content_sha256(
            model,
            exclude={"content_sha256"},
        ):
            raise self._identity_error(artifact_id, artifact_type)

    def _verify_container_measurement(
        self,
        measurement: ContainerMeasurementArtifact,
        measurement_id: str,
    ) -> None:
        self._require_embedded_id(
            measurement.measurement_id,
            measurement_id,
            "container-measurement",
        )
        self._verify_docker_content(
            measurement,
            measurement.content_sha256,
            measurement_id,
            "container-measurement",
        )
        collection = self.load_collection(measurement.source_collection_id)
        context = self.load_container_resource_context(measurement.resource_context_id)
        run = (
            self.load_container_run(measurement.source_run_id)
            if measurement.source_run_id is not None
            else None
        )
        workload = (
            self.load_container_workload_spec(measurement.workload_spec_id)
            if measurement.workload_spec_id is not None
            else None
        )
        if measurement.source_benchmark_id is not None:
            benchmark = self.load_benchmark(measurement.source_benchmark_id)
            if contract_content_sha256(benchmark) != measurement.source_benchmark_content_sha256:
                raise self._identity_error(measurement_id, "container-measurement")
        replayed = build_container_measurement(
            collection,
            context,
            run=run,
            workload=workload,
            created_at=datetime.fromisoformat(measurement.created_at),
        )
        if replayed != measurement:
            raise self._identity_error(measurement_id, "container-measurement")

    def _verify_container_matched_comparison(
        self,
        comparison: ContainerMatchedComparisonArtifact,
        comparison_id: str,
    ) -> None:
        self._require_embedded_id(
            comparison.comparison_id,
            comparison_id,
            "container-matched-comparison",
        )
        self._verify_docker_content(
            comparison,
            comparison.content_sha256,
            comparison_id,
            "container-matched-comparison",
        )
        baseline_measurement = self.load_container_measurement(comparison.baseline_measurement_id)
        candidate_measurement = self.load_container_measurement(comparison.candidate_measurement_id)
        baseline_analysis = self.load_analysis(comparison.baseline_analysis_id)
        candidate_analysis = self.load_analysis(comparison.candidate_analysis_id)
        profile_comparison = self.load_profile_comparison(comparison.profile_comparison_id)
        baseline_benchmark = self.load_benchmark(comparison.baseline_benchmark_id)
        candidate_benchmark = self.load_benchmark(comparison.candidate_benchmark_id)
        benchmark_comparison = self.load_benchmark_comparison(comparison.benchmark_comparison_id)
        if (
            comparison.baseline_measurement_content_sha256 != baseline_measurement.content_sha256
            or comparison.candidate_measurement_content_sha256
            != candidate_measurement.content_sha256
            or comparison.baseline_analysis_content_sha256 != baseline_analysis.content_sha256
            or comparison.candidate_analysis_content_sha256 != candidate_analysis.content_sha256
            or comparison.baseline_benchmark_content_sha256
            != contract_content_sha256(baseline_benchmark)
            or comparison.candidate_benchmark_content_sha256
            != contract_content_sha256(candidate_benchmark)
        ):
            raise self._identity_error(comparison_id, "container-matched-comparison")
        replayed = compare_container_measurements(
            baseline_measurement,
            candidate_measurement,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            profile_comparison=profile_comparison,
            baseline_benchmark=baseline_benchmark,
            candidate_benchmark=candidate_benchmark,
            benchmark_comparison=benchmark_comparison,
            created_at=datetime.fromisoformat(comparison.created_at),
        )
        if replayed != comparison:
            raise self._identity_error(comparison_id, "container-matched-comparison")

    @staticmethod
    def _trace_analysis_type(
        analysis_id: str,
    ) -> tuple[str, type[TraceAnalysisArtifact], str]:
        for artifact_type, (model, id_attribute) in _TRACE_ANALYSIS_TYPES.items():
            if analysis_id.startswith(f"{artifact_type}-"):
                return artifact_type, model, id_attribute
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "artifact",
            "Trace analysis identifier has an unsupported type prefix",
            details={"analysis_id": analysis_id},
        )

    def _verify_diagnosis(self, diagnosis: DiagnosisBundle, analysis: AnalysisArtifact) -> None:
        if (
            diagnosis.analysis_content_sha256 != analysis.content_sha256
            or diagnosis.content_sha256 != compute_diagnosis_content_sha256(diagnosis)
        ):
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "evidence_validation",
                "Diagnosis does not match its verified source Analysis",
                details={"analysis_id": analysis.analysis_id},
            )
        if diagnosis.container_symbol_context_id is not None:
            context = self.load_container_symbol_context(diagnosis.container_symbol_context_id)
            if (
                context.source_analysis_id != analysis.analysis_id
                or context.content_sha256 != diagnosis.container_symbol_context_content_sha256
                or context.quality_status != diagnosis.container_symbol_quality_status
            ):
                raise self._identity_error(
                    diagnosis.container_symbol_context_id,
                    "diagnosis",
                )

    @staticmethod
    def _require_embedded_id(embedded_id: str, requested_id: str, artifact_type: str) -> None:
        if embedded_id != requested_id:
            raise ArtifactStore._identity_error(requested_id, artifact_type)

    @staticmethod
    def _identity_error(artifact_id: str, artifact_type: str) -> PerfLensError:
        return PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "evidence_validation",
            "Stored artifact identifier does not match its Agent-visible content",
            details={"artifact_id": artifact_id, "artifact_type": artifact_type},
        )

    def uri(self, artifact_id: str, artifact_type: str) -> str:
        self._safe_component(artifact_id)
        self._safe_component(artifact_type)
        return f"perflens://artifacts/{artifact_type}/{artifact_id}"

    def _load(self, artifact_id: str, artifact_type: str, model: type[ModelT]) -> ModelT:
        path = self._path(artifact_id, artifact_type)
        try:
            payload = self._read_file(path, maximum=self.max_artifact_bytes)
            return model.model_validate_json(payload)
        except PerfLensError:
            raise
        except (OSError, ValidationError) as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact was not found or is invalid",
                details={"artifact_id": artifact_id, "artifact_type": artifact_type},
            ) from exc

    def _path(self, artifact_id: str, artifact_type: str) -> Path:
        safe_id = self._safe_component(artifact_id)
        safe_type = self._safe_component(artifact_type)
        path = self.root / f"{safe_id}.{safe_type}.json"
        if path.parent != self.root:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact path escaped its configured root",
            )
        return path

    def _inspect_root(self) -> tuple[int, int, int, int] | None:
        try:
            metadata = self.root.stat(follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError("Artifact root cannot be inspected") from exc
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError("Artifact root must be a user-owned directory")
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        )

    def _assert_root_identity(self) -> None:
        if self._root_identity is None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact root does not exist",
            )
        try:
            current = self.root.stat(follow_symlinks=False)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact root identity changed",
            ) from exc
        identity = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
        )
        if not stat.S_ISDIR(current.st_mode) or identity != self._root_identity:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact root identity changed",
            )

    def _open_file(self, path: Path) -> tuple[int, os.stat_result]:
        self._assert_root_identity()
        descriptor = -1
        try:
            preliminary = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(preliminary.st_mode):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "artifact",
                    "Artifact file identity or permissions are unsafe",
                )
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            )
            metadata = os.fstat(descriptor)
            current = path.stat(follow_symlinks=False)
        except PerfLensError:
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact was not found or cannot be opened safely",
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or _file_identity(preliminary) != _file_identity(metadata)
            or _file_identity(metadata) != _file_identity(current)
        ):
            os.close(descriptor)
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact file identity or permissions are unsafe",
            )
        if metadata.st_size > self.max_artifact_bytes:
            os.close(descriptor)
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "artifact",
                "Artifact exceeds configured size limit",
                details={
                    "actual_bytes": metadata.st_size,
                    "max_artifact_bytes": self.max_artifact_bytes,
                },
            )
        return descriptor, metadata

    def _read_file(self, path: Path, *, maximum: int) -> bytes:
        descriptor, before = self._open_file(path)
        try:
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, min(1 << 20, maximum + 1 - total)):
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        "artifact",
                        "Artifact exceeds configured size limit",
                    )
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        except PerfLensError:
            raise
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact could not be read safely",
            ) from exc
        finally:
            os.close(descriptor)
        self._assert_unchanged_file(path, before, after)
        return payload

    def _read_file_page(self, path: Path, *, offset: int, limit: int) -> tuple[bytes, int]:
        descriptor, before = self._open_file(path)
        try:
            os.lseek(descriptor, offset, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = limit
            while remaining > 0:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact page could not be read safely",
            ) from exc
        finally:
            os.close(descriptor)
        self._assert_unchanged_file(path, before, after)
        return payload, before.st_size

    @staticmethod
    def _assert_unchanged_file(
        path: Path,
        before: os.stat_result,
        after: os.stat_result,
    ) -> None:
        try:
            current = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact changed while it was being read",
            ) from exc
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != (
            _file_identity(current)
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact changed while it was being read",
            )

    @staticmethod
    def _safe_component(value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact identifier contains unsupported characters",
                details={"value": value[:128]},
            )
        return value


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
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
