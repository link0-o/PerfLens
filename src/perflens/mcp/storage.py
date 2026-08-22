"""Root-confined artifact storage for MCP tools."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from perflens.application.evidence import (
    compute_diagnosis_content_sha256,
    contract_content_sha256,
    verify_collection_artifact,
)
from perflens.application.trace_evidence import validate_trace_evidence_invariants
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.application.verify_trace import (
    require_usable_trace_analysis,
    verify_trace_analysis_artifact,
)
from perflens.artifacts.filesystem import serialize_json, write_json_new_atomic
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
    ContainerModuleSnapshotArtifact,
    ContainerResourceContextArtifact,
    ContainerRunArtifact,
    ContainerSymbolContextArtifact,
    derive_container_module_snapshot_id,
    derive_container_symbol_context_id,
)
from perflens.contracts.trace import (
    LockAnalysisArtifact,
    OffCpuAnalysisArtifact,
    SchedulerAnalysisArtifact,
    TraceAnalysisVerificationArtifact,
    TraceEvidenceArtifact,
)
from perflens.docker.symbols import assert_public_container_analysis
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import validate_new_output_file

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
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
        return run

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
            "container-resource-context",
            "container-run",
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
        elif artifact_type == "benchmark-comparison":
            model = BenchmarkComparison.model_validate_json(payload)
            embedded_id = model.comparison_id
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
            context = self.load_container_symbol_context(
                diagnosis.container_symbol_context_id
            )
            if (
                context.source_analysis_id != analysis.analysis_id
                or context.content_sha256
                != diagnosis.container_symbol_context_content_sha256
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
