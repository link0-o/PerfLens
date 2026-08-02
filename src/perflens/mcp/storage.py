"""Root-confined artifact storage for MCP tools."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from perflens.artifacts.filesystem import write_json_atomic
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    BenchmarkArtifact,
    CollectionArtifact,
    DiagnosisBundle,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.security.paths import validate_new_output_file

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ModelT = TypeVar("ModelT", bound=BaseModel)


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
            self.root.mkdir(parents=True, exist_ok=True)

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
        output = self.root / f"{safe_id}.{safe_type}.json"
        write_json_atomic(model, output, max_output_bytes=self.max_artifact_bytes)
        return output

    def load_analysis(self, analysis_id: str) -> AnalysisArtifact:
        return self._load(analysis_id, "analysis", AnalysisArtifact)

    def load_diagnosis(self, analysis_id: str) -> DiagnosisBundle | None:
        try:
            return self._load(f"diagnosis-{analysis_id}", "diagnosis", DiagnosisBundle)
        except PerfLensError as exc:
            if exc.code is ErrorCode.INVALID_INPUT:
                return None
            raise

    def load_benchmark(self, benchmark_id: str) -> BenchmarkArtifact:
        return self._load(benchmark_id, "benchmark", BenchmarkArtifact)

    def load_collection(self, collection_id: str) -> CollectionArtifact:
        return self._load(collection_id, "collection", CollectionArtifact)

    def read_page(
        self,
        artifact_id: str,
        artifact_type: str,
        *,
        offset: int,
        limit: int,
    ) -> tuple[str, int | None, int]:
        path = self._path(artifact_id, artifact_type)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Artifact was not found",
                details={"artifact_id": artifact_id, "artifact_type": artifact_type},
            ) from exc
        if offset < 0 or limit < 1 or limit > 65_536:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "artifact",
                "Invalid artifact page bounds",
                details={"offset": offset, "limit": limit},
            )
        with path.open("rb") as handle:
            handle.seek(offset)
            chunk = handle.read(limit)
        next_offset = offset + len(chunk) if offset + len(chunk) < size else None
        return chunk.decode("utf-8", errors="replace"), next_offset, size

    def uri(self, artifact_id: str, artifact_type: str) -> str:
        self._safe_component(artifact_id)
        self._safe_component(artifact_type)
        return f"perflens://artifacts/{artifact_type}/{artifact_id}"

    def _load(self, artifact_id: str, artifact_type: str, model: type[ModelT]) -> ModelT:
        path = self._path(artifact_id, artifact_type)
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                payload = handle.read(self.max_artifact_bytes + 1)
            if size > self.max_artifact_bytes or len(payload) > self.max_artifact_bytes:
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "artifact",
                    "Artifact exceeds configured size limit",
                    details={
                        "actual_bytes": max(size, len(payload)),
                        "max_artifact_bytes": self.max_artifact_bytes,
                    },
                )
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
        path = (self.root / f"{safe_id}.{safe_type}.json").resolve(strict=False)
        if path.parent != self.root:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "artifact",
                "Artifact path escaped its configured root",
            )
        return path

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
