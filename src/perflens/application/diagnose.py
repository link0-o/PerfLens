"""Application boundary for persisted analysis classification and reports."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.classification.engine import build_diagnosis_bundle
from perflens.contracts.artifacts import AnalysisArtifact, DiagnosisBundle
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.reporting.markdown import render_markdown_report
from perflens.security.paths import validate_input_file


def load_analysis(path: Path, *, max_input_bytes: int = 128 << 20) -> AnalysisArtifact:
    if max_input_bytes < 1:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "artifact",
            "max_input_bytes must be positive",
        )
    safe_path = validate_input_file(path)
    try:
        size = safe_path.stat().st_size
        with safe_path.open("rb") as handle:
            payload = handle.read(max_input_bytes + 1)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "artifact",
            "Analysis artifact cannot be read",
            details={"path": str(safe_path)},
        ) from exc
    if size > max_input_bytes or len(payload) > max_input_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "artifact",
            "Analysis artifact exceeds max_input_bytes",
            recoverable=True,
            details={"actual_bytes": max(size, len(payload)), "max_input_bytes": max_input_bytes},
        )
    try:
        analysis = AnalysisArtifact.model_validate_json(payload)
    except ValidationError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "artifact",
            "Input is not a valid PerfLens analysis artifact",
            details={"path": str(safe_path), "validation_errors": exc.error_count()},
        ) from exc
    verify_analysis_artifact(analysis, verify_source=False)
    return analysis


def classify_analysis(path: Path, *, max_input_bytes: int = 128 << 20) -> DiagnosisBundle:
    return build_diagnosis_bundle(load_analysis(path, max_input_bytes=max_input_bytes))


def report_analysis(
    path: Path,
    *,
    problem_statement: str = "Not supplied.",
    target_metric: str = "Not supplied.",
    max_input_bytes: int = 128 << 20,
) -> str:
    analysis = load_analysis(path, max_input_bytes=max_input_bytes)
    diagnosis = build_diagnosis_bundle(analysis)
    return render_markdown_report(
        analysis,
        diagnosis,
        problem_statement=problem_statement,
        target_metric=target_metric,
    )
