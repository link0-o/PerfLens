from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    ArtifactReference,
    ArtifactTextPage,
    BenchmarkArtifact,
    BenchmarkComparison,
    BenchmarkEnvironment,
    BenchmarkMetric,
    BenchmarkMetricComparison,
    CallPath,
    CallPathDelta,
    CallPathPage,
    Classification,
    ClassificationPage,
    CollectionArtifact,
    CollectorDeploymentArtifact,
    CollectorUndeploymentArtifact,
    DiagnosisBundle,
    ElfMetadataArtifact,
    Evidence,
    Frame,
    Hotspot,
    HotspotDetails,
    HotspotPage,
    PerfStatMetric,
    ProfileComparison,
    ProfileHotspotDelta,
    ProfileMetadata,
    ProjectRunArtifact,
    RuntimeStatusArtifact,
    SetupArtifact,
    SourceContextArtifact,
    SourceResolutionArtifact,
    StackSample,
)


def test_checked_in_json_schemas_match_contract_models() -> None:
    project_root = Path(__file__).resolve().parents[2]
    schema_root = project_root / "schemas"
    models: dict[str, type[BaseModel]] = {
        "analysis.schema.json": AnalysisArtifact,
        "profile.schema.json": ProfileMetadata,
        "sample.schema.json": StackSample,
        "frame.schema.json": Frame,
        "hotspot.schema.json": Hotspot,
        "call-path.schema.json": CallPath,
        "elf-metadata.schema.json": ElfMetadataArtifact,
        "source-resolution.schema.json": SourceResolutionArtifact,
        "source-context.schema.json": SourceContextArtifact,
        "classification.schema.json": Classification,
        "diagnosis-bundle.schema.json": DiagnosisBundle,
        "evidence.schema.json": Evidence,
        "artifact-reference.schema.json": ArtifactReference,
        "artifact-text-page.schema.json": ArtifactTextPage,
        "hotspot-page.schema.json": HotspotPage,
        "hotspot-details.schema.json": HotspotDetails,
        "call-path-page.schema.json": CallPathPage,
        "classification-page.schema.json": ClassificationPage,
        "collector-deployment.schema.json": CollectorDeploymentArtifact,
        "collector-undeployment.schema.json": CollectorUndeploymentArtifact,
        "benchmark.schema.json": BenchmarkArtifact,
        "benchmark-metric.schema.json": BenchmarkMetric,
        "benchmark-environment.schema.json": BenchmarkEnvironment,
        "benchmark-comparison.schema.json": BenchmarkComparison,
        "benchmark-metric-comparison.schema.json": BenchmarkMetricComparison,
        "profile-comparison.schema.json": ProfileComparison,
        "profile-hotspot-delta.schema.json": ProfileHotspotDelta,
        "call-path-delta.schema.json": CallPathDelta,
        "collection.schema.json": CollectionArtifact,
        "perf-stat-metric.schema.json": PerfStatMetric,
        "project-run.schema.json": ProjectRunArtifact,
        "runtime-status.schema.json": RuntimeStatusArtifact,
        "setup.schema.json": SetupArtifact,
    }

    for filename, model in models.items():
        checked_in = json.loads((schema_root / filename).read_text(encoding="utf-8"))
        assert checked_in == model.model_json_schema(), filename
