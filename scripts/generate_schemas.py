"""Generate checked-in JSON Schemas from public Pydantic contracts."""

from __future__ import annotations

import json
from pathlib import Path

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
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    CollectionPlanArtifact,
    CollectorAcceptanceArtifact,
    CollectorDeploymentArtifact,
    CollectorHealthArtifact,
    CollectorModeSwitchArtifact,
    CollectorPolicyUpdateArtifact,
    CollectorSetupArtifact,
    CollectorSpoolArchiveArtifact,
    CollectorSpoolArchiveEntry,
    CollectorSpoolArchiveManifest,
    CollectorSpoolArchiveVerificationArtifact,
    CollectorSpoolPruneArtifact,
    CollectorSpoolStatusArtifact,
    CollectorUndeploymentArtifact,
    CollectorUpgradeArtifact,
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
    ProjectDetachmentArtifact,
    ProjectRunArtifact,
    RuntimeStatusArtifact,
    SetupArtifact,
    SourceContextArtifact,
    SourceResolutionArtifact,
    StackSample,
)
from perflens.privileged_helper.protocol import helper_request_schema, helper_response_schema

MODELS = {
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
    "collector-setup.schema.json": CollectorSetupArtifact,
    "collector-mode-switch.schema.json": CollectorModeSwitchArtifact,
    "collector-acceptance.schema.json": CollectorAcceptanceArtifact,
    "collector-health.schema.json": CollectorHealthArtifact,
    "collector-policy-update.schema.json": CollectorPolicyUpdateArtifact,
    "collector-spool-status.schema.json": CollectorSpoolStatusArtifact,
    "collector-spool-archive.schema.json": CollectorSpoolArchiveArtifact,
    "collector-spool-archive-entry.schema.json": CollectorSpoolArchiveEntry,
    "collector-spool-archive-manifest.schema.json": CollectorSpoolArchiveManifest,
    "collector-spool-archive-verification.schema.json": (CollectorSpoolArchiveVerificationArtifact),
    "collector-spool-prune.schema.json": CollectorSpoolPruneArtifact,
    "collector-undeployment.schema.json": CollectorUndeploymentArtifact,
    "collector-upgrade.schema.json": CollectorUpgradeArtifact,
    "benchmark.schema.json": BenchmarkArtifact,
    "benchmark-metric.schema.json": BenchmarkMetric,
    "benchmark-environment.schema.json": BenchmarkEnvironment,
    "benchmark-comparison.schema.json": BenchmarkComparison,
    "benchmark-metric-comparison.schema.json": BenchmarkMetricComparison,
    "profile-comparison.schema.json": ProfileComparison,
    "profile-hotspot-delta.schema.json": ProfileHotspotDelta,
    "call-path-delta.schema.json": CallPathDelta,
    "collection.schema.json": CollectionArtifact,
    "collection-capability.schema.json": CollectionCapabilityArtifact,
    "collection-mode-capability.schema.json": CollectionModeCapability,
    "collection-plan.schema.json": CollectionPlanArtifact,
    "perf-stat-metric.schema.json": PerfStatMetric,
    "project-run.schema.json": ProjectRunArtifact,
    "project-detachment.schema.json": ProjectDetachmentArtifact,
    "runtime-status.schema.json": RuntimeStatusArtifact,
    "setup.schema.json": SetupArtifact,
}


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas"
    root.mkdir(exist_ok=True)
    for filename, model in MODELS.items():
        schema = model.model_json_schema()
        (root / filename).write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    (root / "privileged-helper-request.schema.json").write_text(
        json.dumps(helper_request_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "privileged-helper-response.schema.json").write_text(
        json.dumps(helper_response_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
