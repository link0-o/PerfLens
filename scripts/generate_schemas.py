"""Generate checked-in JSON Schemas from public Pydantic contracts."""

from __future__ import annotations

import json
from pathlib import Path

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    ArtifactReference,
    ArtifactTextPage,
    CallPath,
    CallPathPage,
    Classification,
    ClassificationPage,
    DiagnosisBundle,
    ElfMetadataArtifact,
    Evidence,
    Frame,
    Hotspot,
    HotspotDetails,
    HotspotPage,
    ProfileMetadata,
    SourceContextArtifact,
    SourceResolutionArtifact,
    StackSample,
)

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


if __name__ == "__main__":
    main()
