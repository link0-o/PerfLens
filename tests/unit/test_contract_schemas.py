from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CallPath,
    Classification,
    DiagnosisBundle,
    ElfMetadataArtifact,
    Evidence,
    Frame,
    Hotspot,
    ProfileMetadata,
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
    }

    for filename, model in models.items():
        checked_in = json.loads((schema_root / filename).read_text(encoding="utf-8"))
        assert checked_in == model.model_json_schema(), filename
