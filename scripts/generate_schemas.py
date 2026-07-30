"""Generate checked-in JSON Schemas from public Pydantic contracts."""

from __future__ import annotations

import json
from pathlib import Path

from perflens.contracts.artifacts import (
    AnalysisArtifact,
    CallPath,
    Frame,
    Hotspot,
    ProfileMetadata,
    StackSample,
)

MODELS = {
    "analysis.schema.json": AnalysisArtifact,
    "profile.schema.json": ProfileMetadata,
    "sample.schema.json": StackSample,
    "frame.schema.json": Frame,
    "hotspot.schema.json": Hotspot,
    "call-path.schema.json": CallPath,
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
