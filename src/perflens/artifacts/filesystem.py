"""Deterministic, bounded, atomic JSON artifact persistence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from pydantic import BaseModel

from perflens.domain.errors import ErrorCode, PerfLensError


def serialize_json(model: BaseModel) -> bytes:
    payload = model.model_dump(mode="json", exclude_none=True)
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def write_json_atomic(model: BaseModel, output: Path, *, max_output_bytes: int) -> int:
    data = serialize_json(model)
    if len(data) > max_output_bytes:
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "artifact",
            "Serialized artifact exceeds max_output_bytes",
            recoverable=True,
            details={"actual_bytes": len(data), "max_output_bytes": max_output_bytes},
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        temporary = None
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            "artifact",
            "Unable to write output artifact",
            details={"output": str(output)},
            suggested_actions=("Check output directory permissions and free space.",),
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(data)
