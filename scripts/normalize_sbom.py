#!/usr/bin/env python3
"""Normalize volatile CycloneDX metadata for reproducible release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

_MAX_SBOM_BYTES = 64 << 20
_MAX_SOURCE_DATE_EPOCH = 253_402_300_799


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    arguments = parser.parse_args()

    source = _regular_file(arguments.input, parser)
    output = _output_path(arguments.output, parser)
    if not 0 <= arguments.source_date_epoch <= _MAX_SOURCE_DATE_EPOCH:
        parser.error("--source-date-epoch is outside the supported UTC range")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        parser.error(f"SBOM cannot be read: {exc}")
    if len(raw) > _MAX_SBOM_BYTES:
        parser.error(f"SBOM exceeds {_MAX_SBOM_BYTES} bytes")
    try:
        parsed: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        parser.error(f"SBOM is not valid UTF-8 JSON: {exc}")
    if not isinstance(parsed, dict):
        parser.error("SBOM must be a CycloneDX JSON object")
    sbom = cast(dict[str, object], parsed)
    if sbom.get("bomFormat") != "CycloneDX":
        parser.error("SBOM must be a CycloneDX JSON object")
    raw_metadata = sbom.get("metadata")
    if not isinstance(raw_metadata, dict):
        parser.error("SBOM metadata must be an object")
    metadata = cast(dict[str, object], raw_metadata)

    timestamp = datetime.fromtimestamp(arguments.source_date_epoch, tz=UTC)
    metadata["timestamp"] = timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")
    sbom.pop("serialNumber", None)
    identity_payload = json.dumps(
        sbom,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    content_identity = hashlib.sha256(identity_payload).hexdigest()
    sbom["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, content_identity)}"
    normalized = (
        json.dumps(sbom, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    if len(normalized) > _MAX_SBOM_BYTES:
        parser.error(f"normalized SBOM exceeds {_MAX_SBOM_BYTES} bytes")
    _atomic_write(output, normalized, parser)
    print(output)


def _regular_file(path: Path, parser: argparse.ArgumentParser) -> Path:
    if path.is_symlink():
        parser.error("--input must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        parser.error(f"--input cannot be resolved: {exc}")
    if not resolved.is_file():
        parser.error("--input must be a regular file")
    return resolved


def _output_path(path: Path, parser: argparse.ArgumentParser) -> Path:
    if path.is_symlink():
        parser.error("--output must not be a symbolic link")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        parser.error(f"--output parent cannot be resolved: {exc}")
    if not parent.is_dir():
        parser.error("--output parent must be a directory")
    if path.exists() and not path.is_file():
        parser.error("--output must be a regular file")
    return parent / path.name


def _atomic_write(path: Path, payload: bytes, parser: argparse.ArgumentParser) -> None:
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o644)
    except OSError as exc:
        parser.error(f"normalized SBOM cannot be written: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
