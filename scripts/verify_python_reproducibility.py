#!/usr/bin/env python3
"""Verify that two PerfLens wheel/sdist builds are byte-for-byte identical."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from perflens import __version__

_MAX_ARTIFACT_BYTES = 512 << 20


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--reproducible-directory", type=Path, required=True)
    arguments = parser.parse_args()

    primary = _directory(arguments.directory, parser, label="--directory")
    reproduced = _directory(
        arguments.reproducible_directory,
        parser,
        label="--reproducible-directory",
    )
    if primary == reproduced:
        parser.error("build directories must be different")

    names = (
        f"perflens-{__version__}-py3-none-any.whl",
        f"perflens-{__version__}.tar.gz",
    )
    for name in names:
        first = _artifact(primary / name, parser)
        second = _artifact(reproduced / name, parser)
        try:
            first_digest = _sha256(first)
            second_digest = _sha256(second)
        except OSError as exc:
            parser.error(f"artifact cannot be read: {name}: {exc}")
        if first_digest != second_digest:
            parser.error(f"Python package is not reproducible: {name}")
        print(f"{first_digest}  {name}")


def _directory(
    path: Path,
    parser: argparse.ArgumentParser,
    *,
    label: str,
) -> Path:
    if path.is_symlink():
        parser.error(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        parser.error(f"{label} cannot be resolved: {exc}")
    if not resolved.is_dir():
        parser.error(f"{label} must be a directory")
    return resolved


def _artifact(path: Path, parser: argparse.ArgumentParser) -> Path:
    if path.is_symlink() or not path.is_file():
        parser.error(f"required regular artifact is missing: {path.name}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        parser.error(f"artifact cannot be inspected: {path.name}: {exc}")
    if size <= 0 or size > _MAX_ARTIFACT_BYTES:
        parser.error(f"artifact is empty or oversized: {path.name}")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
