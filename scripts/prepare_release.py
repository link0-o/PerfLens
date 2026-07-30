#!/usr/bin/env python3
"""Create the standalone Skill archive and SHA-256 manifest for a release."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import tomllib
import zipfile
from pathlib import Path
from typing import cast

from perflens import __version__
from perflens.distribution.skill import SKILL_NAME

_ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument(
        "--skill-root",
        type=Path,
        default=Path(".agents/skills") / SKILL_NAME,
    )
    parser.add_argument("--tag", help="Optional release tag, which must equal v<version>.")
    arguments = parser.parse_args()

    project_version = _project_version(Path("pyproject.toml"))
    if project_version != __version__:
        parser.error(
            "pyproject.toml version "
            f"{project_version!r} does not match runtime version {__version__!r}"
        )
    if arguments.tag is not None and arguments.tag != f"v{__version__}":
        parser.error(
            f"release tag {arguments.tag!r} does not match package version v{__version__}"
        )

    try:
        dist_dir = arguments.dist_dir.resolve(strict=True)
        skill_root = arguments.skill_root.resolve(strict=True)
    except OSError as exc:
        parser.error(f"release input cannot be resolved: {exc}")
    if not dist_dir.is_dir():
        parser.error("--dist-dir must be a directory")
    if not skill_root.is_dir() or not (skill_root / "SKILL.md").is_file():
        parser.error("--skill-root must contain SKILL.md")

    wheel = dist_dir / f"perflens-{__version__}-py3-none-any.whl"
    source = dist_dir / f"perflens-{__version__}.tar.gz"
    for required in (wheel, source):
        if not required.is_file():
            parser.error(f"required distribution is missing: {required.name}")

    archive = dist_dir / f"{SKILL_NAME}-{__version__}.zip"
    _write_skill_archive(skill_root, archive)
    _write_checksums(dist_dir)
    print(archive)
    print(dist_dir / "SHA256SUMS")


def _write_skill_archive(skill_root: Path, output: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for source in sorted(skill_root.rglob("*")):
                if source.is_symlink():
                    raise ValueError(f"Skill archives cannot contain symlinks: {source}")
                if not source.is_file():
                    continue
                relative = source.relative_to(skill_root)
                entry = zipfile.ZipInfo(
                    filename=(Path(SKILL_NAME) / relative).as_posix(),
                    date_time=_ZIP_TIMESTAMP,
                )
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, source.read_bytes())
        os.replace(temporary, output)
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def _write_checksums(dist_dir: Path) -> None:
    output = dist_dir / "SHA256SUMS"
    artifacts = sorted(
        path
        for path in dist_dir.iterdir()
        if path.is_file() and path.name != output.name and not path.name.startswith(".")
    )
    lines = [f"{_sha256(path)}  {path.name}" for path in artifacts]
    payload = ("\n".join(lines) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=dist_dir,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_version(pyproject_path: Path) -> str:
    with pyproject_path.open("rb") as handle:
        payload = cast(dict[str, object], tomllib.load(handle))
    project = payload.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml must define project.version")
    version = cast(dict[str, object], project).get("version")
    if not isinstance(version, str):
        raise ValueError("pyproject.toml must define project.version")
    return version


if __name__ == "__main__":
    main()
