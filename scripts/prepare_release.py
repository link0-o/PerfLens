#!/usr/bin/env python3
"""Create the standalone Skill archive and SHA-256 manifest for a release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import tomllib
import zipfile
from pathlib import Path
from typing import cast

from perflens import __version__
from perflens.distribution.skill import SKILL_NAME

_ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
_MAX_SKILL_FILES = 64
_MAX_SKILL_BYTES = 2 << 20
_MAX_SBOM_BYTES = 64 << 20
_MAX_DEB_BYTES = 512 << 20


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
    sbom = dist_dir / "sbom.cdx.json"
    for required in (wheel, source, sbom):
        if required.is_symlink() or not required.is_file():
            parser.error(f"required distribution is missing: {required.name}")
    _validate_sbom(sbom, parser)

    main_debs = tuple(dist_dir.glob(f"perflens_{__version__}-1_*.deb"))
    collector = dist_dir / f"perflens-collector_{__version__}-1_all.deb"
    if len(main_debs) != 1:
        parser.error("release requires exactly one architecture-specific perflens DEB")
    main_deb = main_debs[0]
    for deb in (main_deb, collector):
        _validate_deb(deb, parser)
    try:
        for artifact in (wheel, source, sbom, main_deb, collector):
            artifact.chmod(0o644)
    except OSError as exc:
        parser.error(f"unable to normalize release artifact permissions: {exc}")

    archive = dist_dir / f"{SKILL_NAME}-{__version__}.zip"
    allowed_names = {
        wheel.name,
        source.name,
        sbom.name,
        main_deb.name,
        collector.name,
        archive.name,
        "SHA256SUMS",
    }
    unexpected = sorted(
        path.name
        for path in dist_dir.iterdir()
        if not path.name.startswith(".") and path.name not in allowed_names
    )
    if unexpected:
        parser.error(f"unexpected release artifacts in --dist-dir: {', '.join(unexpected)}")
    try:
        _write_skill_archive(skill_root, archive)
    except (OSError, ValueError) as exc:
        parser.error(f"unable to build Skill archive: {exc}")
    _write_checksums(dist_dir, (wheel, source, main_deb, collector, archive, sbom))
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
            file_count = 0
            total_bytes = 0
            for source in sorted(skill_root.rglob("*")):
                if source.is_symlink():
                    raise ValueError(f"Skill archives cannot contain symlinks: {source}")
                if not source.is_file():
                    continue
                file_count += 1
                if file_count > _MAX_SKILL_FILES:
                    raise ValueError("Skill archive exceeds its file-count limit")
                remaining = _MAX_SKILL_BYTES - total_bytes
                with source.open("rb") as handle:
                    data = handle.read(remaining + 1)
                if len(data) > remaining:
                    raise ValueError("Skill archive exceeds its byte limit")
                total_bytes += len(data)
                relative = source.relative_to(skill_root)
                entry = zipfile.ZipInfo(
                    filename=(Path(SKILL_NAME) / relative).as_posix(),
                    date_time=_ZIP_TIMESTAMP,
                )
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, data)
        os.replace(temporary, output)
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def _write_checksums(dist_dir: Path, artifacts: tuple[Path, ...]) -> None:
    output = dist_dir / "SHA256SUMS"
    lines = [f"{_sha256(path)}  {path.name}" for path in sorted(artifacts)]
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


def _validate_sbom(path: Path, parser: argparse.ArgumentParser) -> None:
    try:
        with path.open("rb") as handle:
            payload = handle.read(_MAX_SBOM_BYTES + 1)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"SBOM cannot be read: {exc}")
    if len(payload) > _MAX_SBOM_BYTES:
        parser.error(f"SBOM exceeds {_MAX_SBOM_BYTES} bytes")
    try:
        raw: object = json.loads(payload)
    except json.JSONDecodeError as exc:
        parser.error(f"SBOM is not valid JSON: {exc}")
    if not isinstance(raw, dict) or raw.get("bomFormat") != "CycloneDX":
        parser.error("SBOM must be a CycloneDX JSON object")


def _validate_deb(path: Path, parser: argparse.ArgumentParser) -> None:
    if path.is_symlink() or not path.is_file():
        parser.error(f"required Debian package is missing: {path.name}")
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
        size = path.stat().st_size
    except OSError as exc:
        parser.error(f"Debian package cannot be read: {exc}")
    if header != b"!<arch>\n" or size > _MAX_DEB_BYTES:
        parser.error(f"invalid or oversized Debian package: {path.name}")


if __name__ == "__main__":
    main()
