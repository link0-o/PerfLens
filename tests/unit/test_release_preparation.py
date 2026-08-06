from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

from perflens import __version__


def test_release_preparation_builds_skill_archive_and_checksums(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / f"perflens-{__version__}-py3-none-any.whl"
    source = dist / f"perflens-{__version__}.tar.gz"
    sbom = dist / "sbom.cdx.json"
    main_deb = dist / f"perflens_{__version__}-1_amd64.deb"
    collector_deb = dist / f"perflens-collector_{__version__}-1_all.deb"
    wheel.write_bytes(b"wheel")
    source.write_bytes(b"source")
    sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5"}')
    main_deb.write_bytes(b"!<arch>\nmain")
    collector_deb.write_bytes(b"!<arch>\ncollector")

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(project_root / "scripts" / "prepare_release.py"),
            "--dist-dir",
            str(dist),
            "--skill-root",
            str(
                project_root
                / ".agents"
                / "skills"
                / "perflens"
            ),
            "--tag",
            f"v{__version__}",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=project_root,
    )

    archive = dist / f"perflens-skill-{__version__}.zip"
    checksums = dist / "SHA256SUMS"
    assert str(archive) in completed.stdout
    with zipfile.ZipFile(archive) as skill_zip:
        names = set(skill_zip.namelist())
    assert "perflens/SKILL.md" in names
    assert "perflens/agents/openai.yaml" in names

    recorded = {
        name: digest
        for digest, name in (
            line.split("  ", maxsplit=1)
            for line in checksums.read_text(encoding="utf-8").splitlines()
        )
    }
    assert recorded[wheel.name] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert recorded[source.name] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert recorded[archive.name] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert recorded[sbom.name] == hashlib.sha256(sbom.read_bytes()).hexdigest()
    assert recorded[main_deb.name] == hashlib.sha256(main_deb.read_bytes()).hexdigest()
    assert recorded[collector_deb.name] == hashlib.sha256(collector_deb.read_bytes()).hexdigest()
    assert set(recorded) == {
        wheel.name,
        source.name,
        main_deb.name,
        collector_deb.name,
        archive.name,
        sbom.name,
    }
    for artifact in (wheel, source, main_deb, collector_deb, archive, sbom, checksums):
        assert artifact.stat().st_mode & 0o777 == 0o644


def test_release_preparation_rejects_stale_artifacts(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / f"perflens-{__version__}-py3-none-any.whl").write_bytes(b"wheel")
    (dist / f"perflens-{__version__}.tar.gz").write_bytes(b"source")
    (dist / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX"}')
    (dist / f"perflens_{__version__}-1_amd64.deb").write_bytes(b"!<arch>\nmain")
    (dist / f"perflens-collector_{__version__}-1_all.deb").write_bytes(
        b"!<arch>\ncollector"
    )
    (dist / "perflens-old.whl").write_bytes(b"stale")

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(project_root / "scripts" / "prepare_release.py"),
            "--dist-dir",
            str(dist),
            "--skill-root",
            str(project_root / ".agents" / "skills" / "perflens"),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
    )

    assert completed.returncode != 0
    assert "unexpected release artifacts" in completed.stderr


def test_release_preparation_requires_native_debian_packages(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / f"perflens-{__version__}-py3-none-any.whl").write_bytes(b"wheel")
    (dist / f"perflens-{__version__}.tar.gz").write_bytes(b"source")
    (dist / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX"}')

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(project_root / "scripts" / "prepare_release.py"),
            "--dist-dir",
            str(dist),
            "--skill-root",
            str(project_root / ".agents" / "skills/perflens"),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
    )

    assert completed.returncode != 0
    assert "exactly one architecture-specific perflens DEB" in completed.stderr

    (dist / f"perflens_{__version__}-1_amd64.deb").write_bytes(b"not a deb")
    (dist / f"perflens-collector_{__version__}-1_all.deb").write_bytes(
        b"!<arch>\ncollector"
    )
    invalid = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        completed.args,
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    assert invalid.returncode != 0
    assert "invalid or oversized Debian package" in invalid.stderr
