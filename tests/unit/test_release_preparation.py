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
    wheel.write_bytes(b"wheel")
    source.write_bytes(b"source")

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
                / "perflens-performance-analysis"
            ),
            "--tag",
            f"v{__version__}",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=project_root,
    )

    archive = dist / f"perflens-performance-analysis-{__version__}.zip"
    checksums = dist / "SHA256SUMS"
    assert str(archive) in completed.stdout
    with zipfile.ZipFile(archive) as skill_zip:
        names = set(skill_zip.namelist())
    assert "perflens-performance-analysis/SKILL.md" in names
    assert "perflens-performance-analysis/agents/openai.yaml" in names

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
