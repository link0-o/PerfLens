from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from perflens import __version__


def test_release_notes_explain_wheel_installation(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "release-notes.md"
    subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(project_root / "scripts/render_release_notes.py"),
            "--tag",
            f"v{__version__}",
            "--output",
            str(output),
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    rendered = output.read_text(encoding="utf-8")
    assert f"perflens-{__version__}-py3-none-any.whl" in rendered
    assert ".whl` 不要解压" in rendered
    assert f"blob/v{__version__}/INSTALL.zh-CN.md" in rendered
    assert "perflens-admin spool-status" in rendered
    assert "gh attestation verify" in rendered
    assert "--signer-workflow link0-o/PerfLens/.github/workflows/release.yml" in rendered
    assert "--deny-self-hosted-runners" in rendered
    assert "{version}" not in rendered
    assert "{tag}" not in rendered


def test_release_notes_reject_wrong_tag_and_existing_output(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    script = project_root / "scripts/render_release_notes.py"
    output = tmp_path / "release-notes.md"
    wrong = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(script), "--tag", "v9.9.9", "--output", str(output)],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert wrong.returncode != 0
    assert "release tag must equal" in wrong.stderr

    output.write_text("existing", encoding="utf-8")
    existing = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            str(script),
            "--tag",
            f"v{__version__}",
            "--output",
            str(output),
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert existing.returncode != 0
    assert "output already exists" in existing.stderr
