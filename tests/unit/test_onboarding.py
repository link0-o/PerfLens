from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from perflens.distribution.onboarding import run_project_setup
from perflens.domain.errors import ErrorCode, PerfLensError


def test_setup_creates_guided_bundle_and_installs_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    artifact = run_project_setup(
        project,
        output_directory=Path("setup-one"),
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    output = project / "setup-one"
    assert artifact.schema_version == "1.0"
    assert artifact.skill_status == "installed"
    assert artifact.collection_status in {"available", "conditional", "blocked"}
    assert (project / ".agents/skills/perflens-performance-analysis/SKILL.md").is_file()
    assert (output / "codex-mcp.toml").is_file()
    assert (output / "collection-capabilities.json").is_file()
    assert (output / "下一步.zh-CN.md").is_file()
    payload = json.loads((output / "setup.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["project_root"] == str(project.resolve())
    assert all(Path(path).exists() for path in payload["generated_files"])

    repeated = run_project_setup(
        project,
        output_directory=Path("setup-two"),
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
        prepare_collector=True,
        automatic_collection=True,
        collector_uid=os.geteuid(),
    )
    assert repeated.skill_status == "existing"
    assert repeated.automatic_collection_enabled is True
    assert repeated.collector_assets_path is not None
    policy = Path(repeated.collector_assets_path) / "collector.toml"
    assert f"allowed_uids = [{os.geteuid()}]" in policy.read_text(encoding="utf-8")
    mcp_config = (project / "setup-two/codex-mcp.toml").read_text(encoding="utf-8")
    assert '"--allow-project-execution"' in mcp_config
    guide = (project / "setup-two/下一步.zh-CN.md").read_text(encoding="utf-8")
    assert "用户不需要查找或输入 PID" in guide


def test_setup_refuses_overwrite_escape_and_unsafe_existing_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / "occupied").mkdir()

    with pytest.raises(PerfLensError) as occupied:
        run_project_setup(
            project,
            output_directory=Path("occupied"),
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert occupied.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as escaped:
        run_project_setup(
            project,
            output_directory=outside / "setup",
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    skill_parent = project / ".agents" / "skills"
    skill_parent.mkdir(parents=True)
    (skill_parent / "perflens-performance-analysis").symlink_to(
        outside,
        target_is_directory=True,
    )
    with pytest.raises(PerfLensError) as unsafe_skill:
        run_project_setup(
            project,
            output_directory=Path("safe-output"),
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert unsafe_skill.value.code is ErrorCode.PATH_SAFETY_VIOLATION
