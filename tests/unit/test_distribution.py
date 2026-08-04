from __future__ import annotations

import sys
from pathlib import Path

import pytest

from perflens.distribution.codex import render_codex_config
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.skill import SKILL_NAME, install_project_skill
from perflens.domain.errors import ErrorCode, PerfLensError


def test_project_skill_install_copies_the_complete_skill_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()

    installed = install_project_skill(project)

    assert installed == project / ".agents" / "skills" / SKILL_NAME
    assert (installed / "SKILL.md").is_file()
    assert (installed / "agents" / "openai.yaml").is_file()
    assert (installed / "assets" / "diagnosis-report-template.md").is_file()
    assert len(tuple((installed / "references").glob("*.md"))) == 8

    skill_text = (installed / "SKILL.md").read_text(encoding="utf-8")
    with pytest.raises(PerfLensError) as captured:
        install_project_skill(project)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert (installed / "SKILL.md").read_text(encoding="utf-8") == skill_text


def test_project_skill_install_rejects_parent_symlink_escape(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / ".agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PerfLensError) as captured:
        install_project_skill(project)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert not (outside / "skills").exists()


def test_collector_assets_are_staged_without_overwrite(tmp_path: Path) -> None:
    target = install_collector_assets(
        tmp_path / "collector-assets",
        allowed_uids=(1000, 1000),
        collector_command=Path("/opt/perflens/bin/perflens-collector"),
        perf_path=Path("/usr/lib/linux-tools/perf"),
    )
    assert {path.name for path in target.iterdir()} == {
        "collector.toml",
        "perflens-collector.service",
        "perflens.sysusers",
    }
    policy = (target / "collector.toml").read_text(encoding="utf-8")
    service = (target / "perflens-collector.service").read_text(encoding="utf-8")
    assert "allowed_uids = [1000]" in policy
    assert "policy_version = 1" in policy
    assert 'perf_path = "/usr/lib/linux-tools/perf"' in policy
    assert "允许连接 Collector 的唯一普通用户 UID" in policy
    assert "The only ordinary-user UID allowed to call this Collector" in policy
    assert "强烈建议保持 false" in policy
    assert "Security-sensitive; keep false" in policy
    assert "max_spool_bytes = 10737418240" in policy
    assert "PerfLens never deletes old evidence automatically" in policy
    assert "exactly one UID is supported" in policy
    assert "ExecStart=/opt/perflens/bin/perflens-collector " in service
    with pytest.raises(PerfLensError) as captured:
        install_collector_assets(target)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_collector_asset_rendering_rejects_unsafe_deployment_values(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError):
        install_collector_assets(tmp_path / "empty", allowed_uids=())
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "multiple-users",
            allowed_uids=(1000, 1001),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "relative",
            collector_command=Path("relative/perflens-collector"),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "space",
            collector_command=Path("/opt/Perf Lens/perflens-collector"),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(tmp_path / "perf", perf_path=Path("perf"))


def test_codex_config_uses_canonical_paths_and_optional_process_gate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = Path(sys.executable).resolve()

    config = render_codex_config(
        workspace,
        allow_process_execution=True,
        mcp_command=executable,
    )

    assert f'command = "{executable}"' in config
    assert f'  "{workspace.resolve()}"' in config
    assert f'  "{workspace.resolve() / "perflens-results"}"' in config
    assert '"--allow-writes"' in config
    assert '"--allow-process-execution"' in config
    assert "--allow-active-collection" not in config


def test_codex_config_rejects_artifact_root_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()

    with pytest.raises(PerfLensError) as captured:
        render_codex_config(
            workspace,
            artifact_root=outside,
            mcp_command=Path(sys.executable),
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_codex_config_generates_complete_project_collection_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    config = render_codex_config(
        workspace,
        automatic_collection=True,
        allow_project_execution=True,
        automatic_modes=("stat", "record", "stat"),
        automatic_max_duration_seconds=12,
        mcp_command=Path(sys.executable),
    )

    assert '  "/var/lib/perflens"' in config
    assert '  "--collector-socket"' in config
    assert '  "/run/perflens/collector.sock"' in config
    assert '  "--allow-automatic-collection"' in config
    assert '  "--allow-project-execution"' in config
    assert config.count('  "--automatic-mode"') == 2
    assert '  "12"' in config

    with pytest.raises(PerfLensError):
        render_codex_config(
            workspace,
            allow_project_execution=True,
            mcp_command=Path(sys.executable),
        )
