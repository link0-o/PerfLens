from __future__ import annotations

import sys
from pathlib import Path

from perflens.distribution.detach import detach_project_integration
from perflens.distribution.onboarding import run_project_setup


def test_detach_dry_run_and_removal_preserve_project_evidence(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_dir = project / ".codex"
    config_dir.mkdir()
    config = config_dir / "config.toml"
    config.write_text('model = "keep-me"\n', encoding="utf-8")
    run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    results = project / "perflens-results"
    results.mkdir()
    before = config.read_text(encoding="utf-8")

    preview = detach_project_integration(project, dry_run=True)

    assert preview.schema_version == "1.0"
    assert preview.codex_config_status == "planned"
    assert config.read_text(encoding="utf-8") == before
    assert str(project / ".agents/skills/perflens-performance-analysis") in preview.preserved_paths
    assert str(project / "perflens-setup") in preview.preserved_paths
    assert str(results) in preview.preserved_paths

    detached = detach_project_integration(project)

    assert detached.codex_config_status == "removed"
    assert config.read_text(encoding="utf-8") == 'model = "keep-me"\n\n'
    assert (project / ".agents/skills/perflens-performance-analysis/SKILL.md").is_file()
    assert (project / "perflens-setup/setup.json").is_file()
    assert results.is_dir()
    repeated = detach_project_integration(project)
    assert repeated.codex_config_status == "not_found"
