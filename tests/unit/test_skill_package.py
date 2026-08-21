from __future__ import annotations

from pathlib import Path

import yaml


def test_performance_skill_has_valid_minimal_frontmatter_and_resources() -> None:
    root = Path(__file__).resolve().parents[2]
    skill_root = root / ".agents" / "skills" / "perflens"
    skill_text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
    _opening, frontmatter, body = skill_text.split("---", maxsplit=2)
    metadata = yaml.safe_load(frontmatter)

    assert metadata.keys() == {"name", "description"}
    assert metadata["name"] == "perflens"
    assert "perf.data" in metadata["description"]
    assert "Docker" in metadata["description"]
    assert "TODO" not in skill_text
    assert "Verified Improvement" in body

    expected_references = {
        "evidence-model.md",
        "on-cpu-analysis.md",
        "lock-analysis.md",
        "memory-analysis.md",
        "syscall-analysis.md",
        "benchmark-validation.md",
        "active-collection-safety.md",
        "project-workload.md",
        "docker-analysis.md",
    }
    assert {path.name for path in (skill_root / "references").glob("*.md")} == expected_references
    assert (skill_root / "assets" / "diagnosis-report-template.md").is_file()
    assert "collect_managed_docker_workload" in body
    assert "collect_docker_target" in body
    assert "build/pull images" in body


def test_skill_declares_mcp_dependency_and_explicit_invocation_prompt() -> None:
    root = Path(__file__).resolve().parents[2]
    config_path = root / ".agents" / "skills" / "perflens" / "agents" / "openai.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert "$perflens" in config["interface"]["default_prompt"]
    assert config["dependencies"]["tools"][0]["value"] == "perflens"
    assert config["dependencies"]["tools"][0]["transport"] == "stdio"
    assert config["policy"]["allow_implicit_invocation"] is True
