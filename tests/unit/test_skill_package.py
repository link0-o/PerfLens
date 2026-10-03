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
    assert "compare_container_measurements" in body
    assert "build/pull images" in body
    assert "Do not launch `perflens-mcp` through a shell" in body
    assert "custom JSON-RPC client" in body
    assert "Do not launch, smoke-test, or" in body
    assert "one fresh explicit reply covering every listed Preview" in body
    assert "never describe the batch as one atomic" in body
    assert "collection must repeat that exact value" in " ".join(body.split())
    assert "both its `runtime_lock_analysis_id` and" in body
    assert "Do not call `analyze_runtime_lock_evidence` again" in body
    assert "runtime_lock_run_finalization_id" in body
    assert "Maintain an append-only Artifact ledger" in body
    assert "it is not an Artifact enumerator" in body
    assert "label the list partial" in body
    assert "Never infer that" in body
    assert "Evidence `quality.status` distinct from Run `quality_status`" in body
    assert "the outer `state` is the authorization state" in body
    assert "never describe that retained substatus as live authority" in body
    assert "map host UID/GID 0 to" in body
    assert "Never accept UID 65534" in body

    lock_reference = (skill_root / "references" / "lock-analysis.md").read_text(encoding="utf-8")
    normalized_lock_reference = " ".join(lock_reference.split())
    assert "may exceed the wall interval" in normalized_lock_reference
    assert "Adjacent wait-end timestamps are not acquire/release pairs" in normalized_lock_reference
    assert "event-local partial provenance" in normalized_lock_reference


def test_skill_declares_mcp_dependency_and_explicit_invocation_prompt() -> None:
    root = Path(__file__).resolve().parents[2]
    config_path = root / ".agents" / "skills" / "perflens" / "agents" / "openai.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert "$perflens" in config["interface"]["default_prompt"]
    assert config["dependencies"]["tools"][0]["value"] == "perflens"
    assert config["dependencies"]["tools"][0]["transport"] == "stdio"
    assert config["policy"]["allow_implicit_invocation"] is True
