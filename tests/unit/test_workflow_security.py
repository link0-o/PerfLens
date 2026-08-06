from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

_IMMUTABLE_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"{label} must be a mapping")
    return cast(dict[str, object], value)


def _sequence(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise AssertionError(f"{label} must be a sequence")
    return cast(list[object], value)


def _workflows() -> dict[str, dict[str, object]]:
    root = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    loaded: dict[str, dict[str, object]] = {}
    for path in sorted(root.glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            payload: object = yaml.safe_load(handle)
        loaded[path.name] = _mapping(payload, label=path.name)
    assert loaded
    return loaded


def _jobs(workflow: dict[str, object], *, label: str) -> dict[str, object]:
    return _mapping(workflow.get("jobs"), label=f"{label}.jobs")


def _steps(job: object, *, label: str) -> tuple[dict[str, object], ...]:
    job_mapping = _mapping(job, label=label)
    raw_steps = _sequence(job_mapping.get("steps"), label=f"{label}.steps")
    return tuple(
        _mapping(step, label=f"{label}.steps[{index}]") for index, step in enumerate(raw_steps)
    )


def test_external_actions_are_immutable_and_checkout_discards_credentials() -> None:
    for workflow_name, workflow in _workflows().items():
        for job_name, job in _jobs(workflow, label=workflow_name).items():
            for step in _steps(job, label=f"{workflow_name}.{job_name}"):
                uses = step.get("uses")
                if uses is None:
                    continue
                assert isinstance(uses, str)
                assert _IMMUTABLE_ACTION.fullmatch(uses), (
                    f"{workflow_name}.{job_name} must pin {uses!r} to a full commit SHA"
                )
                configuration = _mapping(step.get("with", {}), label=f"{uses}.with")
                if uses.startswith("actions/checkout@"):
                    assert configuration.get("persist-credentials") is False
                if uses.startswith("actions/upload-artifact@"):
                    assert configuration.get("if-no-files-found") == "error"
                    retention = configuration.get("retention-days")
                    assert isinstance(retention, int) and 1 <= retention <= 7
                if uses.startswith("actions/download-artifact@"):
                    name = configuration.get("name")
                    assert isinstance(name, str) and name


def test_workflows_default_to_read_only_repository_contents() -> None:
    for workflow_name, workflow in _workflows().items():
        permissions = _mapping(
            workflow.get("permissions"),
            label=f"{workflow_name}.permissions",
        )
        assert permissions == {"contents": "read"}


def test_release_write_token_is_isolated_from_checkout_and_project_code() -> None:
    release = _workflows()["release.yml"]
    jobs = _jobs(release, label="release.yml")
    write_jobs: list[str] = []
    for job_name, job in jobs.items():
        job_mapping = _mapping(job, label=f"release.yml.{job_name}")
        raw_permissions = job_mapping.get("permissions")
        if raw_permissions is None:
            continue
        permissions = _mapping(raw_permissions, label=f"release.yml.{job_name}.permissions")
        if permissions.get("contents") == "write":
            write_jobs.append(job_name)

    assert write_jobs == ["github-release"]
    publisher = _mapping(jobs["github-release"], label="release.yml.github-release")
    assert publisher.get("needs") == "attest-release-assets"
    assert _mapping(
        publisher.get("permissions"),
        label="release.yml.github-release.permissions",
    ) == {"contents": "write"}
    steps = _steps(publisher, label="release.yml.github-release")
    action_steps = tuple(step for step in steps if "uses" in step)
    run_steps = tuple(step for step in steps if "run" in step)
    assert len(action_steps) == 1
    assert str(action_steps[0]["uses"]).startswith("actions/download-artifact@")
    assert len(run_steps) == 1
    publisher_command = run_steps[0]["run"]
    assert isinstance(publisher_command, str)
    assert publisher_command.lstrip().startswith("gh release create ")
    assert '--repo "$GITHUB_REPOSITORY"' in publisher_command
    assert "uv " not in publisher_command
    assert "python" not in publisher_command
    assert "scripts/" not in publisher_command
    assert all(not str(step.get("uses", "")).startswith("actions/checkout@") for step in steps)


def test_release_attestation_credentials_are_isolated_from_project_code() -> None:
    release = _workflows()["release.yml"]
    jobs = _jobs(release, label="release.yml")
    credential_jobs: list[str] = []
    for job_name, job in jobs.items():
        job_mapping = _mapping(job, label=f"release.yml.{job_name}")
        permissions = _mapping(
            job_mapping.get("permissions", {}),
            label=f"release.yml.{job_name}.permissions",
        )
        if permissions.get("id-token") == "write" or permissions.get("attestations") == "write":
            credential_jobs.append(job_name)

    assert credential_jobs == ["attest-release-assets"]
    attester = _mapping(
        jobs["attest-release-assets"],
        label="release.yml.attest-release-assets",
    )
    assert attester.get("needs") == "build-release-assets"
    assert _mapping(
        attester.get("permissions"),
        label="release.yml.attest-release-assets.permissions",
    ) == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    steps = _steps(attester, label="release.yml.attest-release-assets")
    assert len(steps) == 2
    assert all("run" not in step for step in steps)
    assert str(steps[0].get("uses", "")).startswith("actions/download-artifact@")
    assert str(steps[1].get("uses", "")).startswith("actions/attest@")
    download = _mapping(steps[0].get("with"), label="attestation download.with")
    assert download == {
        "name": "perflens-release-bundle",
        "path": "release-bundle",
    }
    attestation = _mapping(steps[1].get("with"), label="attestation.with")
    assert attestation == {"subject-path": "release-bundle/dist/*"}


def test_dependabot_monitors_action_pins_python_and_rust_lockfiles() -> None:
    project_root = Path(__file__).resolve().parents[2]
    with (project_root / ".github" / "dependabot.yml").open(encoding="utf-8") as handle:
        raw_configuration: object = yaml.safe_load(handle)
    configuration = _mapping(raw_configuration, label="dependabot.yml")
    assert configuration.get("version") == 2
    raw_updates = _sequence(configuration.get("updates"), label="dependabot.yml.updates")
    updates = tuple(
        _mapping(update, label=f"dependabot.yml.updates[{index}]")
        for index, update in enumerate(raw_updates)
    )
    by_ecosystem = {
        update["package-ecosystem"]: update
        for update in updates
        if isinstance(update.get("package-ecosystem"), str)
    }
    assert set(by_ecosystem) == {"cargo", "github-actions", "uv"}
    for ecosystem, update in by_ecosystem.items():
        assert update.get("directory") == "/", ecosystem
        schedule = _mapping(update.get("schedule"), label=f"dependabot.{ecosystem}.schedule")
        assert schedule.get("interval") == "weekly"
        assert schedule.get("timezone") == "Asia/Shanghai"
        limit = update.get("open-pull-requests-limit")
        assert isinstance(limit, int) and 1 <= limit <= 10


def test_published_python_packages_are_rebuilt_and_compared() -> None:
    targets = (
        ("ci.yml", "package"),
        ("release.yml", "build-release-assets"),
    )
    workflows = _workflows()
    for workflow_name, job_name in targets:
        jobs = _jobs(workflows[workflow_name], label=workflow_name)
        steps = _steps(jobs[job_name], label=f"{workflow_name}.{job_name}")
        commands = tuple(step["run"] for step in steps if isinstance(step.get("run"), str))
        builds = tuple(
            command
            for command in commands
            if isinstance(command, str) and "uv build --no-sources" in command
        )
        assert len(builds) == 2
        assert all(
            'SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"' in command for command in builds
        )
        assert "--out-dir dist" in builds[0]
        assert "--out-dir /tmp/perflens-python-reproducible" in builds[1]
        verifier_indexes = tuple(
            index
            for index, command in enumerate(commands)
            if isinstance(command, str) and "scripts/verify_python_reproducibility.py" in command
        )
        assert len(verifier_indexes) == 1
        assert commands.index(builds[1]) < verifier_indexes[0]


def test_debian_install_smoke_uses_the_production_perf_entry() -> None:
    workflows = _workflows()
    for workflow_name in ("ci.yml", "release.yml"):
        jobs = _jobs(workflows[workflow_name], label=workflow_name)
        steps = _steps(
            jobs["debian-package"],
            label=f"{workflow_name}.debian-package",
        )
        commands = tuple(
            cast(str, step["run"]) for step in steps if isinstance(step.get("run"), str)
        )
        prerequisites = next(command for command in commands if "apt-get update" in command)
        installed_smoke = next(
            command for command in commands if "perflens-admin deploy" in command
        )
        assert "linux-perf" in prerequisites
        assert "--perf-path /usr/bin/perf" in installed_smoke
        assert "--perf-path /usr/bin/true" not in installed_smoke
