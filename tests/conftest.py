from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    discover_runtime_supervisor_policy,
)


@pytest.fixture
def fixture_root() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def runtime_supervisor_client(
    tmp_path_factory: pytest.TempPathFactory,
) -> RuntimeSupervisorClient:
    """Build and copy the unprivileged test supervisor into a one-link identity."""

    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("Rust toolchain is unavailable for Runtime Supervisor integration")
    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(  # noqa: S603 - fixed workspace package in a test fixture
        (
            cargo,
            "build",
            "--locked",
            "-p",
            "perflens-runtime-supervisor",
        ),
        cwd=project_root,
        check=True,
        capture_output=True,
        timeout=120,
    )
    built = project_root / "target/debug/perflens-runtime-supervisor"
    destination = tmp_path_factory.mktemp("runtime-supervisor") / built.name
    shutil.copyfile(built, destination)
    destination.chmod(0o755)
    discovery = discover_runtime_supervisor_policy(
        destination,
        expected_owner_uid=os.geteuid(),
    )
    assert discovery.policy is not None
    return RuntimeSupervisorClient(discovery.policy)


@pytest.fixture(autouse=True)
def isolate_host_collector_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests must not inherit a Collector deployment from the machine running pytest."""
    from perflens.distribution import onboarding

    monkeypatch.setattr(
        onboarding,
        "detect_deployed_collector_privilege_mode",
        lambda: None,
    )

    def no_deployed_feature_profile(
        *_args: object,
        **_kwargs: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        onboarding,
        "detect_deployed_collector_feature_profile",
        no_deployed_feature_profile,
    )
