from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixture_root() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolate_host_collector_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests must not inherit a Collector deployment from the machine running pytest."""
    from perflens.distribution import onboarding

    monkeypatch.setattr(
        onboarding,
        "detect_deployed_collector_privilege_mode",
        lambda: None,
    )
