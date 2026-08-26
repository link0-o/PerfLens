from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.distribution import client_defaults
from perflens.distribution.client_defaults import (
    BUILTIN_DEFAULT_CLIENTS,
    load_client_defaults,
    normalize_client_options,
    save_client_defaults,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def test_missing_client_defaults_use_codex_and_claude_code(tmp_path: Path) -> None:
    path = tmp_path / "config" / "config.toml"

    defaults = load_client_defaults(path)

    assert defaults.clients == BUILTIN_DEFAULT_CLIENTS
    assert defaults.path == path
    assert defaults.configured is False


def test_client_defaults_round_trip_with_canonical_order_and_private_mode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config" / "config.toml"

    saved = save_client_defaults(("copilot", "codex"), config_path=path)
    loaded = load_client_defaults(path)

    assert saved.clients == ("codex", "copilot")
    assert loaded == saved
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.read_text(encoding="utf-8") == (
        'schema_version = "1.0"\n'
        'default_clients = ["codex", "copilot"]\n'
    )


@pytest.mark.parametrize(
    "content",
    (
        'schema_version = "2.0"\ndefault_clients = ["codex"]\n',
        'schema_version = "1.0"\ndefault_clients = []\n',
        'schema_version = "1.0"\ndefault_clients = ["codex", "codex"]\n',
        'schema_version = "1.0"\ndefault_clients = ["unknown"]\n',
        'schema_version = "1.0"\ndefault_clients = ["codex"]\nextra = true\n',
    ),
)
def test_client_defaults_reject_invalid_or_ambiguous_documents(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(PerfLensError) as captured:
        load_client_defaults(path)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert captured.value.stage == "client_defaults"


def test_client_defaults_reject_symlink_and_unsafe_parent(tmp_path: Path) -> None:
    target = tmp_path / "target.toml"
    target.write_text(
        'schema_version = "1.0"\ndefault_clients = ["codex"]\n',
        encoding="utf-8",
    )
    target.chmod(0o600)
    link = tmp_path / "config.toml"
    link.symlink_to(target)

    with pytest.raises(PerfLensError):
        load_client_defaults(link)

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(PerfLensError):
        save_client_defaults(("codex",), config_path=unsafe / "config.toml")


def test_client_defaults_reject_group_writable_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'schema_version = "1.0"\ndefault_clients = ["codex"]\n',
        encoding="utf-8",
    )
    path.chmod(0o620)

    with pytest.raises(PerfLensError):
        load_client_defaults(path)


def test_repeated_client_options_are_deduplicated_and_all_cannot_be_mixed() -> None:
    assert normalize_client_options(("copilot", "codex", "copilot")) == (
        "codex",
        "copilot",
    )
    assert normalize_client_options(("all",)) == BUILTIN_DEFAULT_CLIENTS

    with pytest.raises(PerfLensError):
        normalize_client_options(("all", "opencode"))


def test_client_defaults_reject_file_replaced_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'schema_version = "1.0"\ndefault_clients = ["codex"]\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    original_metadata = client_defaults._safe_config_metadata  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def replacing_metadata(candidate: Path) -> os.stat_result:
        nonlocal calls
        calls += 1
        metadata = original_metadata(candidate)
        if calls == 1:
            path.write_text(
                'schema_version = "1.0"\ndefault_clients = ["copilot"]\n',
                encoding="utf-8",
            )
            path.chmod(0o600)
        return metadata

    monkeypatch.setattr(client_defaults, "_safe_config_metadata", replacing_metadata)

    with pytest.raises(PerfLensError, match="changed while being read"):
        load_client_defaults(path)
