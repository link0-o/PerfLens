"""Strict per-user defaults for project AI-client activation."""

from __future__ import annotations

import os
import pwd
import stat
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens.artifacts.filesystem import write_text_atomic
from perflens.domain.errors import ErrorCode, PerfLensError

ClientName = Literal["codex", "claude-code", "opencode", "copilot"]
SUPPORTED_CLIENTS: tuple[ClientName, ...] = (
    "codex",
    "claude-code",
    "opencode",
    "copilot",
)
BUILTIN_DEFAULT_CLIENTS: tuple[ClientName, ...] = ("codex", "claude-code")
_CONFIG_SCHEMA_VERSION = "1.0"
_MAX_CONFIG_BYTES = 16 << 10


@dataclass(frozen=True, slots=True)
class ClientDefaults:
    """Resolved client defaults and their provenance."""

    clients: tuple[ClientName, ...]
    path: Path
    configured: bool


def default_client_config_path() -> Path:
    """Return the current account's config path without trusting HOME/XDG variables."""
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as exc:
        raise _config_error("Current account home directory cannot be resolved safely") from exc
    return home / ".config" / "perflens" / "config.toml"


def load_client_defaults(config_path: Path | None = None) -> ClientDefaults:
    """Load one bounded, strict TOML file or return the built-in defaults."""
    path = _resolved_config_path(config_path, for_write=False)
    if not path.exists() and not path.is_symlink():
        return ClientDefaults(
            clients=BUILTIN_DEFAULT_CLIENTS,
            path=path,
            configured=False,
        )
    before = _safe_config_metadata(path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ValueError("client defaults exceed their size limit")
        payload = cast(dict[str, object], tomllib.loads(raw.decode("utf-8")))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        raise _config_error(
            "Client defaults must be bounded valid UTF-8 TOML",
            path=path,
        ) from exc
    after = _safe_config_metadata(path)
    if _metadata_identity(before) != _metadata_identity(after):
        raise _config_error("Client defaults changed while being read", path=path)
    clients = _validate_payload(payload, path=path)
    return ClientDefaults(clients=clients, path=path, configured=True)


def save_client_defaults(
    clients: tuple[str, ...],
    *,
    config_path: Path | None = None,
) -> ClientDefaults:
    """Atomically save a normalized non-empty default client selection."""
    selected = normalize_client_selection(clients)
    path = _resolved_config_path(config_path, for_write=True)
    _ensure_private_config_parent(path.parent)
    if path.exists() or path.is_symlink():
        _safe_config_metadata(path)
    rendered_clients = ", ".join(f'"{client}"' for client in selected)
    content = (
        f'schema_version = "{_CONFIG_SCHEMA_VERSION}"\n'
        f"default_clients = [{rendered_clients}]\n"
    )
    write_text_atomic(content, path, max_output_bytes=_MAX_CONFIG_BYTES)
    os.chmod(path, 0o600, follow_symlinks=False)
    metadata = _safe_config_metadata(path)
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise _config_error("Client defaults permissions could not be restricted", path=path)
    return ClientDefaults(clients=selected, path=path, configured=True)


def normalize_client_options(values: tuple[str, ...]) -> tuple[ClientName, ...]:
    """Normalize repeated CLI options while preserving legacy ``--client all`` semantics."""
    if not values:
        raise _config_error("At least one client must be selected")
    if "all" in values:
        if len(values) != 1:
            raise _config_error("--client all cannot be combined with another --client value")
        return BUILTIN_DEFAULT_CLIENTS
    return normalize_client_selection(values)


def normalize_client_selection(values: tuple[str, ...]) -> tuple[ClientName, ...]:
    """Validate, deduplicate and canonically order a client selection."""
    if not values:
        raise _config_error("At least one client must be selected")
    unsupported = sorted(set(values) - set(SUPPORTED_CLIENTS))
    if unsupported:
        raise _config_error(
            "Client defaults contain unsupported clients",
            details={"unsupported_clients": unsupported},
        )
    selected = tuple(client for client in SUPPORTED_CLIENTS if client in values)
    return cast(tuple[ClientName, ...], selected)


def _validate_payload(payload: dict[str, object], *, path: Path) -> tuple[ClientName, ...]:
    expected = {"schema_version", "default_clients"}
    unknown = sorted(set(payload) - expected)
    missing = sorted(expected - set(payload))
    if unknown or missing:
        raise _config_error(
            "Client defaults have unknown or missing fields",
            path=path,
            details={"unknown_fields": unknown, "missing_fields": missing},
        )
    if payload["schema_version"] != _CONFIG_SCHEMA_VERSION:
        raise _config_error(
            "Client defaults schema_version is unsupported",
            path=path,
            details={"schema_version": payload["schema_version"]},
        )
    raw_clients = payload["default_clients"]
    if not isinstance(raw_clients, list):
        raise _config_error("default_clients must be a non-empty string array", path=path)
    raw_client_values = cast(list[object], raw_clients)
    if any(not isinstance(client, str) for client in raw_client_values):
        raise _config_error("default_clients must be a non-empty string array", path=path)
    typed_clients = tuple(cast(str, client) for client in raw_client_values)
    if len(typed_clients) != len(set(typed_clients)):
        raise _config_error("default_clients must not contain duplicates", path=path)
    return normalize_client_selection(typed_clients)


def _resolved_config_path(config_path: Path | None, *, for_write: bool) -> Path:
    candidate = config_path or default_client_config_path()
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.name in {"", ".", ".."}:
        raise _config_error("Client defaults path must name a file", path=candidate)
    try:
        if candidate.exists() or candidate.is_symlink():
            if candidate.is_symlink():
                raise _config_error("Client defaults must not be a symbolic link", path=candidate)
            return candidate.resolve(strict=True)
        parent = candidate.parent.resolve(strict=False)
    except OSError as exc:
        raise _config_error(
            "Client defaults path cannot be resolved safely",
            path=candidate,
        ) from exc
    return parent / candidate.name


def _ensure_private_config_parent(parent: Path) -> None:
    missing: list[Path] = []
    candidate = parent
    while not candidate.exists():
        missing.append(candidate)
        if candidate == candidate.parent:
            break
        candidate = candidate.parent
    try:
        ancestor = candidate.resolve(strict=True)
        ancestor_metadata = ancestor.stat()
    except OSError as exc:
        raise _config_error(
            "Client defaults parent cannot be resolved safely",
            path=parent,
        ) from exc
    if not stat.S_ISDIR(ancestor_metadata.st_mode):
        raise _config_error("Client defaults parent ancestor is not a directory", path=ancestor)
    for directory in reversed(missing):
        with suppress(FileExistsError):
            directory.mkdir(mode=0o700)
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise _config_error("Client defaults parent is unavailable", path=parent) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise _config_error(
            "Client defaults parent must be owned by the current user and not group/world writable",
            path=parent,
        )


def _safe_config_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _config_error("Client defaults cannot be inspected safely", path=path) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
        or metadata.st_size > _MAX_CONFIG_BYTES
    ):
        raise _config_error(
            "Client defaults must be a bounded, current-user-owned, non-writable regular file",
            path=path,
        )
    return metadata


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
    )


def _config_error(
    message: str,
    *,
    path: Path | None = None,
    details: dict[str, object] | None = None,
) -> PerfLensError:
    error_details = dict(details or {})
    if path is not None:
        error_details["path"] = str(path)
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "client_defaults",
        message,
        recoverable=True,
        details=error_details,
        suggested_actions=(
            "Review the client defaults file or choose clients explicitly with --client.",
        ),
    )
