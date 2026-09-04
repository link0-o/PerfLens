"""Identity-pinned JFR configurations shipped with PerfLens."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from defusedxml import ElementTree as ET

from perflens.domain.errors import ErrorCode, PerfLensError

JavaJfrProfileId = Literal["balanced", "deep"]
JFR_EVENT_SURFACE = (
    "jdk.DataLoss",
    "jdk.JVMInformation",
    "jdk.JavaMonitorEnter",
    "jdk.JavaMonitorWait",
    "jdk.ThreadPark",
)
DEFAULT_JAVA_JFR_PROFILE_ROOT = Path(__file__).resolve().with_name("jfr")
_THRESHOLD_NS = {"balanced": 10_000_000, "deep": 1_000_000}
_MAX_PROFILE_BYTES = 64 << 10


@dataclass(frozen=True, slots=True)
class JavaJfrProfileIdentity:
    jdk_major: int
    profile_id: JavaJfrProfileId
    path: Path
    sha256: str
    threshold_ns: int
    measurement_semantics: Literal["thresholded"]
    event_surface: tuple[str, ...]
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int


def load_java_jfr_profiles(
    profile_root: Path = DEFAULT_JAVA_JFR_PROFILE_ROOT,
    *,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> tuple[JavaJfrProfileIdentity, ...]:
    """Load and strictly validate the six packaged, non-writable JFC files."""

    if not profile_root.is_absolute() or profile_root.is_symlink():
        raise _profile_error("JFR profile root must be absolute and non-symlinked")
    profiles = tuple(
        _load_profile(
            profile_root / f"jdk{major}-{profile_id}.jfc",
            major=major,
            profile_id=profile_id,
            trusted_owner_uids=trusted_owner_uids,
        )
        for major in (17, 21, 25)
        for profile_id in ("balanced", "deep")
    )
    return profiles


def _load_profile(
    path: Path,
    *,
    major: int,
    profile_id: JavaJfrProfileId,
    trusted_owner_uids: tuple[int, ...],
) -> JavaJfrProfileIdentity:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _profile_error("Packaged JFR profile cannot be opened safely") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted_owner_uids
            or mode & 0o022
            or before.st_size <= 0
            or before.st_size > _MAX_PROFILE_BYTES
        ):
            raise _profile_error("Packaged JFR profile identity is unsafe")
        raw = os.read(fd, _MAX_PROFILE_BYTES + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if len(raw) != before.st_size or _identity_tuple(before) != _identity_tuple(after):
        raise _profile_error("Packaged JFR profile changed while it was read")
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise _profile_error("Packaged JFR profile contains forbidden XML declarations")
    _validate_profile_xml(raw, profile_id=profile_id)
    return JavaJfrProfileIdentity(
        jdk_major=major,
        profile_id=profile_id,
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        threshold_ns=_THRESHOLD_NS[profile_id],
        measurement_semantics="thresholded",
        event_surface=JFR_EVENT_SURFACE,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        mode=mode,
        size=before.st_size,
    )


def _validate_profile_xml(raw: bytes, *, profile_id: JavaJfrProfileId) -> None:
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, UnicodeDecodeError) as exc:
        raise _profile_error("Packaged JFR profile is not valid bounded XML") from exc
    if root.tag != "configuration" or set(root.attrib) - {
        "version",
        "label",
        "description",
        "provider",
    }:
        raise _profile_error("Packaged JFR profile has an unsupported root")
    events: dict[str, dict[str, str]] = {}
    for child in root:
        if child.tag != "event" or set(child.attrib) != {"name"}:
            raise _profile_error("Packaged JFR profile contains an unsupported element")
        name = child.attrib["name"]
        if name in events:
            raise _profile_error("Packaged JFR profile contains a duplicate event")
        settings: dict[str, str] = {}
        for setting in child:
            if setting.tag != "setting" or set(setting.attrib) != {"name"}:
                raise _profile_error("Packaged JFR profile contains an unsupported setting")
            key = setting.attrib["name"]
            if key in settings or list(setting):
                raise _profile_error("Packaged JFR profile contains a duplicate setting")
            settings[key] = (setting.text or "").strip()
        events[name] = settings
    if tuple(sorted(events)) != JFR_EVENT_SURFACE:
        raise _profile_error("Packaged JFR profile event surface is not fixed")
    threshold = "10 ms" if profile_id == "balanced" else "1 ms"
    for name in JFR_EVENT_SURFACE:
        expected = {"enabled": "true"}
        if name not in {"jdk.DataLoss", "jdk.JVMInformation"}:
            expected.update({"stackTrace": "true", "threshold": threshold})
        if events[name] != expected:
            raise _profile_error("Packaged JFR profile settings are not fixed")


def _identity_tuple(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _profile_error(message: str) -> PerfLensError:
    return PerfLensError(
        code=ErrorCode.PATH_SAFETY_VIOLATION,
        stage="java_jfr_profile",
        message=message,
    )
