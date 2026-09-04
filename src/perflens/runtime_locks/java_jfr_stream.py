"""Incremental, bounded reader for the whole-object JFR JSON projection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from typing import Any, BinaryIO, cast

from pydantic import ValidationError

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.java_jfr_models import (
    JfrDataLossEvent,
    JfrJvmInformationEvent,
    JfrLockEvent,
    JfrPrivateEvent,
    JfrStreamIdentity,
)

MAX_JFR_JSON_BYTES = 67_108_864
MAX_JFR_EVENT_BYTES = 1_048_576
MAX_JFR_EVENTS = 20_000
MAX_JSON_DEPTH = 192
_SUFFIX = b"}}"
_PREFIX_PATTERN = re.compile(rb'^\s*\{\s*"recording"\s*:\s*\{\s*"events"\s*:\s*\[\s*$')


def _invalid(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PROFILE_PARSE_FAILED, "java_jfr_conversion", message)


def _limit(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "java_jfr_conversion", message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


class JfrJsonEventStream:
    """Yield one validated JFR event at a time without retaining the document."""

    def __init__(self, source: BinaryIO) -> None:
        self._source = source
        self.identity: JfrStreamIdentity | None = None

    def __iter__(self) -> Iterator[JfrPrivateEvent]:
        digest = hashlib.sha256()
        total = 0
        prefix = bytearray()
        event = bytearray()
        suffix = bytearray()
        in_string = False
        escaped = False
        depth = 0
        count = 0
        phase = "prefix"
        expect_event = True
        while True:
            chunk = self._source.read(65_536)
            if chunk == b"":
                break
            total += len(chunk)
            if total > MAX_JFR_JSON_BYTES:
                raise _limit("JFR JSON exceeds 64 MiB")
            digest.update(chunk)
            for byte in chunk:
                if phase == "prefix":
                    prefix.append(byte)
                    if len(prefix) > 256:
                        raise _invalid("JFR JSON top-level prefix is too long")
                    if byte == ord("["):
                        if _PREFIX_PATTERN.fullmatch(prefix) is None:
                            raise _invalid("JFR JSON has an unexpected top-level shape")
                        phase = "between"
                elif phase == "between":
                    if byte in b" \t\r\n":
                        continue
                    if byte == ord(","):
                        if expect_event or count == 0:
                            raise _invalid("JFR events array has an invalid separator")
                        expect_event = True
                        continue
                    if byte == ord("]"):
                        if expect_event and count != 0:
                            raise _invalid("JFR events array has a trailing separator")
                        phase = "suffix"
                        continue
                    if byte != ord("{") or not expect_event:
                        raise _invalid("JFR events array contains a non-object")
                    event = bytearray(b"{")
                    depth = 1
                    in_string = False
                    escaped = False
                    phase = "event"
                elif phase == "event":
                    event.append(byte)
                    if len(event) > MAX_JFR_EVENT_BYTES:
                        raise _limit("One JFR event exceeds 1 MiB")
                    if in_string:
                        if escaped:
                            escaped = False
                        elif byte == ord("\\"):
                            escaped = True
                        elif byte == ord('"'):
                            in_string = False
                    elif byte == ord('"'):
                        in_string = True
                    elif byte in (ord("{"), ord("[")):
                        depth += 1
                        if depth > MAX_JSON_DEPTH:
                            raise _limit("JFR JSON nesting is too deep")
                    elif byte in (ord("}"), ord("]")):
                        depth -= 1
                        if depth == 0:
                            count += 1
                            if count > MAX_JFR_EVENTS:
                                raise _limit("JFR event count exceeds the fixed limit")
                            yield _decode_event(bytes(event))
                            expect_event = False
                            phase = "between"
                else:
                    if byte not in b" \t\r\n":
                        suffix.append(byte)
                        if len(suffix) > len(_SUFFIX) or not _SUFFIX.startswith(suffix):
                            raise _invalid("JFR JSON has trailing or unknown top-level fields")
        if phase != "suffix" or bytes(suffix) != _SUFFIX:
            raise _invalid("JFR JSON is truncated")
        self.identity = JfrStreamIdentity(
            source_sha256=digest.hexdigest(), source_bytes=total, event_count=count
        )


def _decode_event(raw: bytes) -> JfrPrivateEvent:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        _validate_tree(value)
        if not isinstance(value, dict):
            raise ValueError("event is not an object")
        typed = cast(dict[str, Any], value)
        if typed.get("type") == "jdk.DataLoss":
            return JfrDataLossEvent.model_validate(typed)
        if typed.get("type") == "jdk.JVMInformation":
            return JfrJvmInformationEvent.model_validate(typed)
        return JfrLockEvent.model_validate(typed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError):
        raise _invalid("JFR event failed strict validation") from None


_KNOWN_NESTED_KEYS = frozenset(
    {
        "address",
        "amount",
        "bytecodeIndex",
        "classLoader",
        "descriptor",
        "duration",
        "eventThread",
        "exported",
        "frames",
        "group",
        "hidden",
        "javaName",
        "javaArguments",
        "javaThreadId",
        "jvmArguments",
        "jvmFlags",
        "jvmName",
        "jvmStartTime",
        "jvmVersion",
        "lineNumber",
        "location",
        "method",
        "modifiers",
        "module",
        "monitorClass",
        "name",
        "notifier",
        "osName",
        "osThreadId",
        "package",
        "parent",
        "parkedClass",
        "pid",
        "previousOwner",
        "stackTrace",
        "startTime",
        "timedOut",
        "timeout",
        "total",
        "truncated",
        "type",
        "until",
        "values",
        "version",
        "virtual",
    }
)


def _validate_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting too deep")
    if isinstance(value, dict):
        typed = cast(dict[str, Any], value)
        if not set(typed).issubset(_KNOWN_NESTED_KEYS):
            raise ValueError("unknown JFR JSON field")
        for child in typed.values():
            _validate_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in cast(list[Any], value):
            _validate_tree(child, depth + 1)
    elif not isinstance(value, (str, int, bool, type(None))) or isinstance(value, float):
        raise ValueError("unsupported JFR JSON scalar")
