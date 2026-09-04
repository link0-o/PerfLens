"""Strict private models for bounded ``jfr print --json`` lock events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

JFR_LOCK_EVENT_TYPES = frozenset(
    {
        "jdk.JavaMonitorEnter",
        "jdk.JavaMonitorWait",
        "jdk.ThreadPark",
        "jdk.DataLoss",
        "jdk.JVMInformation",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class JfrThread(_StrictModel):
    osName: StrictStr = Field(max_length=4096)
    osThreadId: StrictInt
    javaName: StrictStr = Field(max_length=4096)
    javaThreadId: StrictInt = Field(gt=0)
    group: dict[str, Any] | None
    # JDK 17 does not serialize this metadata field.  Absence means only that
    # the source did not claim a virtual thread; newer JDKs must send a bool.
    virtual: StrictBool = False

    @model_validator(mode="after")
    def validate_thread(self) -> JfrThread:
        if not {"osName", "osThreadId", "javaName", "javaThreadId", "group"}.issubset(
            self.model_fields_set
        ):
            raise ValueError("JFR thread omitted a required field")
        if not self.virtual and self.osThreadId <= 0:
            raise ValueError("JFR platform thread requires an OS thread ID")
        return self


class JfrClassLoader(_StrictModel):
    # ``type`` is explicitly null for the bootstrap loader.  Other loaders
    # carry the same bounded class metadata shape used by stack-frame owners.
    type: JfrJavaType | None
    name: StrictStr = Field(min_length=1, max_length=4096)


class JfrModule(_StrictModel):
    name: StrictStr | None = Field(max_length=4096)
    version: StrictStr | None = Field(max_length=1024)
    location: StrictStr | None = Field(max_length=8192)
    classLoader: JfrClassLoader | None


class JfrPackage(_StrictModel):
    name: StrictStr = Field(max_length=4096)
    module: JfrModule | None
    exported: StrictBool


class JfrJavaType(_StrictModel):
    classLoader: JfrClassLoader | None
    name: StrictStr = Field(min_length=1, max_length=4096)
    # JFR uses an explicit null package for classes in the unnamed package.
    package: JfrPackage | None
    modifiers: StrictInt = Field(ge=0, le=(1 << 31) - 1)
    hidden: StrictBool


class JfrMethod(_StrictModel):
    type: JfrJavaType
    name: StrictStr = Field(min_length=1, max_length=4096)
    descriptor: StrictStr = Field(max_length=16_384)
    modifiers: StrictInt = Field(ge=0, le=(1 << 31) - 1)
    hidden: StrictBool


class JfrStackFrame(_StrictModel):
    method: JfrMethod
    lineNumber: StrictInt = Field(ge=-1, le=(1 << 31) - 1)
    bytecodeIndex: StrictInt = Field(ge=-1, le=(1 << 31) - 1)
    type: StrictStr = Field(min_length=1, max_length=128)


class JfrStackTrace(_StrictModel):
    truncated: StrictBool
    # An empty list is a real ``jfr print --json`` encoding.  The converter
    # accepts it but must downgrade public evidence because no call path can
    # be attributed to the affected event.
    frames: tuple[JfrStackFrame, ...] = Field(max_length=127)


class JfrLockValues(_StrictModel):
    startTime: StrictStr = Field(max_length=128)
    duration: StrictStr = Field(max_length=128)
    eventThread: JfrThread
    stackTrace: JfrStackTrace | None
    monitorClass: JfrJavaType | None = None
    parkedClass: JfrJavaType | None = None
    previousOwner: JfrThread | None = None
    notifier: JfrThread | None = None
    address: StrictInt = Field(ge=0)
    timedOut: StrictBool | None = None
    timeout: StrictStr | None = None
    until: StrictStr | None = None


class JfrDataLossValues(_StrictModel):
    startTime: StrictStr = Field(max_length=128)
    amount: StrictInt = Field(ge=0)
    total: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_loss(self) -> JfrDataLossValues:
        if self.total < self.amount:
            raise ValueError("JFR cumulative data loss is smaller than this loss record")
        return self


class JfrLockEvent(_StrictModel):
    type: Literal["jdk.JavaMonitorEnter", "jdk.JavaMonitorWait", "jdk.ThreadPark"]
    values: JfrLockValues

    @model_validator(mode="after")
    def validate_event_shape(self) -> JfrLockEvent:
        fields = self.values.model_fields_set
        common = {"startTime", "duration", "eventThread", "stackTrace", "address"}
        if self.type == "jdk.JavaMonitorEnter":
            expected = common | {"monitorClass", "previousOwner"}
        elif self.type == "jdk.JavaMonitorWait":
            expected = common | {"monitorClass", "notifier", "timedOut", "timeout"}
        else:
            expected = common | {"parkedClass", "timeout", "until"}
        if fields != expected:
            raise ValueError("JFR lock event fields do not match its event type")
        return self


class JfrDataLossEvent(_StrictModel):
    type: Literal["jdk.DataLoss"]
    values: JfrDataLossValues


class JfrJvmInformationValues(_StrictModel):
    startTime: StrictStr = Field(max_length=128)
    jvmName: StrictStr = Field(min_length=1, max_length=1024)
    jvmVersion: StrictStr = Field(min_length=1, max_length=8192)
    jvmArguments: StrictStr | None = Field(default=None, max_length=65_536)
    jvmFlags: StrictStr | None = Field(default=None, max_length=65_536)
    javaArguments: StrictStr | None = Field(default=None, max_length=65_536)
    jvmStartTime: StrictStr = Field(max_length=128)
    pid: StrictInt = Field(gt=0)


class JfrJvmInformationEvent(_StrictModel):
    type: Literal["jdk.JVMInformation"]
    values: JfrJvmInformationValues


type JfrPrivateEvent = JfrLockEvent | JfrDataLossEvent | JfrJvmInformationEvent


@dataclass(frozen=True, slots=True)
class JfrStreamIdentity:
    source_sha256: str
    source_bytes: int
    event_count: int
