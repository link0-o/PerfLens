"""Stable machine errors and Chinese-first terminal summaries."""

from __future__ import annotations

import hashlib
import json
from contextvars import ContextVar
from typing import Final

from perflens.contracts.artifacts import ErrorArtifact, ErrorBody
from perflens.domain.errors import ErrorCode, PerfLensError

_JSON_ERRORS = ContextVar("perflens_json_errors", default=False)

ERROR_EXIT_CODES: Final[dict[ErrorCode, int]] = {
    ErrorCode.INVALID_INPUT: 2,
    ErrorCode.UNSUPPORTED_FORMAT: 3,
    ErrorCode.PROFILE_PARSE_FAILED: 3,
    ErrorCode.EXTERNAL_TOOL_FAILED: 6,
    ErrorCode.EXTERNAL_TOOL_TIMEOUT: 6,
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: 4,
    ErrorCode.PATH_SAFETY_VIOLATION: 5,
    ErrorCode.OUTPUT_WRITE_FAILED: 5,
    ErrorCode.INTERNAL_ERROR: 70,
}

_ERROR_LABELS: Final[dict[ErrorCode, str]] = {
    ErrorCode.INVALID_INPUT: "输入参数或配置无效",
    ErrorCode.UNSUPPORTED_FORMAT: "输入格式暂不支持",
    ErrorCode.PROFILE_PARSE_FAILED: "性能数据无法可靠解析",
    ErrorCode.EXTERNAL_TOOL_FAILED: "外部性能工具执行失败",
    ErrorCode.EXTERNAL_TOOL_TIMEOUT: "外部性能工具执行超时",
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: "安全资源上限不足或已达到",
    ErrorCode.PATH_SAFETY_VIOLATION: "路径、权限或授权未通过安全检查",
    ErrorCode.OUTPUT_WRITE_FAILED: "结果文件无法安全写入",
    ErrorCode.INTERNAL_ERROR: "PerfLens 发生内部错误",
}

_GENERIC_ACTIONS: Final[dict[ErrorCode, str]] = {
    ErrorCode.INVALID_INPUT: "检查命令参数和配置文件后重试。",
    ErrorCode.UNSUPPORTED_FORMAT: "确认输入类型, 并先使用受支持的转换工具生成 Profile。",
    ErrorCode.PROFILE_PARSE_FAILED: "保留原始数据, 检查诊断信息和采集工具版本。",
    ErrorCode.EXTERNAL_TOOL_FAILED: "检查对应工具是否已安装, 并查看上面的技术信息。",
    ErrorCode.EXTERNAL_TOOL_TIMEOUT: "缩短任务范围或提高有界超时后重试。",
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: "缩短采集、降低输出上限, 或由管理员审查存储容量。",
    ErrorCode.PATH_SAFETY_VIOLATION: "确认路径所有者、权限和显式授权; 不要用 root 绕过检查。",
    ErrorCode.OUTPUT_WRITE_FAILED: "选择一个尚不存在、父目录可写的新输出路径。",
    ErrorCode.INTERNAL_ERROR: "保留错误 ID 和技术信息, 用于提交问题报告。",
}


def configure_json_errors(enabled: bool) -> None:
    """Set error presentation for the current CLI invocation context."""
    _JSON_ERRORS.set(enabled)


def json_errors_enabled() -> bool:
    return _JSON_ERRORS.get()


def error_artifact(error: PerfLensError) -> ErrorArtifact:
    material = f"{error.code}:{error.stage}:{error.message}"
    return ErrorArtifact(
        error=ErrorBody(
            error_id=f"err-{hashlib.sha256(material.encode()).hexdigest()[:16]}",
            code=error.code.value,
            stage=error.stage,
            message=error.message,
            recoverable=error.recoverable,
            retryable=error.retryable,
            details=error.details,
            suggested_actions=error.suggested_actions,
        )
    )


def error_json(error: PerfLensError) -> str:
    return json.dumps(
        error_artifact(error).model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
    )


def render_error_chinese(error: PerfLensError, *, executable: str) -> str:
    artifact = error_artifact(error)
    lines = [
        "PerfLens 操作失败",
        f"错误: {_ERROR_LABELS[error.code]}",
        f"错误代码: {error.code.value}",
        f"阶段: {error.stage}",
        f"技术信息: {error.message}",
        f"错误 ID: {artifact.error.error_id}",
        "下一步:",
        f"- {_GENERIC_ACTIONS[error.code]}",
    ]
    lines.extend(f"- {action}" for action in error.suggested_actions)
    lines.append(
        f"- 自动化程序需要完整 JSON 时, 把 --json-errors 放在子命令前: "
        f"{executable} --json-errors <子命令> ..."
    )
    return "\n".join(lines)
