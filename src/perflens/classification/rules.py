"""Safe YAML rule loading and deterministic hotspot matching."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from perflens.domain.errors import ErrorCode, PerfLensError


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleMatch(_StrictModel):
    symbol_regex: tuple[str, ...]
    dso_regex: tuple[str, ...] = ()


class RuleThresholds(_StrictModel):
    self_percent_gte: float = Field(default=0, ge=0, le=100)
    inclusive_percent_gte: float = Field(default=0, ge=0, le=100)


class RuleClassification(_StrictModel):
    category: str
    confidence: Literal["low", "medium"]


class RuleDocument(_StrictModel):
    id: str
    version: int = Field(ge=1)
    scope: Literal["generic", "linux", "cpp"]
    match: RuleMatch
    thresholds: RuleThresholds = RuleThresholds()
    classification: RuleClassification
    observation: str
    limitations: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    next_steps: tuple[str, ...]
    forbidden_conclusions: tuple[str, ...]


class CompiledRule:
    __slots__ = ("document", "dso_patterns", "symbol_patterns")

    def __init__(self, document: RuleDocument) -> None:
        self.document = document
        try:
            self.symbol_patterns = tuple(
                re.compile(pattern, re.IGNORECASE) for pattern in document.match.symbol_regex
            )
            self.dso_patterns = tuple(
                re.compile(pattern, re.IGNORECASE) for pattern in document.match.dso_regex
            )
        except re.error as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "classification",
                "Classification rule contains an invalid regular expression",
                details={"rule_id": document.id, "regex_error": str(exc)},
            ) from exc

    def matches(
        self,
        symbol: str,
        dso: str,
        self_percent: float,
        inclusive_percent: float,
    ) -> bool:
        if not any(pattern.search(symbol) for pattern in self.symbol_patterns):
            return False
        if self.dso_patterns and not any(pattern.search(dso) for pattern in self.dso_patterns):
            return False
        thresholds = self.document.thresholds
        return (
            self_percent >= thresholds.self_percent_gte
            and inclusive_percent >= thresholds.inclusive_percent_gte
        )


def load_builtin_rules() -> tuple[CompiledRule, ...]:
    rule_root = resources.files("perflens.rules")
    documents: list[RuleDocument] = []
    for filename in ("generic.yaml", "linux.yaml", "cpp.yaml"):
        text = rule_root.joinpath(filename).read_text(encoding="utf-8")
        documents.extend(_parse_rule_documents(text, source=filename))
    return tuple(CompiledRule(document) for document in documents)


def load_rule_file(path: Path) -> tuple[CompiledRule, ...]:
    try:
        safe_path = path.expanduser().resolve(strict=True)
        text = safe_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "classification",
            "Rule file cannot be read",
            details={"path": str(path)},
        ) from exc
    return tuple(CompiledRule(document) for document in _parse_rule_documents(text, str(safe_path)))


def _parse_rule_documents(text: str, source: str) -> tuple[RuleDocument, ...]:
    try:
        raw: object = yaml.safe_load(text)
        items = [raw] if not isinstance(raw, list) else cast(list[object], raw)
        return tuple(RuleDocument.model_validate(item) for item in items)
    except (yaml.YAMLError, ValidationError, TypeError) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "classification",
            "Classification rule YAML is invalid",
            details={"source": source, "exception_type": type(exc).__name__},
        ) from exc
