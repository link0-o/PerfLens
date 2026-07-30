"""Candidate-only classification with explicit evidence and limitations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from perflens.classification.rules import CompiledRule, load_builtin_rules
from perflens.contracts.artifacts import (
    AnalysisArtifact,
    Classification,
    DiagnosisBundle,
    Evidence,
)


def build_diagnosis_bundle(
    analysis: AnalysisArtifact,
    *,
    rules: tuple[CompiledRule, ...] | None = None,
) -> DiagnosisBundle:
    effective_rules = rules or load_builtin_rules()
    classifications: list[Classification] = []
    for hotspot in analysis.hotspots:
        for rule in effective_rules:
            if not rule.matches(
                hotspot.symbol,
                hotspot.dso,
                hotspot.self_percent,
                hotspot.inclusive_percent,
            ):
                continue
            document = rule.document
            level: Literal["L1", "L2"] = "L2" if analysis.metadata.has_call_graph else "L1"
            supporting = (
                Evidence(
                    evidence_id=f"E-{len(classifications) + 1:03d}-self",
                    level=level,
                    kind="profile_hotspot",
                    statement=(
                        f"{hotspot.symbol} has {hotspot.self_percent:.3f}% self and "
                        f"{hotspot.inclusive_percent:.3f}% inclusive weight."
                    ),
                    artifact_id=analysis.analysis_id,
                    hotspot_id=hotspot.hotspot_id,
                ),
            )
            counter = (
                ("The function has no direct self weight in this profile.",)
                if hotspot.self_weight == 0
                else ()
            )
            classifications.append(
                Classification(
                    classification_id=f"C-{len(classifications) + 1:03d}",
                    rule_id=document.id,
                    rule_version=document.version,
                    hotspot_id=hotspot.hotspot_id,
                    symbol=hotspot.symbol,
                    dso=hotspot.dso,
                    category=document.classification.category,
                    confidence=document.classification.confidence,
                    evidence_level=level,
                    observation=document.observation.format(symbol=hotspot.symbol),
                    supporting_evidence=supporting,
                    counter_evidence=counter,
                    missing_evidence=document.missing_evidence,
                    limitations=document.limitations,
                    next_steps=document.next_steps,
                    forbidden_conclusions=document.forbidden_conclusions,
                )
            )

    observations = tuple(
        f"{hotspot.hotspot_id} {hotspot.symbol} self={hotspot.self_percent:.3f}% "
        f"inclusive={hotspot.inclusive_percent:.3f}%"
        for hotspot in analysis.hotspots[:10]
    )
    limitations = list(analysis.metadata.warnings)
    if not analysis.metadata.has_call_graph:
        limitations.append("The profile has no call graph; evidence is limited to L1 hotspots.")
    if not analysis.metadata.has_source_lines:
        limitations.append(
            "Source lines are unavailable; source-level attribution is not supported."
        )
    if analysis.metadata.event == "unknown":
        limitations.append("The sampled event is unknown, so weight semantics are limited.")
    missing = {
        item for classification in classifications for item in classification.missing_evidence
    }
    if not classifications:
        missing.add("No generic classification rule matched; inspect top call paths manually.")
    return DiagnosisBundle(
        analysis_id=analysis.analysis_id,
        status="partial" if limitations or missing else "complete",
        generated_at=datetime.now(tz=UTC).isoformat(),
        classifications=tuple(classifications),
        observations=observations,
        limitations=tuple(dict.fromkeys(limitations)),
        missing_evidence=tuple(sorted(missing)),
    )
