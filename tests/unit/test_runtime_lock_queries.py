from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from perflens.application.analyze_runtime_locks import build_runtime_lock_analysis
from perflens.application.evidence import contract_content_sha256
from perflens.application.runtime_lock_queries import (
    build_runtime_lock_diagnosis_bundle,
    get_runtime_lock_call_paths,
    list_runtime_lock_hotspots,
)
from perflens.application.verify_runtime_locks import (
    verify_runtime_lock_analysis_artifact,
)
from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import import_runtime_lock_ndjson


def _artifacts():
    fixture = Path(__file__).parents[1] / "fixtures/runtime_locks/valid-v1.1.ndjson"
    with fixture.open("rb") as source:
        evidence = import_runtime_lock_ndjson(source)
    analysis = build_runtime_lock_analysis(evidence)
    verification = verify_runtime_lock_analysis_artifact(analysis, evidence)
    return evidence, analysis, verification


@pytest.mark.parametrize(
    "projection",
    ["lock", "execution_context", "call_path", "wait_outcome", "lock_kind"],
)
def test_runtime_lock_hotspot_pages_preserve_projection_coverage(
    projection: str,
) -> None:
    _, analysis, _ = _artifacts()

    page = list_runtime_lock_hotspots(
        analysis,
        projection=projection,  # type: ignore[arg-type]
        cursor=0,
        limit=1,
    )

    assert page.projection == projection
    assert page.coverage is not None
    assert page.total_items == page.coverage.exported_row_count
    assert len(page.items) <= 1
    assert page.runtime_lock_analysis_id == analysis.runtime_lock_analysis_id
    assert page.forbidden_conclusions == analysis.forbidden_conclusions


def test_runtime_lock_call_paths_join_only_public_redacted_stacks() -> None:
    evidence, analysis, _ = _artifacts()

    page = get_runtime_lock_call_paths(analysis, evidence, limit=1)

    assert len(page.items) == len(page.stacks) == 1
    stack = page.stacks[0]
    assert stack is not None
    assert page.items[0].stack_id == stack.stack_id
    assert all(
        frame.source_file is None or not frame.source_file.startswith("/") for frame in stack.frames
    )
    assert page.coverage == analysis.call_path_coverage


def test_runtime_lock_call_path_page_rejects_a_mismatched_stack() -> None:
    evidence, analysis, _ = _artifacts()
    page = get_runtime_lock_call_paths(analysis, evidence, limit=1)

    with pytest.raises(ValidationError, match="do not match"):
        page.model_copy(
            update={
                "stacks": (
                    evidence.stacks[0].model_copy(update={"stack_id": "runtime-stack-" + "f" * 24}),
                )
            },
        ).__class__.model_validate(
            {
                **page.model_dump(mode="json"),
                "stacks": [
                    {
                        **evidence.stacks[0].model_dump(mode="json"),
                        "stack_id": "runtime-stack-" + "f" * 24,
                    }
                ],
            }
        )


def test_runtime_lock_call_paths_reject_evidence_from_another_artifact() -> None:
    evidence, analysis, _ = _artifacts()
    mismatched = evidence.model_copy(
        update={"runtime_lock_evidence_id": "runtime-lock-evidence-" + "f" * 16}
    )

    with pytest.raises(PerfLensError, match="deterministic invariant checks"):
        get_runtime_lock_call_paths(analysis, mismatched)


def test_runtime_lock_diagnosis_remains_a_bounded_verified_summary() -> None:
    evidence, analysis, verification = _artifacts()

    diagnosis = build_runtime_lock_diagnosis_bundle(
        analysis,
        evidence,
        verification,
    )

    assert diagnosis.runtime_lock_analysis_id == analysis.runtime_lock_analysis_id
    assert diagnosis.runtime_lock_evidence_id == evidence.runtime_lock_evidence_id
    assert diagnosis.runtime_lock_verification_id == verification.runtime_lock_verification_id
    assert diagnosis.content_sha256 == contract_content_sha256(
        diagnosis,
        exclude={"content_sha256"},
    )
    assert len(diagnosis.observations) == 3
    assert "performance_root_cause" in diagnosis.forbidden_conclusions


def test_runtime_lock_diagnosis_rejects_a_verification_from_another_chain() -> None:
    evidence, analysis, verification = _artifacts()
    mismatched = verification.model_copy(
        update={"runtime_lock_verification_id": "runtime-lock-verification-" + "f" * 16}
    )

    with pytest.raises(PerfLensError, match="does not match"):
        build_runtime_lock_diagnosis_bundle(analysis, evidence, mismatched)
