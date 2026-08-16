from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, cast

from mcp.client import Client
from tests.support.trace import make_scheduler_trace_evidence

from perflens.collection.collector import ACTIVE_COLLECTION_AUTHORIZATION
from perflens.mcp.server import ServerConfig, create_server
from perflens.mcp.storage import ArtifactStore, PathPolicy


def _structured(result: Any) -> dict[str, Any]:
    payload = result.structured_content
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_tools_have_typed_schemas_annotations_and_permissions(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            result = await client.list_tools()
            tools = {tool.name: tool for tool in result.tools}
            assert set(tools) == {
                "analyze_profile",
                "verify_analysis",
                "list_hotspots",
                "get_hotspot_details",
                "get_call_paths",
                "classify_hotspots",
                "build_diagnosis_bundle",
                "read_artifact_page",
                "resolve_source",
                "get_source_context",
                "analyze_benchmark",
                "compare_profiles",
                "compare_benchmarks",
                "collect_profile",
                "inspect_collection_capabilities",
                "plan_automatic_collection",
                "execute_collection_plan",
                "collect_project_workload",
                "analyze_collection",
                "analyze_trace_evidence",
                "verify_trace_analysis",
            }
            for tool in tools.values():
                assert tool.input_schema["type"] == "object"
                assert tool.output_schema is not None
                assert tool.annotations is not None
                assert tool.annotations.open_world_hint is False
            read_annotations = tools["list_hotspots"].annotations
            write_annotations = tools["analyze_profile"].annotations
            assert read_annotations is not None
            assert write_annotations is not None
            assert read_annotations.read_only_hint is True
            assert write_annotations.read_only_hint is False
            assert tools["analyze_profile"].meta == {"perflens/permission": "WRITES_ARTIFACTS"}
            active_annotations = tools["collect_profile"].annotations
            assert active_annotations is not None
            assert active_annotations.destructive_hint is True
            assert active_annotations.idempotent_hint is False
            assert tools["collect_profile"].meta == {"perflens/permission": "ACTIVE_COLLECTION"}
            capability_annotations = tools["inspect_collection_capabilities"].annotations
            plan_annotations = tools["plan_automatic_collection"].annotations
            assert capability_annotations is not None
            assert plan_annotations is not None
            assert capability_annotations.read_only_hint is True
            assert plan_annotations.read_only_hint is True
            assert tools["execute_collection_plan"].meta == {
                "perflens/permission": "AUTOMATIC_COLLECTION"
            }
            assert tools["collect_project_workload"].meta == {
                "perflens/permission": "PROJECT_EXECUTION"
            }
            project_authorization = tools["collect_project_workload"].input_schema["properties"][
                "authorization"
            ]
            assert project_authorization["const"] == "I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION"
            assert tools["analyze_collection"].meta == {"perflens/permission": "PROCESS_EXECUTION"}
            assert tools["analyze_trace_evidence"].meta == {
                "perflens/permission": "WRITES_ARTIFACTS"
            }
            assert tools["verify_trace_analysis"].meta == {
                "perflens/permission": "READ_ONLY"
            }

    asyncio.run(exercise())


def test_trace_evidence_is_analyzed_verified_and_paged_without_a_raw_path(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    store = ArtifactStore(
        artifact_root,
        PathPolicy((tmp_path,)),
        allow_writes=True,
    )
    evidence = make_scheduler_trace_evidence()
    store.save(evidence, evidence.trace_evidence_id, "trace-evidence")
    server = create_server(
        ServerConfig((tmp_path,), artifact_root, allow_writes=True)
    )

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = _structured(
                await client.call_tool(
                    "analyze_trace_evidence",
                    {"trace_evidence_id": evidence.trace_evidence_id},
                )
            )
            assert analyzed["artifact_type"] == "scheduler-analysis"
            summary = cast(dict[str, Any], analyzed["summary"])
            assert summary["artifact_content_sha256"]
            assert summary["summary_sha256"]
            assert summary["verification_status"] == "partial"
            analysis_id = cast(str, analyzed["artifact_id"])

            verification = _structured(
                await client.call_tool(
                    "verify_trace_analysis",
                    {"analysis_id": analysis_id},
                )
            )
            assert verification["verification_status"] == "partial"
            assert all(
                check["status"] != "failed"
                for check in cast(list[dict[str, Any]], verification["checks"])
            )

            page = _structured(
                await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": analysis_id,
                        "artifact_type": "scheduler-analysis",
                    },
                )
            )
            assert '"scheduler_analysis_id"' in cast(str, page["text"])
            assert "private scheduler trace" not in cast(str, page["text"])
            assert "/var/lib/perflens-trace" not in cast(str, page["text"])

    asyncio.run(exercise())


def test_end_to_end_analysis_details_diagnosis_and_paging(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    profile = tmp_path / "profile.folded"
    profile.write_text("main;worker;malloc 70\nmain;worker;compute 30\n")
    candidate_profile = tmp_path / "candidate.folded"
    candidate_profile.write_text("main;worker;malloc 50\nmain;worker;compute 50\n")
    baseline_benchmark = tmp_path / "baseline-benchmark.json"
    candidate_benchmark = tmp_path / "candidate-benchmark.json"
    baseline_benchmark.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "command": "./bench",
                        "times": [1.0, 1.01, 0.99],
                        "exit_codes": [0, 0, 0],
                    }
                ]
            }
        )
    )
    candidate_benchmark.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "command": "./bench",
                        "times": [0.8, 0.81, 0.79],
                        "exit_codes": [0, 0, 0],
                    }
                ]
            }
        )
    )
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            analyzed = await client.call_tool("analyze_profile", {"path": str(profile)})
            analysis = _structured(analyzed)
            analysis_id = cast(str, analysis["artifact_id"])
            candidate_analysis = _structured(
                await client.call_tool("analyze_profile", {"path": str(candidate_profile)})
            )

            hotspots = _structured(
                await client.call_tool(
                    "list_hotspots",
                    {"analysis_id": analysis_id, "limit": 1},
                )
            )
            assert hotspots["total_items"] == 4
            assert hotspots["next_cursor"] == 1
            assert hotspots["evidence_quality"]["parser_invariants_passed"] is True
            hotspot_id = hotspots["items"][0]["hotspot_id"]

            verification = _structured(
                await client.call_tool("verify_analysis", {"analysis_id": analysis_id})
            )
            assert verification["status"] == "partial"
            assert verification["checks"][0]["name"] == "analysis_content_sha256"

            details = _structured(
                await client.call_tool(
                    "get_hotspot_details",
                    {"analysis_id": analysis_id, "hotspot_id": hotspot_id},
                )
            )
            assert details["hotspot"]["symbol"] == "malloc"
            assert details["classifications"][0]["conclusion_status"] == "candidate"

            paths = _structured(
                await client.call_tool(
                    "get_call_paths",
                    {"analysis_id": analysis_id, "symbol": "malloc"},
                )
            )
            assert paths["total_items"] == 1

            classifications = _structured(
                await client.call_tool("classify_hotspots", {"analysis_id": analysis_id})
            )
            assert classifications["items"][0]["category"] == "memory-allocation"

            bundle = _structured(
                await client.call_tool(
                    "build_diagnosis_bundle",
                    {"analysis_id": analysis_id},
                )
            )
            diagnosis_path = artifact_root / f"{bundle['artifact_id']}.diagnosis.json"
            diagnosis_snapshot = diagnosis_path.read_bytes()
            repeated_bundle = _structured(
                await client.call_tool(
                    "build_diagnosis_bundle",
                    {"analysis_id": analysis_id},
                )
            )
            assert repeated_bundle == bundle
            assert diagnosis_path.read_bytes() == diagnosis_snapshot
            page = _structured(
                await client.call_tool(
                    "read_artifact_page",
                    {
                        "artifact_id": bundle["artifact_id"],
                        "artifact_type": "diagnosis",
                        "limit": 128,
                    },
                )
            )
            assert page["total_bytes"] > 128
            assert page["next_offset"] == 128
            assert page["text"].startswith("{")

            profile_comparison = _structured(
                await client.call_tool(
                    "compare_profiles",
                    {
                        "baseline_analysis_id": analysis_id,
                        "candidate_analysis_id": candidate_analysis["artifact_id"],
                    },
                )
            )
            assert profile_comparison["summary"]["hotspot_delta_count"] > 0

            benchmark_ids: list[str] = []
            for benchmark_path in (baseline_benchmark, candidate_benchmark):
                normalized = _structured(
                    await client.call_tool("analyze_benchmark", {"path": str(benchmark_path)})
                )
                benchmark_ids.append(cast(str, normalized["artifact_id"]))
            benchmark_comparison = _structured(
                await client.call_tool(
                    "compare_benchmarks",
                    {
                        "baseline_benchmark_id": benchmark_ids[0],
                        "candidate_benchmark_id": benchmark_ids[1],
                    },
                )
            )
            assert benchmark_comparison["summary"]["metric_count"] == 1

    asyncio.run(exercise())


def test_artifact_paging_cannot_bypass_analysis_integrity_gate(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    profile = tmp_path / "profile.folded"
    profile.write_text("main;worker 10\n", encoding="utf-8")
    server = create_server(ServerConfig((tmp_path,), artifact_root, allow_writes=True))

    async def exercise() -> None:
        async with Client(server) as client:
            analyzed = _structured(
                await client.call_tool("analyze_profile", {"path": str(profile)})
            )
            analysis_id = cast(str, analyzed["artifact_id"])
            artifact_path = artifact_root / f"{analysis_id}.analysis.json"
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
            payload["metadata"]["total_weight"] = 11
            artifact_path.write_text(json.dumps(payload), encoding="utf-8")

            paged = await client.call_tool(
                "read_artifact_page",
                {
                    "artifact_id": analysis_id,
                    "artifact_type": "analysis",
                },
            )
            assert paged.is_error

    asyncio.run(exercise())


def test_server_enforces_write_process_and_path_authorization(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    artifact_root = allowed / "artifacts"
    artifact_root.mkdir()
    profile = allowed / "profile.folded"
    profile.write_text("main 1\n")
    outside = tmp_path / "outside.folded"
    outside.write_text("secret 1\n")
    server = create_server(ServerConfig((allowed,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            write_denied = await client.call_tool(
                "analyze_profile",
                {"path": str(profile)},
            )
            path_denied = await client.call_tool(
                "analyze_profile",
                {"path": str(outside)},
            )
            process_denied = await client.call_tool(
                "resolve_source",
                {"binary_path": str(profile), "module_offset": 1},
            )
            collection_denied = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(allowed / "profile.data"),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(profile),
                },
            )
            assert write_denied.is_error
            assert path_denied.is_error
            assert process_denied.is_error
            assert collection_denied.is_error
        assert list(artifact_root.iterdir()) == []

    asyncio.run(exercise())


def test_automatic_collection_is_plannable_but_not_executable_by_default(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server) as client:
            planned = await client.call_tool(
                "plan_automatic_collection",
                {"pid": os.getppid(), "duration_seconds": 0.1},
            )
            payload = _structured(planned)
            assert payload["policy_status"] == "denied"
            executed = await client.call_tool(
                "execute_collection_plan",
                {"plan_id": payload["plan_id"]},
            )
            assert executed.is_error
        assert list(artifact_root.iterdir()) == []

    asyncio.run(exercise())


def test_active_collection_requires_server_and_per_call_authorization(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'PERFILE2')\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    target = tmp_path / "target"
    target.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            perf_path=fake_perf,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            denied = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(tmp_path / "denied.data"),
                    "authorization": "not-authorized",
                    "executable": str(target),
                },
            )
            assert denied.is_error
            assert not (tmp_path / "denied.data").exists()

        async with Client(server, raise_exceptions=True) as client:
            collected = _structured(
                await client.call_tool(
                    "collect_profile",
                    {
                        "output_path": str(tmp_path / "profile.data"),
                        "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                        "executable": str(target),
                    },
                )
            )
            assert collected["artifact_type"] == "collection"
            assert collected["summary"]["mode"] == "record"
            assert (tmp_path / "profile.data").read_bytes() == b"PERFILE2"
            stored = artifact_root / (f"{collected['artifact_id']}.collection.json")
            assert json.loads(stored.read_text(encoding="utf-8"))["authorization"] == "explicit"

    asyncio.run(exercise())


def test_analyze_collection_binds_collection_hash_and_quality_context(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version collection-test')\n"
        "elif args and args[0] == 'script':\n"
        "    print('app 9/9 [000] 1.0: 11 cycles: 400010 leaf (/app) /src/app.c:7')\n"
        "elif 'record' in args:\n"
        "    pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'PERFILE2')\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    target = tmp_path / "target"
    target.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    profile = tmp_path / "profile.data"
    server = create_server(
        ServerConfig(
            (tmp_path,),
            artifact_root,
            allow_writes=True,
            allow_process_execution=True,
            allow_active_collection=True,
            perf_path=fake_perf,
        )
    )

    async def exercise() -> None:
        async with Client(server) as client:
            collected_result = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(profile),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(target),
                },
            )
            assert not collected_result.is_error
            collected = _structured(collected_result)
            collection_id = cast(str, collected["artifact_id"])
            analyzed_result = await client.call_tool(
                "analyze_collection", {"collection_id": collection_id}
            )
            assert not analyzed_result.is_error
            analyzed = _structured(analyzed_result)
            quality = cast(dict[str, Any], analyzed["evidence_quality"])
            assert quality["source_collection_id"] == collection_id
            assert quality["input_sha256"] == hashlib.sha256(b"PERFILE2").hexdigest()

            trace_collected_result = await client.call_tool(
                "collect_profile",
                {
                    "output_path": str(tmp_path / "trace.data"),
                    "authorization": ACTIVE_COLLECTION_AUTHORIZATION,
                    "executable": str(target),
                    "mode": "sched",
                },
            )
            assert not trace_collected_result.is_error
            trace_collection_id = cast(
                str,
                _structured(trace_collected_result)["artifact_id"],
            )
            wrong_analyzer = await client.call_tool(
                "analyze_collection",
                {"collection_id": trace_collection_id},
            )
            assert wrong_analyzer.is_error
            assert "TraceEvidence" in str(wrong_analyzer.content)

            profile.write_bytes(b"PERFILE3")
            rejected = await client.call_tool(
                "analyze_collection", {"collection_id": collection_id}
            )
            assert rejected.is_error

    asyncio.run(exercise())


def test_source_context_is_workspace_bounded(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    source = tmp_path / "sample.c"
    source.write_text("one\ntwo\nthree\n")
    server = create_server(ServerConfig((tmp_path,), artifact_root))

    async def exercise() -> None:
        async with Client(server, raise_exceptions=True) as client:
            result = _structured(
                await client.call_tool(
                    "get_source_context",
                    {
                        "file": str(source),
                        "line": 2,
                        "workspace_root": str(tmp_path),
                        "before": 1,
                        "after": 1,
                    },
                )
            )
            assert result["lines"] == ["one", "two", "three"]

    asyncio.run(exercise())
