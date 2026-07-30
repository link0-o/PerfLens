# MCP server and Performance Analysis Skill

PerfLens consists of three separable layers:

1. The deterministic Python Core and CLI.
2. A local stdio MCP server that exposes bounded, typed tools.
3. A repository Skill that tells an Agent how to interpret evidence and use the tools.

Neither the Core nor MCP server calls an LLM API. The Skill contains workflow instructions only.

## Start the MCP server

Install/sync the project, choose the workspace root that profiles and source files may be read from, and place generated artifacts under that root:

```bash
uv sync --all-groups
mkdir -p perflens-results

.venv/bin/perflens-mcp \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

The server uses stdio, so an MCP client normally starts it. `--allow-writes` authorizes only atomic JSON artifacts beneath `--artifact-root`. Add `--allow-process-execution` only when the client should be allowed to invoke the read-only `perf script` or symbolizer adapters. It does not authorize live sampling or process attachment.

Active collection is a separate, default-off capability. For an explicitly approved target command, all three startup gates are required:

```bash
.venv/bin/perflens-mcp \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes \
  --allow-process-execution \
  --allow-active-collection
```

Each `collect_profile` call must also carry the exact authorization value `I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING`. PID attachment remains disabled unless `--allow-pid-attach` is present and the call also carries `I_EXPLICITLY_AUTHORIZE_PID_ATTACH`. PerfLens never requests sudo or changes kernel perf policy.

Multiple `--allowed-root` options are supported. Every root must already exist. Input profiles, binaries, debug files, source workspaces, and the artifact directory are canonicalized and checked against these roots.

## Connect Codex

The current Codex CLI supports local stdio MCP servers. From the repository, use absolute paths:

```bash
codex mcp add perflens -- \
  "$PWD/.venv/bin/perflens-mcp" \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

Alternatively, add project-scoped configuration in `.codex/config.toml` after trusting the project:

```toml
[mcp_servers.perflens]
command = "/absolute/path/to/PerfLens/.venv/bin/perflens-mcp"
args = [
  "--allowed-root", "/absolute/path/to/workspace",
  "--artifact-root", "/absolute/path/to/workspace/perflens-results",
  "--allow-writes",
]
required = true
default_tools_approval_mode = "writes"
tool_timeout_sec = 300
```

Restart Codex after changing MCP configuration, then use `/mcp` or `codex mcp list` to confirm the server and tools. See the [official Codex MCP configuration reference](https://developers.openai.com/codex/mcp/).

## Use the Skill

The repository Skill is at `.agents/skills/perflens-performance-analysis`. In Codex, invoke it explicitly when desired:

```text
$perflens-performance-analysis analyze ./perf.data and explain the strongest evidence and missing evidence.
```

It may also trigger implicitly for Linux profile diagnosis. The Skill requires the Agent to inspect metadata and dominant paths, treat rule matches as candidates, state missing evidence, and reserve `Verified Improvement` for equivalent-workload A/B validation.

## Tool permissions

| Permission | Tools | Server enforcement |
|---|---|---|
| `READ_ONLY` | hotspot/path lookup, classification pages, artifact pages, source context | Only configured artifact IDs and allowed-root paths are accepted. |
| `WRITES_ARTIFACTS` | profile analysis, diagnosis bundle | Disabled unless `--allow-writes`; writes only beneath the artifact root. |
| `PROCESS_EXECUTION` | perf.data conversion and source symbolization | Disabled unless `--allow-process-execution`; executable selection remains allowlisted and bounded. |
| `ACTIVE_COLLECTION` | `collect_profile` record/stat/sched/lock/off-CPU modes | Requires writes, process execution, active-collection startup gate, exact per-call authorization, bounded output, and a new output path. PID attachment has two additional gates. |

Tool annotations are client hints. The authorization checks above are independent server-side controls.

## Recommended sequence

1. `analyze_profile`
2. `list_hotspots`
3. `get_hotspot_details`
4. `get_call_paths`
5. `resolve_source` and `get_source_context` when verified module offsets exist
6. `classify_hotspots`
7. `build_diagnosis_bundle`
8. `read_artifact_page` for large output
9. `analyze_benchmark`, `compare_profiles`, and `compare_benchmarks` for A/B work

`collect_profile` is intentionally outside the default sequence. Use it only after the user approves the exact target and the [Skill safety rules](../.agents/skills/perflens-performance-analysis/references/active-collection-safety.md) have been applied.

All list responses are bounded and paginated. The server emits typed structured output and checked-in JSON Schemas; it never returns an unbounded full analysis through a list tool.
