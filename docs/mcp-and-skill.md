# MCP server and Performance Analysis Skill

[简体中文](mcp-and-skill.zh-CN.md) | English

PerfLens consists of three separable layers:

1. The deterministic Python Core and CLI.
2. A local stdio MCP server that exposes bounded, typed tools to Codex or Claude Code.
3. A project Skill that tells an Agent how to interpret evidence and use the tools.

Neither the Core nor MCP server calls an LLM API. The Skill contains workflow instructions only.

## Start the MCP server

For an installed package, opt only the selected project in:

```bash
cd /absolute/path/to/workspace
perflens init
```

It activates Codex and Claude Code by default. Use `--client codex`,
`--client claude-code`, or `--read-only` to narrow the scope. It installs only
project Skills and MCP configuration, then creates Chinese and English next steps,
capability diagnostics, a safely managed project `.codex/config.toml` block,
and a standalone `codex-mcp.toml` under
`perflens-setup/`. It neither overwrites existing files nor requests
administrator privileges. See the [installation guide](../INSTALL.md) for the
complete download-to-first-analysis path.

Use `perflens init --update` to refresh an existing project after an upgrade or
to change collection gates. Update mode requires a matching ownership artifact
and refuses modified Skills or unverified client configuration. Detach a client
before updating with a narrower client selection. The managed setup directory
refuses unexpected user files and preserves staged Collector assets unless
regeneration is explicitly requested.

For a project that intentionally targets a local Docker workload, initialize with:

```bash
perflens init --docker
```

This adds the fixed project Docker policy and bounded MCP gates; it does not start Docker or grant
execution. Review `perflens-setup/container-workload.toml` before use. The Skill then uses
`inspect_docker_capability` and `discover_docker_processes`, resolves one exact target, requests
either `per_run` or `bounded_session` authorization, and calls only the corresponding existing- or
managed-container collection tool. The authorization call carries the exact `allowed_modes` shown
to and confirmed by the user; a later mode expansion requires a new summary and authorization.
The session token lives only in that MCP connection and is revoked with `revoke_docker_session` or
by connection exit.

The session run budget is an upper bound, not blanket consent to consume every run. If the confirmed
summary says one execution, the Skill makes one collection call and reports a failure without a
silent retry. A retry must have been disclosed in the summary or receive a new confirmation. The
requested duration is also a maximum observation window: it does not extend the fixed workload's
lifetime, so a workload that exits after two seconds cannot yield ten seconds of samples merely by
requesting a ten-second collection.

The default project policy allows `stat` and `record`, with MCP ceilings of 30
seconds, 99 Hz, 256 MiB per collection, and a 120-second plan lifetime. The
Skill normally starts near 10 seconds and adapts to the workload. Existing-PID
attachment is disabled unless onboarding includes
`--allow-existing-pid-attach`; project-run collection does not require it.

A structurally valid `record` file can still contain zero samples when a short or mostly sleeping
workload exits before useful sampling occurs. PerfLens publishes this as a verified `partial`
Analysis with no hotspot conclusions; it does not invent an event or treat the file as corrupt.
Zero samples alone do not establish a Docker, Gate, Collector, PMU, or sampling-pipeline defect;
target-process CPU opportunity must be distinguished from whole-container CPU and wall time before
assigning a cause.
Changing a managed recipe to run longer or perform more CPU work requires a new authorization
summary because the workload specification changed.
Docker `record` requests capture mmap Build IDs. When the capture-time module snapshot verifies a
`/workspace` module by path digest, Build ID, size, and SHA-256, later analysis copies only that
exact module into a private temporary `symfs`. The copy is reverified and removed after conversion,
and public provenance contains only its content identity. Unavailable or changed modules remain
`partial`; PerfLens does not guess a matching host file.
An unchanged v0.1.2 Skill is migrated to the shorter `perflens` directory by
`perflens init --update`, while user-modified content is preserved and refused.

The individual commands remain available for users who want to control each
step separately:

```bash
perflens install-skill --project /absolute/path/to/workspace
perflens codex-config --workspace /absolute/path/to/workspace
```

The first command refuses to overwrite an existing Skill. The second command
prints TOML for review; it never modifies global or project Codex configuration.
Add `--allow-process-execution` to `codex-config` only when needed.

For a source checkout, install/sync the project, choose the workspace root that
profiles and source files may be read from, and place generated artifacts under
that root:

```bash
uv sync --all-groups
mkdir -p perflens-results

.venv/bin/perflens-mcp \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

The server uses stdio, so an MCP client normally starts it. `--allow-writes`
authorizes only atomic, no-overwrite JSON artifacts beneath `--artifact-root`.
Reusing an artifact ID is idempotent only for byte-identical content. Reads
reject FIFOs, symlinks, extra hard links, unsafe modes, and root/file identity
changes. Add `--allow-process-execution` only when the client should be allowed
to invoke the read-only `perf script` or symbolizer adapters. It does not
authorize live sampling or process attachment.

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

## Connect Claude Code

`perflens init` installs the same Agent Skill under
`.claude/skills/perflens` and safely merges the bounded
stdio server into the project `.mcp.json`. Existing unrelated servers are
preserved, while a conflicting user-managed `perflens` entry is not overwritten.
Claude Code asks the user to approve a project-scoped MCP server before use.
If the top-level `.claude/skills` directory was created after Claude Code
started, restart once, then invoke `/perflens`.
See the official Claude Code [Skills](https://code.claude.com/docs/en/slash-commands)
and [MCP](https://code.claude.com/docs/en/mcp) documentation for client behavior.

## Use the Skill

The repository Skill is at `.agents/skills/perflens`. In Codex, invoke it explicitly when desired:

```text
$perflens analyze ./perf.data and explain the strongest evidence and missing evidence.
```

It may also trigger implicitly for Linux profile diagnosis or optimization. An
analysis request reports evidence and recommendations without source edits by
default. An optimization request establishes a baseline, changes only
evidence-supported code, runs correctness tests, and repeats the same workload
for A/B validation. “Deep” requests more thorough investigation but never grants
additional paths, PID attachment, execution, duration, or edit permission.

With an administrator-deployed Collector and an MCP configuration generated
with `--automatic-collection`, the user may ask to optimize the current project
without supplying a PID. The Skill must first confirm one exact in-project
executable, arguments, representative workload, and per-call authorization.
`collect_project_workload` then launches it as the ordinary MCP user, obtains
the new PID internally, and gives the Collector only a PID-bound plan. The user
does not need to memorize the internal token. After exact confirmation, the
Agent supplies the complete fixed `authorization` value
`I_EXPLICITLY_AUTHORIZE_PROJECT_EXECUTION`; a boolean, empty value, or
natural-language paraphrase is invalid. If the call is rejected, only correct
the argument and retry the same tool inside the confirmed scope. Do not switch
to a shell/background launch, `timeout`, direct perf, or existing-PID attach.
Callgrind, parameter sweeps, changed arguments, and other extra executions need
their own explicit authorization.

## Tool permissions

| Permission | Tools | Server enforcement |
|---|---|---|
| `READ_ONLY` | hotspot/path lookup, classification pages, artifact pages, source context | Only configured artifact IDs and allowed-root paths are accepted. |
| `WRITES_ARTIFACTS` | profile analysis, diagnosis bundle | Disabled unless `--allow-writes`; writes only beneath the artifact root. |
| `PROCESS_EXECUTION` | perf.data conversion and source symbolization | Disabled unless `--allow-process-execution`; executable selection remains allowlisted and bounded. |
| `ACTIVE_COLLECTION` | Supported `record`/`stat`; `sched`/`lock`/`off_cpu` when the deployed Collector is `full_diagnostics` | Requires writes, process execution, active-collection startup gate, exact authorization, bounded output, and a new output path. PID attachment has two additional gates; trace also requires Collector policy and the independent Trace Helper. |
| `AUTOMATIC_COLLECTION` | Execute a short-lived PID-bound plan through the Collector | Requires explicit MCP startup gates and an independent Collector policy. |
| `PROJECT_EXECUTION` | Launch one confirmed project executable and collect its new PID | Also requires automatic collection, `--allow-project-execution`, exact per-call authorization, and project path checks. |
| `DOCKER_COLLECTION` | Discover, authorize, and collect one local-container process or one fixed managed workload | Requires `perflens init --docker`, project Docker policy, automatic collection, a matching in-memory session, independently verified Linux identity, and Docker/Collector policy intersection. |

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

`collect_profile` is intentionally outside the default sequence. Use it only after the user approves the exact target and the [Skill safety rules](../.agents/skills/perflens/references/active-collection-safety.md) have been applied. The stable automatic sequence is `stat → record`; a request for “deep analysis” does not authorize or activate the raw trace experiments.

For policy-approved live PIDs, use `inspect_collection_capabilities`,
`plan_automatic_collection`, `execute_collection_plan`, and `analyze_collection`.
See [automatic collection](automatic-collection.md).

Planning and project-workload tools default to `event_source=auto`. Always
surface the returned actual source, fallback reason, and limitations. Continue
with software CPU-time/scheduling/page-fault or `cpu-clock` hotspot evidence,
but do not infer IPC, hardware cache, branch, or other microarchitectural facts.
Matched A/B runs require the same actual source.

`inspect_collection_capabilities` diagnoses local perf access for the ordinary
MCP process. A `blocked` result under `perf_event_paranoid=3` does not establish
that the separate Collector is blocked. For an executed collection, the
Collection's `actual_event_source`, `fallback_used`, and `fallback_reason` are
the authoritative provenance. When an older software recording lacks the
sample CPU attribute, the analyzer retries only the exact known conversion
failure and emits `MISSING_SAMPLE_CPU`; per-CPU analysis is then unavailable.

For a confirmed current-project workload, use `collect_project_workload`, then
analyze its Collection artifact and perform matched baseline/candidate runs.
The user need not discover a PID, but natural-language intent alone is not
authorization to execute arbitrary project files.

All list responses are bounded and paginated. The server emits typed structured output and checked-in JSON Schemas; it never returns an unbounded full analysis through a list tool.

## Detach project integration

Before package uninstall, preview and then detach every configured project:

```bash
perflens detach --project /absolute/path/to/project --dry-run
perflens detach --project /absolute/path/to/project
```

By default both clients are handled: a complete marked Codex block, an exact
recorded Claude `perflens` entry, and unchanged managed project Skills are
removed. Other client settings, onboarding files, analysis artifacts, and
Collector data are preserved; modified or unverified content is refused. Use
`--client codex|claude-code` for one client, `--keep-skills` to retain Skills,
and `--setup-directory` for a custom onboarding directory. A retained Skill
remains discoverable, so `--keep-skills` is not complete deactivation.
