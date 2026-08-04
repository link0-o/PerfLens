# PerfLens

> Evidence-driven Linux performance analysis with a CLI, MCP Server, and Codex Skill.
> 基于证据的 Linux 性能分析工具，集成 CLI、MCP Server 与 Codex Skill。

[![CI](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml/badge.svg)](https://github.com/link0-o/PerfLens/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

[简体中文](README.zh-CN.md) | English

**First installation: read [Installation and first use](INSTALL.md). Do not extract the wheel; install it with pipx or uv.**

PerfLens is an evidence-driven performance-analysis toolkit for Linux
applications and coding agents.

The current release formally supports Milestones 0 through 9:

- streaming FlameGraph-compatible folded stack input;
- deterministic self and inclusive hotspot aggregation;
- root-to-leaf call-path aggregation;
- symbol plus DSO grouping (DSO is explicitly `unknown` for standard folded input);
- bounded parse diagnostics and versioned JSON artifacts;
- a production CLI with path checks, stable error output, resource limits, and
  atomic writes;
- streaming parsing of explicitly-fielded `perf script` text;
- `perf.data` conversion through an allowlisted system `perf` process;
- bounded subprocess output, stderr diagnostics, timeouts, and process-group cleanup.
- ELF Build ID/debug capability inspection and verified module-offset symbolization;
- bounded workspace source context and container/build path mapping;
- generic candidate-only classification, evidence bundles, and Markdown reports.
- an official-SDK MCP server with typed, paginated tools and server-side authorization;
- a repository Performance Analysis Skill for evidence-constrained Agent workflows.
- profile and repeated-benchmark comparison with environment comparability checks;
- pyperf, Google Benchmark, and hyperfine JSON normalization;
- default-off, explicitly authorized perf record/stat/sched/lock/off-CPU collection.

It does **not** include an AI/LLM API, Web UI, source-code patch tool, benchmark
runner, or custom agent framework.

## Install

PerfLens requires Python 3.12 or newer.

For a GitHub release, download the wheel and install it as an isolated tool:

```bash
pipx install ./perflens-0.1.1-py3-none-any.whl
# or
uv tool install ./perflens-0.1.1-py3-none-any.whl
```

Then run project-scoped onboarding:

```bash
perflens setup \
  --project /absolute/path/to/project \
  --prepare-collector \
  --automatic-collection
```

Follow the generated `NEXT_STEPS.md`. See [Installation and first use](INSTALL.md) for the complete beginner flow.

Debian 13 users can instead install the native, offline `.deb` packages. See
[Debian packages](docs/debian-packages.md) for the split main/Collector flow.

Run a read-only readiness summary at any time:

```bash
perflens status --project /absolute/path/to/project
```

When automatic collection is configured and local access is available, this
also performs a bounded, read-only health handshake. It verifies the Collector
PID/UID with kernel peer credentials and reports stale, unreachable, or
wrong-identity sockets instead of declaring them ready.

After administrator deployment and a fresh login, verify the Collector without
finding a PID:

```bash
perflens accept-collector --authorize-host-acceptance
```

The default output is a concise Chinese pass summary with the evidence path,
hash, metric count, and conclusion boundary. Use `--json` for complete
machine-readable output or `--output ./collector-acceptance.json` to preserve a
new versioned evidence file.

The wheel installation commands provide `perflens`, `perflens-mcp`, the optional
`perflens-collector`, and the explicit administrator entry point
`perflens-admin`. Confirm the release:

```bash
perflens --version
perflens-mcp --version
perflens-collector --version
perflens-admin --version
```

Installing directly from a source checkout is also supported:

```bash
python -m pip install .
```

For development with uv:

```bash
uv sync --all-groups
```

## Analyze folded stacks

```bash
perflens analyze-folded \
  --input tests/fixtures/folded/normal.folded \
  --output build/analysis.json
```

Input follows standard folded syntax:

```text
main;worker;parse;malloc 182
main;worker;compute 271
```

Frames are normalized to `root → leaf`. The final frame receives self weight.
Every unique `(symbol, DSO)` in a sample receives inclusive weight once, so
recursive frames cannot make a function-level inclusive percentage exceed
100%. Frame occurrences are counted separately.

Standard folded text has no DSO, PID/TID, CPU, timestamp, event, or source
metadata. PerfLens records these fields as `unknown`; it never infers them from
symbol names. Each folded line is one weighted stack record, not `weight`
individual samples.

## Analyze perf profiles

For existing text, generate the supported stable field set and analyze it:

```bash
perf script --ns \
  -F comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline \
  -i perf.data > profile.perf-script

perflens analyze-perf-script \
  --input profile.perf-script \
  --output build/analysis.json
```

Or let PerfLens run the same read-only conversion:

```bash
perflens analyze-perf-data \
  --input perf.data \
  --output build/analysis.json
```

`analyze-perf-data` never records, attaches to a process, or requests root. It
invokes an absolute, allowlisted `perf` executable without a shell. Use
`--perf-path` when several versions are installed and `--timeout-seconds` to
lower the conversion deadline.

## Inspect symbols and build evidence

```bash
perflens inspect-elf --input build/app --output build/elf.json
perflens resolve-source \
  --binary build/app \
  --module-offset 0x1234 \
  --output build/source.json

perflens classify \
  --analysis build/analysis.json \
  --output build/diagnosis.json
perflens report \
  --analysis build/analysis.json \
  --problem "Throughput regression" \
  --metric "requests/second" \
  --output build/report.md
```

Source resolution requires a verified module-relative offset. A runtime IP by
itself is never rebased heuristically. PerfLens prefers a long-lived
`llvm-symbolizer` JSON provider, then falls back to a long-lived `addr2line`
provider. Cache identity includes Build ID, module offset, and resolver version.

Classification rules label investigation candidates only. Generated reports
keep direct observations, missing evidence, forbidden conclusions, and A/B
validation requirements separate.

## Compare profiles and benchmarks

```bash
perflens compare-profiles \
  --baseline build/baseline-analysis.json \
  --candidate build/candidate-analysis.json \
  --output build/profile-comparison.json \
  --markdown-output build/profile-comparison.md

perflens normalize-benchmark \
  --input benchmark-hyperfine.json \
  --output build/benchmark.json
perflens compare-benchmarks \
  --baseline build/baseline-benchmark.json \
  --candidate build/candidate-benchmark.json \
  --output build/benchmark-comparison.json
```

Profile percentage changes describe the selected event distribution, not
absolute elapsed time. Benchmark comparisons require repeated samples, check
environment differences, apply a practical-impact threshold, and emit only
candidate improvement/regression states.

## Explicitly authorized active collection

Active collection is disabled by default. A CLI invocation requires both a
confirmation switch and the exact per-call authorization phrase:

```bash
perflens collect-profile \
  --mode record \
  --executable /absolute/path/to/app \
  --target-arg=--workload \
  --data-output build/profile.data \
  --metadata-output build/collection.json \
  --authorize-target \
  --authorization I_EXPLICITLY_AUTHORIZE_TARGET_PROFILING
```

Modes are `record`, `stat`, `sched`, `lock`, and `off_cpu`. `stat` uses an
independent typed metric adapter and derives IPC when cycles and instructions
are available. PID attachment requires `--pid`, a bounded duration,
`--authorize-pid-attach`, and the separate phrase
`I_EXPLICITLY_AUTHORIZE_PID_ATTACH`. PerfLens never invokes sudo or changes
kernel policy. See [MCP server and Skill setup](docs/mcp-and-skill.md) for the
additional MCP startup gates.

For an approved live PID, PerfLens can automatically inspect permissions, create a
short-lived PID-bound plan, execute it once through a separately policy-enforcing
Collector Broker, and analyze the result. See
[automatic collection](docs/automatic-collection.md). The MCP server and Agent remain
unprivileged. The Collector also enforces cumulative spool byte/file quotas and
a filesystem free-space reserve; exhaustion denies new work without deleting
old evidence.

Each Collector instance permits exactly one ordinary UID. Sharing its
`perflens` group and spool across callers would expose group-readable profiles
between users and is rejected.

After deployment, `perflens-admin spool-status` gives a read-only Chinese
summary of spool usage, filesystem reserve, and currently reservable output;
add `--json` for the versioned machine-readable artifact.

Evidence is never age-deleted automatically. Administrators can use the
archive-then-prune workflow to create a bounded stored ZIP with a versioned
manifest and per-file SHA-256, preserve all sources, verify both copies with a
dry run, and only then explicitly authorize removal of exact matching source
inodes. The archive remains intact and Agents must not schedule pruning.

Administrators can tune the bilingual policy without memorizing a manual
restart sequence: copy it to a separate mode-`0600` candidate, run
`perflens-admin update-policy --config <candidate> --dry-run`, then repeat with
`sudo`. The command atomically applies and health-checks the policy, rolls back
on activation failure, and refuses UID or fixed-spool migration.

Deploy and upgrade require a bounded, read-only Collector health round trip and
verify the responding PID/UID through kernel credentials. A stale, wrong-owner,
or unlistened socket pathname is not readiness. `perflens-admin deploy` prints a
Chinese dry-run or success summary by default; add `--json` for the complete
versioned artifact.

After installing a new release, run `sudo perflens-admin upgrade --dry-run` and
then `sudo perflens-admin upgrade`. The explicit flow preserves policy and spool
data, replaces only a verified managed unit, restarts the service, and attempts
unit rollback on activation failure.

After one administrator-reviewed deployment, users do not need to discover a
PID. They may ask the Skill to optimize the current project, approve one exact
executable and argument list, and let the ordinary-user launcher obtain the new
PID internally. The Collector still receives only a short-lived PID-bound plan;
the project workload never runs with Collector privilege.

See [product deployment](docs/deployment.md) for configurable service assets,
real Collector verification, upgrades, and uninstall behavior.

## Use MCP with the Skill

An installed release contains a copy of the Skill. Install it into the project
that will use PerfLens:

```bash
perflens install-skill --project /absolute/path/to/workspace
```

The command creates
`.agents/skills/perflens-performance-analysis` and refuses to overwrite an
existing Skill. To print a project-scoped MCP configuration:

```bash
perflens codex-config --workspace /absolute/path/to/workspace
```

Add `--allow-process-execution` only when `perf.data` conversion or source
symbolization is required. Review the printed TOML before adding it to the
project's `.codex/config.toml`.

From a source checkout, the equivalent direct registration is:

```bash
mkdir -p perflens-results
codex mcp add perflens -- \
  "$PWD/.venv/bin/perflens-mcp" \
  --allowed-root "$PWD" \
  --artifact-root "$PWD/perflens-results" \
  --allow-writes
```

Restart Codex, then ask:

```text
$perflens-performance-analysis analyze ./profile.folded and report direct evidence, candidates, and missing evidence.
```

See [MCP server and Skill setup](docs/mcp-and-skill.md) for permissions,
project-scoped configuration, process-execution opt-in, and the full tool flow.

## Resource limits

Defaults are intentionally explicit:

- input file: 1 GiB;
- logical records: 10 million;
- line length: 1 MiB;
- stack depth: 4,096;
- unique frames: 2 million;
- unique call paths: 1 million;
- retained warnings: 100;
- emitted hotspots: 10,000;
- emitted call paths: 1,000.

Limits can be lowered from the CLI. Exceeding structural limits fails with a
structured error rather than silently dropping exact data. Malformed individual
records are skipped and reported with bounded line previews.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success |
| 2 | invalid CLI usage or input |
| 3 | unsupported or malformed profile |
| 4 | resource limit exceeded |
| 5 | output/path safety failure |
| 6 | external tool failure or timeout |
| 70 | unexpected internal failure |

## Development checks

```bash
uv run ruff check .
uv run pyright
uv run pytest --cov=perflens
uv build
uv run pip-audit
```

The reproducible performance harness is:

```bash
uv run python tests/performance/benchmark_folded.py \
  --records 1000 100000 1000000 \
  --repetitions 3
```

See `docs/performance-budget.md` for the recorded environment and baseline.

See [release readiness](docs/release-readiness.md),
[release process](docs/releasing.md),
[real-world profile acceptance](docs/real-world-acceptance.md), and
[troubleshooting](docs/troubleshooting.md) for final verification evidence and
operational failure guidance.

Chinese maintainer documentation is available in the
[development guide](docs/development.zh-CN.md),
[architecture guide](docs/architecture.zh-CN.md),
[compatibility matrix](docs/compatibility.zh-CN.md),
[known limitations](docs/limitations.zh-CN.md),
[real-world acceptance record](docs/real-world-acceptance.zh-CN.md),
[security policy](SECURITY.zh-CN.md), and
[release-readiness record](docs/release-readiness.zh-CN.md). Every document under
`docs/` that has an English version now links to a corresponding Simplified
Chinese version.

## Known limitations

- Folded input cannot distinguish identically named functions from different
  DSOs because the format omits DSO metadata.
- Percentages describe selected event weight, not wall-clock duration.
- Call paths are exact up to the configured unique-path limit.
- Symbol names are preserved with only conservative compiler-suffix cleanup.
- A hotspot is an observation, not a confirmed root cause.
- `perf.data` portability remains dependent on the installed `perf` version and
  access to matching DSOs/symbols; preserved unknown frames make gaps explicit.
- Active collection depends on kernel perf permissions. On the development
  host, `perf_event_paranoid=3` rejects unprivileged sampling; PerfLens returns
  a bounded structured error and leaves no collection output.
- `off_cpu` mode records `sched:sched_switch` stack evidence; workload-aware
  post-processing is still required before making blocked-time claims.
