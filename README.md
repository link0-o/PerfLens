# PerfLens

PerfLens is an evidence-driven performance-analysis toolkit for Linux
applications and coding agents.

The current release formally supports Milestones 0 through 3:

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

It does **not** yet support external ELF symbolization, MCP, benchmark
comparison, active sampling, or AI/LLM APIs.

## Install

PerfLens requires Python 3.12 or newer.

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

## Known limitations

- Folded input cannot distinguish identically named functions from different
  DSOs because the format omits DSO metadata.
- Percentages describe selected event weight, not wall-clock duration.
- Call paths are exact up to the configured unique-path limit.
- Symbol names are preserved with only conservative compiler-suffix cleanup.
- A hotspot is an observation, not a confirmed root cause.
- `perf.data` portability remains dependent on the installed `perf` version and
  access to matching DSOs/symbols; preserved unknown frames make gaps explicit.
