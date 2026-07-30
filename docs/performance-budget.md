# Performance budget

Milestone 1 establishes measured baselines rather than promising unmeasured
absolute throughput. The reproducible harness generates folded records in a
temporary file, analyzes them through the public application service, and
records wall time, records/second, input bytes/second, and peak RSS.

Corpus sizes:

- small: 1,000 records;
- medium: 100,000 records;
- large: 1,000,000 records.

Run:

```bash
python tests/performance/benchmark_folded.py \
  --records 1000 100000 1000000 \
  --repetitions 3
```

CI runs the small corpus as a smoke baseline. Dedicated runs record the exact
OS, architecture, Python version, input size, elapsed time, throughput, and peak
RSS in this document before release.

## Recorded baseline

Measured on 2026-07-30:

- Linux 6.12.74, Debian 13, x86_64;
- Python 3.13.5, GCC 14.2.0;
- one process, cold generated input, exact aggregation;
- 100 unique leaf symbols and three shared parent symbols.

The table reports median elapsed time and throughput across three repetitions,
and the maximum observed process RSS. Raw values are checked in at
`docs/performance-baseline.json`.

| Corpus | Input | Median elapsed | Median records/s | Median input MiB/s | Max RSS |
|---|---:|---:|---:|---:|---:|
| Small (1,000) | 27,900 bytes | 0.0094 s | 106,814 | 2.84 | 30.8 MiB |
| Medium (100,000) | 2,790,000 bytes | 0.7316 s | 136,682 | 3.64 | 32.7 MiB |
| Large (1,000,000) | 27,900,000 bytes | 7.6194 s | 131,245 | 3.49 | 32.7 MiB |

Peak RSS is the process-wide high-water mark reported by `getrusage`, not an
isolated allocation measurement. The near-flat medium-to-large RSS reflects
streamed samples and bounded cardinality in this corpus; unique frame and path
state still grows with cardinality until its explicit hard limit.

CI uses deliberately wide smoke thresholds (10 seconds and 1 GiB for 1,000
records) to detect order-of-magnitude regressions without treating shared
runner noise as a performance failure. Release baselines must retain raw
repeated measurements before tighter budgets are introduced.
