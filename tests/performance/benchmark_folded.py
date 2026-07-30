"""Reproducible folded parsing/aggregation time and peak-RSS harness."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import sys
import tempfile
from pathlib import Path
from time import perf_counter

from perflens.application.analyze import analyze_folded


def run(records: int, repetition: int) -> dict[str, int | float | str]:
    with tempfile.TemporaryDirectory(prefix="perflens-benchmark-") as directory:
        profile = Path(directory) / "corpus.folded"
        line = "main;worker;parse;leaf 1\n"
        with profile.open("w") as handle:
            for index in range(records):
                handle.write(line.replace("leaf", f"leaf-{index % 100}"))
        input_bytes = profile.stat().st_size
        started = perf_counter()
        artifact = analyze_folded(profile)
        elapsed = perf_counter() - started
        peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        assert artifact.metadata.sample_count == records
    return {
        "records": records,
        "repetition": repetition,
        "input_bytes": input_bytes,
        "elapsed_seconds": elapsed,
        "records_per_second": records / elapsed,
        "bytes_per_second": input_bytes / elapsed,
        "peak_rss_kib": peak_rss_kib,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", nargs="+", type=int, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    result = {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "architecture": platform.machine(),
        },
        "runs": [
            run(records, repetition)
            for records in args.records
            for repetition in range(1, args.repetitions + 1)
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
