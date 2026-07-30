# Real-world profile acceptance

The final acceptance run uses a profile supplied by an upstream project, not a PerfLens-generated test fixture.

## Provenance

- Source: [Brendan Gregg's FlameGraph example Linux perf profile](https://github.com/brendangregg/FlameGraph/blob/41fee1f99f9276008b7cd112fca19dc3ea84ac32/example-perf-stacks.txt.gz)
- Upstream commit: `41fee1f99f9276008b7cd112fca19dc3ea84ac32`
- Compressed source SHA-256: `ad0d2cb09dba33c492893e6010adcc4806431b8a351b31798b7a4a2deddab7e5`
- Upstream converter: `stackcollapse-perf.pl --all` from the same commit
- Converter SHA-256: `74faa47a29d8df07cb06731dfd8bb94dc4c165b9d811ac6b4c9449eea2ac25d8`
- Converted folded profile SHA-256: `b1a9d70d4d5604815775225ba4200789964eaade3f9232dd7462e6e591710a0b`

The external profile and converter are not redistributed in this repository. The pinned links and hashes make the acceptance input independently reproducible while keeping third-party data outside the package.

## End-to-end flow

The 2026-07-30 run performed:

```bash
perflens analyze-folded --input upstream.folded --output analysis.json
perflens classify --analysis analysis.json --output diagnosis.json
perflens report \
  --analysis analysis.json \
  --problem "Upstream Vert.x CPU profile acceptance" \
  --metric "sample weight distribution" \
  --output report.md
```

Results:

| Check | Result |
|---|---:|
| Folded records parsed | 710 |
| Malformed records | 0 |
| Total sample weight | 1,315 |
| Hotspots emitted | 531 |
| Call paths emitted | 710 |
| Analysis status | `complete` |
| Diagnosis status | `partial` |

The `partial` diagnosis is intentional: folded input has no event or source-line metadata, and no generic symbol rule matched strongly enough to emit a candidate classification. The report preserved those limitations instead of inventing a root cause.

Output SHA-256 values:

- analysis: `f3c5da385a7785765fcd96424fea9d67433be7514cb7cd4ff8e80ee83e3980bd`
- diagnosis: `a50e04eeb9864be24de9442ddfa487d3ec2aabc61a0561f203ccfcfae2f97b3c`
- Markdown report: `99f01ff2719803cb41ab60f68fff5b6b7c45870a9a627f9b089519a2032f3a2e`

This satisfies the requirement for a non-author-provided real profile while keeping the result evidence-constrained.
