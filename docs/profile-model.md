# Folded profile model

[简体中文](profile-model.zh-CN.md) | English

One non-empty folded line is one logical stack record with a positive integer
weight. `frames[0]` is the root and `frames[-1]` is the leaf.

Self weight is credited to the leaf. Inclusive weight is credited once per
unique `(symbol, DSO)` key in the record. Occurrence count is credited for every
frame position and therefore preserves recursion depth separately.

All records in one analysis must use the same event, weight unit, and weight
source. Folded input fixes those values to `unknown`,
`sample_count`, and `folded_weight`.

For `perf script`, PerfLens supports the explicit fields
`comm,pid,tid,cpu,misc,time,event,period,ip,sym,dso,srcline`. Callchains emitted by
perf are normalized from leaf-first to root-first. Period uses the event's native
unit: CPU/task clock is nanoseconds, cycles is cycles, and instructions is
instructions. Unfamiliar events remain `event_count` instead of receiving a guessed
physical unit; absent period falls back explicitly to one sample. IP, raw symbol,
DSO, kernel status, and source line/column remain attached to interned frames.
The `misc` sample privilege marker is retained as user, kernel, or unknown context.
EvidenceQuality reports those Self-weight distributions separately and also splits unresolved
Self weight by context, so hidden kernel symbols are not misreported as failed user/container
symbolization.

Hotspots group by normalized `(symbol, DSO)`, so different instruction
addresses inside one function are not split. Public call paths use the same
`(symbol, DSO)` identity, so address/source variants that render as the same
path are aggregated once. Exact IP, raw symbol, and bounded source metadata
remain on internal frames; source locations are projected onto hotspots.

When perf emits CPython perf-map names, PerfLens recognizes the documented
`py::function:filename` form. The extra `dso[offset]` and
`[JIT] tid N[offset]` lines emitted with `srcline` are redundant annotations,
not additional stack frames. A strict `file:line` annotation, optionally followed
by `(inlined)`, enriches only the immediately preceding frame. A source filename
without a line number does not by itself set `has_source_lines=true`.

The Frame/Annotation classifier is not Python-specific. Checked-in regressions also cover C/C++
templates and inline frames, Rust hash variants, Go methods, Java/JIT perf maps, ordinary native
parent frames, and parenthesized DSO paths. Language adapters may enrich Frame metadata but cannot
change sample weight, stack order, or conservation rules. For `perf.data`, Java and other JIT maps
without a frozen transcript or symbol sidecar are valid only for the current analysis and are not
claimed to be replayable across time; a directly retained perf-script text already freezes its
symbol strings.

If a line clearly occupies a callchain position but truncation or an unknown format prevents Frame
reconstruction, PerfLens retains a bounded `unknown` Frame and lowers evidence quality instead of
dropping it. This preserves leaf position and prevents the caller from receiving false Self weight;
the placeholder still counts toward `max_unique_frames`.

## Provenance and integrity

An Analysis has two hashes. `analysis_fingerprint` binds the raw-input SHA-256, conversion manifest,
parser/normalizer versions, limits, and optional Collection provenance. `content_sha256` binds every
Agent-visible field except itself, detecting post-save changes to hotspots, percentages, event
source, or limitations.

For `analyze_collection`, `CollectionEvidenceProvenance` records the Collection artifact digest,
output hash/size, mode, event source, fallback, and limitations. PerfLens checks the Collection
hash/size before parsing and rechecks input identity and SHA-256 after conversion, preventing one
Collection's provenance from being attached to another file.

These hashes are not signatures and do not prove that the kernel PMU, perf, or debug symbols are
infallible. They address mismatch and mutation inside the PerfLens chain; conversion provenance,
goldens, cross-language fixtures, and explicit quality limits bound external uncertainty.

## EvidenceQuality and independent verification

The Analysis and every Agent-facing hotspot/details/path/classification response carry the same
EvidenceQuality header. It exposes source identity, event fallback, record/weight semantics,
parser/annotation counters, unresolved Self weight and its sample-privilege split, source-line
Frame occurrences, independent
leaf-Self source coverage, call-graph coverage, normalization merges, omitted output weight, and
allowed/forbidden conclusions.

CLI `perflens verify-analysis` and MCP `verify_analysis` independently check the content digest,
analysis fingerprint, Collection/input binding, metadata/quality consistency, Self/Inclusive/path
percentages and conservation, conclusion gates, and—when available—the raw source SHA-256.
`verified` means conversion and structural checks passed, not that a root cause is confirmed.
`partial` evidence may support only its listed allowed observations; failed binding or conservation
is rejected before Agent interpretation.
