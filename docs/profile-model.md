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
`comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline`. Callchains emitted by
perf are normalized from leaf-first to root-first. Period becomes event-count
weight; absent period falls back explicitly to one sample. IP, raw symbol, DSO,
kernel status, and source line remain attached to interned frames.

Hotspots group by normalized `(symbol, DSO)`, so different instruction
addresses inside one function are not split. Exact call paths retain distinct
frames and therefore preserve address/source variation.
