# Folded profile model

One non-empty folded line is one logical stack record with a positive integer
weight. `frames[0]` is the root and `frames[-1]` is the leaf.

Self weight is credited to the leaf. Inclusive weight is credited once per
unique `(symbol, DSO)` key in the record. Occurrence count is credited for every
frame position and therefore preserves recursion depth separately.

All records in one analysis must use the same event, weight unit, and weight
source. Milestone 1 folded input fixes those values to `unknown`,
`sample_count`, and `folded_weight`.
