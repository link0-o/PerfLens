# Limitations

Milestone 1 accepts only standard folded stacks. It cannot recover process,
thread, CPU, event, DSO, address, timestamp, or source information absent from
that format. Unknown data remains unknown. Results identify weighted hotspots
and call paths; they do not establish causality or elapsed time.

Exact aggregation is bounded. If configured cardinality limits are exceeded,
analysis fails with a recoverable resource-limit error; no approximation or
silent truncation is used.
