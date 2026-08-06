# PerfLens allocation, copying, and memory candidates

Allocator frames do not establish that the allocator implementation is causal. Collect allocation counts, size distribution, lifetime, caller paths, peak memory, fragmentation, and cross-thread behavior.

Copy frames require byte counts and call counts. Check temporary buffers, serialization boundaries, encoding conversion, ownership transfer, repeated materialization, and whether zero-copy changes would extend lifetimes or pin memory.

For cache or bandwidth hypotheses, request hardware-counter or memory-bandwidth evidence. State when the profile contains only symbol-name clues.
