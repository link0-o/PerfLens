# Folded Profile 数据模型

简体中文 | [English](profile-model.md)

每一条非空 folded 行代表一条逻辑栈记录，并带有一个正整数权重。`frames[0]` 是根帧，
`frames[-1]` 是叶子帧。

Self 权重计入叶子帧。Inclusive 权重按记录中唯一的 `(symbol, DSO)` 键各计一次。
Occurrence count 会对每一个帧位置计数，因此能够单独保留递归深度信息。

同一次分析中的所有记录必须使用相同的事件、权重单位和权重来源。folded 输入会把这些
值固定为 `unknown`、`sample_count` 和 `folded_weight`。

对于 `perf script`，PerfLens 支持明确的
`comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline` 字段。perf 输出的调用链会从
“叶子优先”规范化为“根优先”。period 会成为对应事件原生单位的权重：
`cpu-clock`/`task-clock` 为纳秒、cycles 为周期、instructions 为指令；陌生事件使用
`event_count`，不会猜测物理单位。没有 period 时会明确回退为一个样本。IP、原始符号、
DSO、内核状态和源码行/列会继续绑定到经过驻留复用的 Frame。

热点按规范化的 `(symbol, DSO)` 分组，因此同一个函数内部的不同指令地址不会被拆开。
公开调用路径采用相同的 `(symbol, DSO)` 身份，因此渲染结果相同的地址/源码变体会合并
计数，不再输出多条看起来完全相同的路径。精确 IP、原始符号和有界源码元数据仍保留在
内部 Frame 上，源码位置会汇总到热点。

对于 CPython perf-map，PerfLens 会识别官方的 `py::函数:文件名` 格式。启用 `srcline`
后 perf 额外输出的 `dso[offset]` 与 `[JIT] tid N[offset]` 是前一帧的重复注释，不是新的
调用栈帧。严格匹配的 `文件:行号`（可带 `(inlined)`）只会补充到紧邻的上一帧。只有
文件名而没有行号时，不会仅凭文件名把 `has_source_lines` 标成 `true`。

这套 Frame/Annotation 判定不是 Python 专用分支。回归矩阵同时覆盖 C/C++ 模板与内联、
Rust hash 变体、Go 方法名、Java/JIT perf-map、普通 native 父子帧和带括号的 DSO 路径。
语言专用规则只能补充 Frame 元数据，不能改变样本权重、调用栈顺序或守恒规则。对
`perf.data` 的 Java 和其他 JIT 分析，如果没有冻结转换文本或符号 sidecar，只能支持本次
分析，不能宣称跨时间完全重放；直接保存的 perf-script 文本本身已经冻结了符号字符串。

如果某一行显然占据调用栈位置，但因截断或未知格式无法还原 Frame，PerfLens 会保留一个
`unknown` Frame 并降低证据质量，而不是删除它。这样可以守住叶帧位置，避免把父帧错误记为
Self 热点；未知 Frame 数量仍受 `max_unique_frames` 限制。

## 来源与完整性

Analysis 同时包含两种摘要：

- `analysis_fingerprint` 绑定原始输入 SHA-256、转换器清单、解析/规范化版本、资源上限和
  可选 Collection 来源，用于判断两次分析是否使用同一语义配置；
- `content_sha256` 绑定除它自身外的全部 Agent 可见字段，用于发现热点、百分比、事件来源
  或限制声明在保存后被错改。

来自 `analyze_collection` 的 perf.data 还会保存 `CollectionEvidenceProvenance`。分析开始前
必须核对 Collection 声明的输出大小和 SHA-256；分析结束后再次核对输入文件身份和哈希，
避免把一个 Collection 的硬件/软件事件来源套到另一个文件上。

这两个摘要不是数字签名，也不能证明内核 PMU、perf 或调试符号本身绝对正确。它们解决的
是 PerfLens 链路内的错配、修改和派生字段不一致；外部工具不确定性由转换清单、Golden、
跨语言 fixture 和 EvidenceQuality 限制共同约束。

## EvidenceQuality 与独立验证

每份 Analysis 都带同一份 EvidenceQuality，MCP 的热点、详情、调用路径和分类接口也会原样
返回它。字段包括原始输入/Collection 身份、事件来源与回退、样本/权重语义、解析和注释
计数、未知 Self 权重、任意源码帧出现次数、独立的叶帧 Self 源码覆盖率、调用栈覆盖率、
规范化合并、输出省略权重以及允许/禁止结论。

`perflens verify-analysis` 和 MCP `verify_analysis` 会独立复核：

- 内容摘要与分析指纹；
- Collection→输入绑定；
- metadata 与 EvidenceQuality 一致性；
- Self、Inclusive、调用路径、百分比和输出省略的数值守恒；
- 事件来源对应的结论门禁；
- 可访问时的原始输入 SHA-256。

`verified` 只表示转换和结构校验通过，不表示性能根因已经确认。`partial` 仍可用于它明确
允许的观察，但报告必须携带限制；守恒或绑定失败时 Analysis 会被拒绝，不能继续交给 Agent。
