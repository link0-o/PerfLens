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
“叶子优先”规范化为“根优先”。period 会成为事件计数权重；没有 period 时会明确回退为
一个样本。IP、原始符号、DSO、内核状态和源码行会继续绑定到经过驻留复用的 Frame。

热点按规范化的 `(symbol, DSO)` 分组，因此同一个函数内部的不同指令地址不会被拆开。
精确调用路径仍保留不同 Frame，所以地址和源码位置的差异不会丢失。
